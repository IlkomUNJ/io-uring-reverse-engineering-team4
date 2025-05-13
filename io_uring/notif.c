#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/io_uring.h>

#include "io_uring.h"
#include "notif.h"
#include "rsrc.h"

static const struct ubuf_info_ops io_ubuf_ops;


/*
 * io_notif_tw_complete - complete notification request from task_work
 * @notif: notification request to complete
 * @ts: task_work state
 *
 * This function completes a notification request. It processes a linked
 * list of io_notif_data structures, finalizes zero-copy status if enabled,
 * unaccounts memory if needed, and completes the request in task context.
 */
static void io_notif_tw_complete(struct io_kiocb *notif, struct io_tw_state *ts)
{
	struct io_notif_data *nd = io_notif_to_data(notif);

	do {
		notif = cmd_to_io_kiocb(nd);

		lockdep_assert(refcount_read(&nd->uarg.refcnt) == 0);

		if (unlikely(nd->zc_report) && (nd->zc_copied || !nd->zc_used))
			notif->cqe.res |= IORING_NOTIF_USAGE_ZC_COPIED;

		if (nd->account_pages && notif->ctx->user) {
			__io_unaccount_mem(notif->ctx->user, nd->account_pages);
			nd->account_pages = 0;
		}

		nd = nd->next;
		io_req_task_complete(notif, ts);
	} while (nd);
}

/*
 * io_tx_ubuf_complete - callback for zerocopy tx completion
 * @skb: socket buffer, may be NULL
 * @uarg: ubuf_info pointer associated with the request
 * @success: indicates whether the zerocopy send succeeded
 *
 * This is the zerocopy completion handler invoked when TX completion
 * is triggered. It updates the zerocopy status, manages reference
 * counting on ubuf_info, and defers completion via task_work if this
 * is the final reference.
 */
void io_tx_ubuf_complete(struct sk_buff *skb, struct ubuf_info *uarg,
			 bool success)
{
	struct io_notif_data *nd = container_of(uarg, struct io_notif_data, uarg);
	struct io_kiocb *notif = cmd_to_io_kiocb(nd);
	unsigned tw_flags;

	if (nd->zc_report) {
		if (success && !nd->zc_used && skb)
			WRITE_ONCE(nd->zc_used, true);
		else if (!success && !nd->zc_copied)
			WRITE_ONCE(nd->zc_copied, true);
	}

	if (!refcount_dec_and_test(&uarg->refcnt))
		return;

	if (nd->head != nd) {
		io_tx_ubuf_complete(skb, &nd->head->uarg, success);
		return;
	}

	tw_flags = nd->next ? 0 : IOU_F_TWQ_LAZY_WAKE;
	notif->io_task_work.func = io_notif_tw_complete;
	__io_req_task_work_add(notif, tw_flags);
}

/*
 * io_link_skb - link sk_buff zerocopy notification chains
 * @skb: new sk_buff to associate with notification
 * @uarg: ubuf_info associated with the new notification
 *
 * This function attempts to link the given ubuf_info with a previously
 * attached sk_buff zerocopy notification. It ensures that all notifications
 * can be completed in the same context, and that zerocopy providers match.
 * Returns 0 on success or -EEXIST if linking is not possible.
 */
static int io_link_skb(struct sk_buff *skb, struct ubuf_info *uarg)
{
	struct io_notif_data *nd, *prev_nd;
	struct io_kiocb *prev_notif, *notif;
	struct ubuf_info *prev_uarg = skb_zcopy(skb);

	nd = container_of(uarg, struct io_notif_data, uarg);
	notif = cmd_to_io_kiocb(nd);

	if (!prev_uarg) {
		net_zcopy_get(&nd->uarg);
		skb_zcopy_init(skb, &nd->uarg);
		return 0;
	}
	/* handle it separately as we can't link a notif to itself */
	if (unlikely(prev_uarg == &nd->uarg))
		return 0;
	/* we can't join two links together, just request a fresh skb */
	if (unlikely(nd->head != nd || nd->next))
		return -EEXIST;
	/* don't mix zc providers */
	if (unlikely(prev_uarg->ops != &io_ubuf_ops))
		return -EEXIST;

	prev_nd = container_of(prev_uarg, struct io_notif_data, uarg);
	prev_notif = cmd_to_io_kiocb(nd);

	/* make sure all noifications can be finished in the same task_work */
	if (unlikely(notif->ctx != prev_notif->ctx ||
		     notif->tctx != prev_notif->tctx))
		return -EEXIST;

	nd->head = prev_nd->head;
	nd->next = prev_nd->next;
	prev_nd->next = nd;
	net_zcopy_get(&nd->head->uarg);
	return 0;
}

/*
 * io_ubuf_ops - ubuf_info ops for io_uring zerocopy notifications
 *
 * Defines the completion and skb linking callbacks for zerocopy
 * transmission notifications used by io_uring.
 */
static const struct ubuf_info_ops io_ubuf_ops = {
	.complete = io_tx_ubuf_complete,
	.link_skb = io_link_skb,
};

/*
 * io_alloc_notif - allocate and initialize notification request
 * @ctx: io_ring context that will own the request
 *
 * Allocates an io_kiocb and initializes it as a notification request.
 * This request is set up with a nop opcode and is marked for zerocopy
 * transmission. Also initializes reference counting and ubuf_info ops.
 * Returns the allocated request or NULL on failure.
 */
struct io_kiocb *io_alloc_notif(struct io_ring_ctx *ctx)
	__must_hold(&ctx->uring_lock)
{
	struct io_kiocb *notif;
	struct io_notif_data *nd;

	if (unlikely(!io_alloc_req(ctx, &notif)))
		return NULL;
	notif->opcode = IORING_OP_NOP;
	notif->flags = 0;
	notif->file = NULL;
	notif->tctx = current->io_uring;
	io_get_task_refs(1);
	notif->file_node = NULL;
	notif->buf_node = NULL;

	nd = io_notif_to_data(notif);
	nd->zc_report = false;
	nd->account_pages = 0;
	nd->next = NULL;
	nd->head = nd;

	nd->uarg.flags = IO_NOTIF_UBUF_FLAGS;
	nd->uarg.ops = &io_ubuf_ops;
	refcount_set(&nd->uarg.refcnt, 1);
	return notif;
}
