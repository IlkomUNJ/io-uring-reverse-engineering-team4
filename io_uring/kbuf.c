// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/vmalloc.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "opdef.h"
#include "kbuf.h"
#include "memmap.h"

/* BIDs are addressed by a 16-bit field in a CQE */
#define MAX_BIDS_PER_BGID (1 << 16)

struct kmem_cache *io_buf_cachep;

struct io_provide_buf {
	struct file			*file;
	__u64				addr;
	__u32				len;
	__u32				bgid;
	__u32				nbufs;
	__u16				bid;
};

static inline struct io_buffer_list *io_buffer_get_list(struct io_ring_ctx *ctx,
							unsigned int bgid)
{
	lockdep_assert_held(&ctx->uring_lock);

	return xa_load(&ctx->io_bl_xa, bgid);
}

/*
 * io_buffer_add_list - Store a buffer list into the XArray for a given bgid.
 * @ctx: the io_uring context
 * @bl: the buffer list to store
 * @bgid: the buffer group ID
 *
 * Stores the buffer group in the XArray and marks it visible,
 * ensuring mmap-related accesses can observe it properly.
 */
static int io_buffer_add_list(struct io_ring_ctx *ctx,
			      struct io_buffer_list *bl, unsigned int bgid)
{
	/*
	 * Store buffer group ID and finally mark the list as visible.
	 * The normal lookup doesn't care about the visibility as we're
	 * always under the ->uring_lock, but lookups from mmap do.
	 */
	bl->bgid = bgid;
	guard(mutex)(&ctx->mmap_lock);
	return xa_err(xa_store(&ctx->io_bl_xa, bgid, bl, GFP_KERNEL));
}

/*
 * io_kbuf_recycle_legacy - Recycle a previously used kernel buffer.
 * @req: the io_kiocb request structure
 * @issue_flags: flags used during issue phase
 *
 * Returns a buffer to its associated buffer list, making it
 * available for reuse, and clears buffer selection flags in the request.
 */
bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	struct io_buffer *buf;

	io_ring_submit_lock(ctx, issue_flags);

	buf = req->kbuf;
	bl = io_buffer_get_list(ctx, buf->bgid);
	list_add(&buf->list, &bl->buf_list);
	req->flags &= ~REQ_F_BUFFER_SELECTED;
	req->buf_index = buf->bgid;

	io_ring_submit_unlock(ctx, issue_flags);
	return true;
}

/*
 * __io_put_kbuf - Return a used buffer back to either issue or completion list.
 * @req: the request structure containing the buffer
 * @len: length of the buffer
 * @issue_flags: flags affecting buffer management path
 *
 * Depending on locking context, returns buffer to io_buffers_cache
 * or io_buffers_comp for future reuse.
 */
void __io_put_kbuf(struct io_kiocb *req, int len, unsigned issue_flags)
{
	/*
	 * We can add this buffer back to two lists:
	 *
	 * 1) The io_buffers_cache list. This one is protected by the
	 *    ctx->uring_lock. If we already hold this lock, add back to this
	 *    list as we can grab it from issue as well.
	 * 2) The io_buffers_comp list. This one is protected by the
	 *    ctx->completion_lock.
	 *
	 * We migrate buffers from the comp_list to the issue cache list
	 * when we need one.
	 */
	if (issue_flags & IO_URING_F_UNLOCKED) {
		struct io_ring_ctx *ctx = req->ctx;

		spin_lock(&ctx->completion_lock);
		__io_put_kbuf_list(req, len, &ctx->io_buffers_comp);
		spin_unlock(&ctx->completion_lock);
	} else {
		lockdep_assert_held(&req->ctx->uring_lock);

		__io_put_kbuf_list(req, len, &req->ctx->io_buffers_cache);
	}
}

/*
 * io_provided_buffer_select - Select a buffer from a user-provided list.
 * @req: the request structure
 * @len: in/out buffer length
 * @bl: buffer list to select from
 *
 * Picks the first buffer from the list, updates request metadata,
 * and returns a pointer to user space buffer address.
 */
static void __user *io_provided_buffer_select(struct io_kiocb *req, size_t *len,
					      struct io_buffer_list *bl)
{
	if (!list_empty(&bl->buf_list)) {
		struct io_buffer *kbuf;

		kbuf = list_first_entry(&bl->buf_list, struct io_buffer, list);
		list_del(&kbuf->list);
		if (*len == 0 || *len > kbuf->len)
			*len = kbuf->len;
		if (list_empty(&bl->buf_list))
			req->flags |= REQ_F_BL_EMPTY;
		req->flags |= REQ_F_BUFFER_SELECTED;
		req->kbuf = kbuf;
		req->buf_index = kbuf->bid;
		return u64_to_user_ptr(kbuf->addr);
	}
	return NULL;
}

/*
 * io_provided_buffers_select - Wrapper to select a provided buffer and setup iovec.
 * @req: the io_kiocb structure
 * @len: in/out buffer length
 * @bl: buffer list
 * @iov: output iovec pointer to hold selected buffer
 *
 * Tries to select a buffer from the list. If successful,
 * fills iovec with buffer information. Returns 1 on success,
 * -ENOBUFS if no buffer available.
 */
static int io_provided_buffers_select(struct io_kiocb *req, size_t *len,
				      struct io_buffer_list *bl,
				      struct iovec *iov)
{
	void __user *buf;

	buf = io_provided_buffer_select(req, len, bl);
	if (unlikely(!buf))
		return -ENOBUFS;

	iov[0].iov_base = buf;
	iov[0].iov_len = *len;
	return 1;
}

/*
 * io_ring_buffer_select - Select a buffer from a buffer ring for an I/O request.
 *
 * @req:           The io_kiocb request.
 * @len:           Length of the data to be read/written; may be adjusted.
 * @bl:            The buffer list containing the buffer ring.
 * @issue_flags:   Flags that influence buffer selection behavior.
 *
 * Selects a buffer from a shared buffer ring. If the request is issued from an
 * unlocked context or cannot be polled, the buffer is committed immediately.
 * Otherwise, the caller is responsible for committing the buffer after the I/O.
 */
static void __user *io_ring_buffer_select(struct io_kiocb *req, size_t *len,
					  struct io_buffer_list *bl,
					  unsigned int issue_flags)
{
	struct io_uring_buf_ring *br = bl->buf_ring;
	__u16 tail, head = bl->head;
	struct io_uring_buf *buf;
	void __user *ret;

	tail = smp_load_acquire(&br->tail);
	if (unlikely(tail == head))
		return NULL;

	if (head + 1 == tail)
		req->flags |= REQ_F_BL_EMPTY;

	buf = io_ring_head_to_buf(br, head, bl->mask);
	if (*len == 0 || *len > buf->len)
		*len = buf->len;
	req->flags |= REQ_F_BUFFER_RING | REQ_F_BUFFERS_COMMIT;
	req->buf_list = bl;
	req->buf_index = buf->bid;
	ret = u64_to_user_ptr(buf->addr);

	if (issue_flags & IO_URING_F_UNLOCKED || !io_file_can_poll(req)) {
		/*
		 * If we came in unlocked, we have no choice but to consume the
		 * buffer here, otherwise nothing ensures that the buffer won't
		 * get used by others. This does mean it'll be pinned until the
		 * IO completes, coming in unlocked means we're being called from
		 * io-wq context and there may be further retries in async hybrid
		 * mode. For the locked case, the caller must call commit when
		 * the transfer completes (or if we get -EAGAIN and must poll of
		 * retry).
		 */
		io_kbuf_commit(req, bl, *len, 1);
		req->buf_list = NULL;
	}
	return ret;
}

/*
 * io_buffer_select - Select a user buffer for an I/O request.
 *
 * @req:           The io_kiocb request.
 * @len:           Length of the data to be transferred; may be adjusted.
 * @issue_flags:   Submission flags affecting buffer behavior.
 *
 * Acquires the submission lock and attempts to select a buffer from the
 * appropriate list (provided buffers or buffer ring). Delegates to the
 * corresponding helper function.
 */
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	void __user *ret = NULL;

	io_ring_submit_lock(req->ctx, issue_flags);

	bl = io_buffer_get_list(ctx, req->buf_index);
	if (likely(bl)) {
		if (bl->flags & IOBL_BUF_RING)
			ret = io_ring_buffer_select(req, len, bl, issue_flags);
		else
			ret = io_provided_buffer_select(req, len, bl);
	}
	io_ring_submit_unlock(req->ctx, issue_flags);
	return ret;
}

/* cap it at a reasonable 256, will be one page even for 4K */
#define PEEK_MAX_IMPORT		256

/*
 * io_ring_buffers_peek - Peek into the buffer ring and prepare IO vectors.
 *
 * @req:     The io_kiocb request.
 * @arg:     Buffer selection arguments (holds result vectors, max_len, etc).
 * @bl:      The buffer list pointing to the buffer ring.
 *
 * Attempts to map a number of buffers from the ring into a set of IO vectors,
 * with optional dynamic allocation if more vectors are needed. Used to prepare
 * multiple buffers in advance for a single I/O operation.
 */
static int io_ring_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg,
				struct io_buffer_list *bl)
{
	struct io_uring_buf_ring *br = bl->buf_ring;
	struct iovec *iov = arg->iovs;
	int nr_iovs = arg->nr_iovs;
	__u16 nr_avail, tail, head;
	struct io_uring_buf *buf;

	tail = smp_load_acquire(&br->tail);
	head = bl->head;
	nr_avail = min_t(__u16, tail - head, UIO_MAXIOV);
	if (unlikely(!nr_avail))
		return -ENOBUFS;

	buf = io_ring_head_to_buf(br, head, bl->mask);
	if (arg->max_len) {
		u32 len = READ_ONCE(buf->len);

		if (unlikely(!len))
			return -ENOBUFS;
		/*
		 * Limit incremental buffers to 1 segment. No point trying
		 * to peek ahead and map more than we need, when the buffers
		 * themselves should be large when setup with
		 * IOU_PBUF_RING_INC.
		 */
		if (bl->flags & IOBL_INC) {
			nr_avail = 1;
		} else {
			size_t needed;

			needed = (arg->max_len + len - 1) / len;
			needed = min_not_zero(needed, (size_t) PEEK_MAX_IMPORT);
			if (nr_avail > needed)
				nr_avail = needed;
		}
	}

	/*
	 * only alloc a bigger array if we know we have data to map, eg not
	 * a speculative peek operation.
	 */
	if (arg->mode & KBUF_MODE_EXPAND && nr_avail > nr_iovs && arg->max_len) {
		iov = kmalloc_array(nr_avail, sizeof(struct iovec), GFP_KERNEL);
		if (unlikely(!iov))
			return -ENOMEM;
		if (arg->mode & KBUF_MODE_FREE)
			kfree(arg->iovs);
		arg->iovs = iov;
		nr_iovs = nr_avail;
	} else if (nr_avail < nr_iovs) {
		nr_iovs = nr_avail;
	}

	/* set it to max, if not set, so we can use it unconditionally */
	if (!arg->max_len)
		arg->max_len = INT_MAX;

	req->buf_index = buf->bid;
	do {
		u32 len = buf->len;

		/* truncate end piece, if needed, for non partial buffers */
		if (len > arg->max_len) {
			len = arg->max_len;
			if (!(bl->flags & IOBL_INC))
				buf->len = len;
		}

		iov->iov_base = u64_to_user_ptr(buf->addr);
		iov->iov_len = len;
		iov++;

		arg->out_len += len;
		arg->max_len -= len;
		if (!arg->max_len)
			break;

		buf = io_ring_head_to_buf(br, ++head, bl->mask);
	} while (--nr_iovs);

	if (head == tail)
		req->flags |= REQ_F_BL_EMPTY;

	req->flags |= REQ_F_BUFFER_RING;
	req->buf_list = bl;
	return iov - arg->iovs;
}

/*
 * io_buffers_select - Select one or more buffers for a request, with commit if needed.
 *
 * @req:           The io_kiocb request.
 * @arg:           Arguments describing buffer selection (including output length).
 * @issue_flags:   Flags controlling buffer behavior.
 *
 * Entry point for buffer selection. Locks the submission context, selects buffers
 * from either a buffer ring or provided list, and commits them if necessary.
 */
int io_buffers_select(struct io_kiocb *req, struct buf_sel_arg *arg,
		      unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret = -ENOENT;

	io_ring_submit_lock(ctx, issue_flags);
	bl = io_buffer_get_list(ctx, req->buf_index);
	if (unlikely(!bl))
		goto out_unlock;

	if (bl->flags & IOBL_BUF_RING) {
		ret = io_ring_buffers_peek(req, arg, bl);
		/*
		 * Don't recycle these buffers if we need to go through poll.
		 * Nobody else can use them anyway, and holding on to provided
		 * buffers for a send/write operation would happen on the app
		 * side anyway with normal buffers. Besides, we already
		 * committed them, they cannot be put back in the queue.
		 */
		if (ret > 0) {
			req->flags |= REQ_F_BUFFERS_COMMIT | REQ_F_BL_NO_RECYCLE;
			io_kbuf_commit(req, bl, arg->out_len, ret);
		}
	} else {
		ret = io_provided_buffers_select(req, &arg->out_len, bl, arg->iovs);
	}
out_unlock:
	io_ring_submit_unlock(ctx, issue_flags);
	return ret;
}

/*
 * io_buffers_peek() - Select buffer(s) for a request from provided list
 * @req: the I/O request context
 * @arg: selection arguments containing maximum length and iovec output
 *
 * This function attempts to select buffers for a request from a
 * buffer list previously registered with the context. If the list
 * uses a ring buffer (IOBL_BUF_RING), it uses a different strategy
 * to peek into it. Otherwise, falls back to legacy behavior.
 *
 * Return: number of buffers selected on success, negative error code on failure.
 */
int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret;

	lockdep_assert_held(&ctx->uring_lock);

	bl = io_buffer_get_list(ctx, req->buf_index);
	if (unlikely(!bl))
		return -ENOENT;

	if (bl->flags & IOBL_BUF_RING) {
		ret = io_ring_buffers_peek(req, arg, bl);
		if (ret > 0)
			req->flags |= REQ_F_BUFFERS_COMMIT;
		return ret;
	}

	/* don't support multiple buffer selections for legacy */
	return io_provided_buffers_select(req, &arg->max_len, bl, arg->iovs);
}

/*
 * __io_remove_buffers() - Internal helper to remove up to @nbufs buffers
 * @ctx: the I/O ring context
 * @bl: buffer list to remove from
 * @nbufs: number of buffers to remove, 0 means no-op
 *
 * Removes buffers from the provided buffer list, either from a ring
 * or legacy list, and returns the count of successfully removed buffers.
 */
static int __io_remove_buffers(struct io_ring_ctx *ctx,
			       struct io_buffer_list *bl, unsigned nbufs)
{
	unsigned i = 0;

	/* shouldn't happen */
	if (!nbufs)
		return 0;

	if (bl->flags & IOBL_BUF_RING) {
		i = bl->buf_ring->tail - bl->head;
		io_free_region(ctx, &bl->region);
		/* make sure it's seen as empty */
		INIT_LIST_HEAD(&bl->buf_list);
		bl->flags &= ~IOBL_BUF_RING;
		return i;
	}

	/* protects io_buffers_cache */
	lockdep_assert_held(&ctx->uring_lock);

	while (!list_empty(&bl->buf_list)) {
		struct io_buffer *nxt;

		nxt = list_first_entry(&bl->buf_list, struct io_buffer, list);
		list_move(&nxt->list, &ctx->io_buffers_cache);
		if (++i == nbufs)
			return i;
		cond_resched();
	}

	return i;
}

/*
 * io_put_bl() - Free a buffer list
 * @ctx: the I/O ring context
 * @bl: the buffer list to free
 *
 * Removes all remaining buffers from the list and frees the memory
 * for the buffer list structure.
 */
static void io_put_bl(struct io_ring_ctx *ctx, struct io_buffer_list *bl)
{
	__io_remove_buffers(ctx, bl, -1U);
	kfree(bl);
}

/*
 * io_destroy_buffers() - Destroy all registered buffers in context
 * @ctx: the I/O ring context
 *
 * Frees all buffer lists and associated buffers, ensuring that both
 * active and cached buffers are properly cleaned up during context
 * teardown.
 */
void io_destroy_buffers(struct io_ring_ctx *ctx)
{
	struct io_buffer_list *bl;
	struct list_head *item, *tmp;
	struct io_buffer *buf;

	while (1) {
		unsigned long index = 0;

		scoped_guard(mutex, &ctx->mmap_lock) {
			bl = xa_find(&ctx->io_bl_xa, &index, ULONG_MAX, XA_PRESENT);
			if (bl)
				xa_erase(&ctx->io_bl_xa, bl->bgid);
		}
		if (!bl)
			break;
		io_put_bl(ctx, bl);
	}

	/*
	 * Move deferred locked entries to cache before pruning
	 */
	spin_lock(&ctx->completion_lock);
	if (!list_empty(&ctx->io_buffers_comp))
		list_splice_init(&ctx->io_buffers_comp, &ctx->io_buffers_cache);
	spin_unlock(&ctx->completion_lock);

	list_for_each_safe(item, tmp, &ctx->io_buffers_cache) {
		buf = list_entry(item, struct io_buffer, list);
		kmem_cache_free(io_buf_cachep, buf);
	}
}

/*
 * io_remove_buffers_prep() - Prepare to remove buffers via SQE
 * @req: the I/O request context
 * @sqe: submission queue entry to extract parameters from
 *
 * Validates the SQE fields and prepares internal state for buffer
 * removal. Returns -EINVAL for any unexpected values in SQE.
 *
 * Return: 0 on success, -EINVAL on invalid input.
 */
static void io_destroy_bl(struct io_ring_ctx *ctx, struct io_buffer_list *bl)
{
	scoped_guard(mutex, &ctx->mmap_lock)
		WARN_ON_ONCE(xa_erase(&ctx->io_bl_xa, bl->bgid) != bl);
	io_put_bl(ctx, bl);
}

/*
 * io_remove_buffers_prep() - Prepare to remove provided buffers from a buffer group.
 * @req: IO request containing user submission queue entry (SQE).
 * @sqe: Submission queue entry with removal parameters.
 *
 * Validates the SQE fields and extracts the number of buffers (nbufs) and
 * buffer group ID (bgid). Returns 0 on success or a negative error code.
 */
int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	u64 tmp;

	if (sqe->rw_flags || sqe->addr || sqe->len || sqe->off ||
	    sqe->splice_fd_in)
		return -EINVAL;

	tmp = READ_ONCE(sqe->fd);
	if (!tmp || tmp > MAX_BIDS_PER_BGID)
		return -EINVAL;

	memset(p, 0, sizeof(*p));
	p->nbufs = tmp;
	p->bgid = READ_ONCE(sqe->buf_group);
	return 0;
}

/*
 * io_remove_buffers() - Remove provided buffers from a buffer group.
 * @req: IO request.
 * @issue_flags: Submission flags.
 *
 * Locates the target buffer list by buffer group ID and removes the requested
 * number of buffers. Fails if buffers are from a mapped buffer ring.
 * Sets the result of the request accordingly.
 */

int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret = 0;

	io_ring_submit_lock(ctx, issue_flags);

	ret = -ENOENT;
	bl = io_buffer_get_list(ctx, p->bgid);
	if (bl) {
		ret = -EINVAL;
		/* can't use provide/remove buffers command on mapped buffers */
		if (!(bl->flags & IOBL_BUF_RING))
			ret = __io_remove_buffers(ctx, bl, p->nbufs);
	}
	io_ring_submit_unlock(ctx, issue_flags);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_provide_buffers_prep() - Prepare a request to provide buffers to a buffer group.
 * @req: IO request.
 * @sqe: Submission queue entry describing the buffers.
 *
 * Validates SQE values and ensures user-supplied memory is accessible.
 * Populates the internal command structure with buffer parameters.
 * Returns 0 on success or an error code on failure.
 */
int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	unsigned long size, tmp_check;
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	u64 tmp;

	if (sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	tmp = READ_ONCE(sqe->fd);
	if (!tmp || tmp > MAX_BIDS_PER_BGID)
		return -E2BIG;
	p->nbufs = tmp;
	p->addr = READ_ONCE(sqe->addr);
	p->len = READ_ONCE(sqe->len);

	if (check_mul_overflow((unsigned long)p->len, (unsigned long)p->nbufs,
				&size))
		return -EOVERFLOW;
	if (check_add_overflow((unsigned long)p->addr, size, &tmp_check))
		return -EOVERFLOW;

	size = (unsigned long)p->len * p->nbufs;
	if (!access_ok(u64_to_user_ptr(p->addr), size))
		return -EFAULT;

	p->bgid = READ_ONCE(sqe->buf_group);
	tmp = READ_ONCE(sqe->off);
	if (tmp > USHRT_MAX)
		return -E2BIG;
	if (tmp + p->nbufs > MAX_BIDS_PER_BGID)
		return -EINVAL;
	p->bid = tmp;
	return 0;
}

#define IO_BUFFER_ALLOC_BATCH 64

/*
 * io_refill_buffer_cache() - Refill the internal buffer cache with new buffer entries.
 * @ctx: io_uring context.
 *
 * Moves completed buffers to the free list if present. Otherwise,
 * allocates a new batch of buffers and adds them to the cache list.
 * Returns 0 on success, or -ENOMEM on allocation failure.
 */
static int io_refill_buffer_cache(struct io_ring_ctx *ctx)
{
	struct io_buffer *bufs[IO_BUFFER_ALLOC_BATCH];
	int allocated;

	/*
	 * Completions that don't happen inline (eg not under uring_lock) will
	 * add to ->io_buffers_comp. If we don't have any free buffers, check
	 * the completion list and splice those entries first.
	 */
	if (!list_empty_careful(&ctx->io_buffers_comp)) {
		spin_lock(&ctx->completion_lock);
		if (!list_empty(&ctx->io_buffers_comp)) {
			list_splice_init(&ctx->io_buffers_comp,
						&ctx->io_buffers_cache);
			spin_unlock(&ctx->completion_lock);
			return 0;
		}
		spin_unlock(&ctx->completion_lock);
	}

	/*
	 * No free buffers and no completion entries either. Allocate a new
	 * batch of buffer entries and add those to our freelist.
	 */

	allocated = kmem_cache_alloc_bulk(io_buf_cachep, GFP_KERNEL_ACCOUNT,
					  ARRAY_SIZE(bufs), (void **) bufs);
	if (unlikely(!allocated)) {
		/*
		 * Bulk alloc is all-or-nothing. If we fail to get a batch,
		 * retry single alloc to be on the safe side.
		 */
		bufs[0] = kmem_cache_alloc(io_buf_cachep, GFP_KERNEL);
		if (!bufs[0])
			return -ENOMEM;
		allocated = 1;
	}

	while (allocated)
		list_add_tail(&bufs[--allocated]->list, &ctx->io_buffers_cache);

	return 0;
}

/*
 * io_add_buffers() - Add user-provided buffers to a buffer list.
 * @ctx: io_uring context.
 * @pbuf: Buffer information from user request.
 * @bl: Target buffer list.
 *
 * Takes buffers from the cache, initializes them, and attaches them
 * to the buffer list. Stops early if the cache runs out and refill fails.
 * Returns 0 on success, or -ENOMEM if no buffers could be added.
 */

static int io_add_buffers(struct io_ring_ctx *ctx, struct io_provide_buf *pbuf,
			  struct io_buffer_list *bl)
{
	struct io_buffer *buf;
	u64 addr = pbuf->addr;
	int i, bid = pbuf->bid;

	for (i = 0; i < pbuf->nbufs; i++) {
		if (list_empty(&ctx->io_buffers_cache) &&
		    io_refill_buffer_cache(ctx))
			break;
		buf = list_first_entry(&ctx->io_buffers_cache, struct io_buffer,
					list);
		list_move_tail(&buf->list, &bl->buf_list);
		buf->addr = addr;
		buf->len = min_t(__u32, pbuf->len, MAX_RW_COUNT);
		buf->bid = bid;
		buf->bgid = pbuf->bgid;
		addr += pbuf->len;
		bid++;
		cond_resched();
	}

	return i ? 0 : -ENOMEM;
}

/*
 * io_provide_buffers() - Add provided buffers to a buffer group.
 * @req: IO request.
 * @issue_flags: Submission flags.
 *
 * Locates or creates the buffer list associated with a given buffer group ID.
 * Validates that the buffer list is not using a mapped ring. Then fills
 * the list with buffers using the cached entries.
 * Sets the request result to indicate success or error.
 */

int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret = 0;

	io_ring_submit_lock(ctx, issue_flags);

	bl = io_buffer_get_list(ctx, p->bgid);
	if (unlikely(!bl)) {
		bl = kzalloc(sizeof(*bl), GFP_KERNEL_ACCOUNT);
		if (!bl) {
			ret = -ENOMEM;
			goto err;
		}
		INIT_LIST_HEAD(&bl->buf_list);
		ret = io_buffer_add_list(ctx, bl, p->bgid);
		if (ret) {
			kfree(bl);
			goto err;
		}
	}
	/* can't add buffers via this command for a mapped buffer ring */
	if (bl->flags & IOBL_BUF_RING) {
		ret = -EINVAL;
		goto err;
	}

	ret = io_add_buffers(ctx, p, bl);
err:
	io_ring_submit_unlock(ctx, issue_flags);

	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_register_pbuf_ring() - Register a shared buffer ring mapped into userspace.
 * @ctx: io_uring context.
 * @arg: User pointer to struct io_uring_buf_reg describing the ring.
 *
 * Validates input and ensures no conflicting mappings or buffer lists exist.
 * Allocates and sets up a ring buffer for shared use between user and kernel,
 * supporting both mmap-based and user-supplied address registration.
 * Returns 0 on success, or an appropriate error code on failure.
 */

int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_uring_buf_reg reg;
	struct io_buffer_list *bl, *free_bl = NULL;
	struct io_uring_region_desc rd;
	struct io_uring_buf_ring *br;
	unsigned long mmap_offset;
	unsigned long ring_size;
	int ret;

	lockdep_assert_held(&ctx->uring_lock);

	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;

	if (reg.resv[0] || reg.resv[1] || reg.resv[2])
		return -EINVAL;
	if (reg.flags & ~(IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC))
		return -EINVAL;
	if (!is_power_of_2(reg.ring_entries))
		return -EINVAL;
	/* cannot disambiguate full vs empty due to head/tail size */
	if (reg.ring_entries >= 65536)
		return -EINVAL;

	bl = io_buffer_get_list(ctx, reg.bgid);
	if (bl) {
		/* if mapped buffer ring OR classic exists, don't allow */
		if (bl->flags & IOBL_BUF_RING || !list_empty(&bl->buf_list))
			return -EEXIST;
		io_destroy_bl(ctx, bl);
	}

	free_bl = bl = kzalloc(sizeof(*bl), GFP_KERNEL);
	if (!bl)
		return -ENOMEM;

	mmap_offset = (unsigned long)reg.bgid << IORING_OFF_PBUF_SHIFT;
	ring_size = flex_array_size(br, bufs, reg.ring_entries);

	memset(&rd, 0, sizeof(rd));
	rd.size = PAGE_ALIGN(ring_size);
	if (!(reg.flags & IOU_PBUF_RING_MMAP)) {
		rd.user_addr = reg.ring_addr;
		rd.flags |= IORING_MEM_REGION_TYPE_USER;
	}
	ret = io_create_region_mmap_safe(ctx, &bl->region, &rd, mmap_offset);
	if (ret)
		goto fail;
	br = io_region_get_ptr(&bl->region);

#ifdef SHM_COLOUR
	/*
	 * On platforms that have specific aliasing requirements, SHM_COLOUR
	 * is set and we must guarantee that the kernel and user side align
	 * nicely. We cannot do that if IOU_PBUF_RING_MMAP isn't set and
	 * the application mmap's the provided ring buffer. Fail the request
	 * if we, by chance, don't end up with aligned addresses. The app
	 * should use IOU_PBUF_RING_MMAP instead, and liburing will handle
	 * this transparently.
	 */
	if (!(reg.flags & IOU_PBUF_RING_MMAP) &&
	    ((reg.ring_addr | (unsigned long)br) & (SHM_COLOUR - 1))) {
		ret = -EINVAL;
		goto fail;
	}
#endif

	bl->nr_entries = reg.ring_entries;
	bl->mask = reg.ring_entries - 1;
	bl->flags |= IOBL_BUF_RING;
	bl->buf_ring = br;
	if (reg.flags & IOU_PBUF_RING_INC)
		bl->flags |= IOBL_INC;
	io_buffer_add_list(ctx, bl, reg.bgid);
	return 0;
fail:
	io_free_region(ctx, &bl->region);
	kfree(free_bl);
	return ret;
}

/*
 * io_unregister_pbuf_ring() - Unregister a previously registered buffer ring.
 * @ctx: io_uring context.
 * @arg: User pointer to struct io_uring_buf_reg describing the ring to unregister.
 *
 * Validates the input, checks that the specified buffer group exists and was
 * registered as a shared buffer ring. If valid, removes the buffer group from
 * the buffer list XArray and releases associated resources.
 *
 * Must be called with uring_lock held.
 *
 * Returns 0 on success or a negative error code on failure.
 */
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_uring_buf_reg reg;
	struct io_buffer_list *bl;

	lockdep_assert_held(&ctx->uring_lock);

	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (reg.resv[0] || reg.resv[1] || reg.resv[2])
		return -EINVAL;
	if (reg.flags)
		return -EINVAL;

	bl = io_buffer_get_list(ctx, reg.bgid);
	if (!bl)
		return -ENOENT;
	if (!(bl->flags & IOBL_BUF_RING))
		return -EINVAL;

	scoped_guard(mutex, &ctx->mmap_lock)
		xa_erase(&ctx->io_bl_xa, bl->bgid);

	io_put_bl(ctx, bl);
	return 0;
}

/*
 * io_register_pbuf_status() - Return the current head index of a buffer ring.
 * @ctx: io_uring context.
 * @arg: User pointer to struct io_uring_buf_status for querying the buffer ring status.
 *
 * Validates user input and buffer group existence, and confirms the group is
 * backed by a registered buffer ring. Copies the current ring head index back
 * to user space.
 *
 * Returns 0 on success, -ENOENT if the group is not found, or other negative
 * error codes on failure.
 */

int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_uring_buf_status buf_status;
	struct io_buffer_list *bl;
	int i;

	if (copy_from_user(&buf_status, arg, sizeof(buf_status)))
		return -EFAULT;

	for (i = 0; i < ARRAY_SIZE(buf_status.resv); i++)
		if (buf_status.resv[i])
			return -EINVAL;

	bl = io_buffer_get_list(ctx, buf_status.buf_group);
	if (!bl)
		return -ENOENT;
	if (!(bl->flags & IOBL_BUF_RING))
		return -EINVAL;

	buf_status.head = bl->head;
	if (copy_to_user(arg, &buf_status, sizeof(buf_status)))
		return -EFAULT;

	return 0;
}

/*
 * io_pbuf_get_region() - Get the mapped region of a registered buffer ring.
 * @ctx: io_uring context.
 * @bgid: Buffer group ID.
 *
 * Loads the buffer list from the XArray and returns the mapped region pointer
 * if the group is a valid buffer ring. This function must be called with the
 * mmap_lock held.
 *
 * Returns pointer to io_mapped_region on success, or NULL if not found or not a ring.
 */

struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx,
					    unsigned int bgid)
{
	struct io_buffer_list *bl;

	lockdep_assert_held(&ctx->mmap_lock);

	bl = xa_load(&ctx->io_bl_xa, bgid);
	if (!bl || !(bl->flags & IOBL_BUF_RING))
		return NULL;
	return &bl->region;
}
