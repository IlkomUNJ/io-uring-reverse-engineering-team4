// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"
#include "alloc_cache.h"
#include "msg_ring.h"

/* All valid masks for MSG_RING */
#define IORING_MSG_RING_MASK		(IORING_MSG_RING_CQE_SKIP | \
					IORING_MSG_RING_FLAGS_PASS)

struct io_msg {
	struct file			*file;
	struct file			*src_file;
	struct callback_head		tw;
	u64 user_data;
	u32 len;
	u32 cmd;
	u32 src_fd;
	union {
		u32 dst_fd;
		u32 cqe_flags;
	};
	u32 flags;
};

/*
 * io_double_unlock_ctx() - Unlock the target io_uring context.
 * @octx: The target io_uring context to unlock.
 *
 * Unlocks the uring_lock for the given context. Used when two contexts
 * are involved and the secondary lock was previously acquired.
 */
static void io_double_unlock_ctx(struct io_ring_ctx *octx)
{
	mutex_unlock(&octx->uring_lock);
}

/*
 * io_double_lock_ctx() - Attempt to lock a second io_uring context.
 * @octx: The target io_uring context to lock.
 * @issue_flags: Flags that control lock behavior, e.g., IO_URING_F_UNLOCKED.
 *
 * Used when operating across multiple contexts to avoid deadlock.
 * If IO_URING_F_UNLOCKED is not set, a trylock is performed on the
 * target context. If locking fails, the caller must fallback to
 * task work offload. Otherwise, a blocking lock is used.
 *
 * Returns 0 on success or -EAGAIN if trylock fails.
 */

static int io_double_lock_ctx(struct io_ring_ctx *octx,
			      unsigned int issue_flags)
{
	/*
	 * To ensure proper ordering between the two ctxs, we can only
	 * attempt a trylock on the target. If that fails and we already have
	 * the source ctx lock, punt to io-wq.
	 */
	if (!(issue_flags & IO_URING_F_UNLOCKED)) {
		if (!mutex_trylock(&octx->uring_lock))
			return -EAGAIN;
		return 0;
	}
	mutex_lock(&octx->uring_lock);
	return 0;
}

/*
 * io_msg_ring_cleanup() - Cleanup after a message ring request.
 * @req: The request to clean up.
 *
 * Releases the reference on the source file of a message and clears
 * the pointer. Must be called before freeing the request.
 */

void io_msg_ring_cleanup(struct io_kiocb *req)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);

	if (WARN_ON_ONCE(!msg->src_file))
		return;

	fput(msg->src_file);
	msg->src_file = NULL;
}

/*
 * io_msg_need_remote() - Determine if target context requires task_work.
 * @target_ctx: The target io_uring context.
 *
 * Returns true if the target context has a task_complete handler,
 * indicating that it requires message delivery via task_work.
 */

static inline bool io_msg_need_remote(struct io_ring_ctx *target_ctx)
{
	return target_ctx->task_complete;
}

/*
 * io_msg_tw_complete() - Task work completion handler for message ring.
 * @req: The completed message request.
 * @ts: Task work state (unused).
 *
 * Completes the message ring request by delivering an auxiliary CQE,
 * and returns the request to the cache or frees it if caching is not possible.
 * Also releases the context reference.
 */

static void io_msg_tw_complete(struct io_kiocb *req, struct io_tw_state *ts)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_add_aux_cqe(ctx, req->cqe.user_data, req->cqe.res, req->cqe.flags);
	if (spin_trylock(&ctx->msg_lock)) {
		if (io_alloc_cache_put(&ctx->msg_cache, req))
			req = NULL;
		spin_unlock(&ctx->msg_lock);
	}
	if (req)
		kmem_cache_free(req_cachep, req);
	percpu_ref_put(&ctx->refs);
}

/*
 * io_msg_remote_post() - Post a message to a remote io_uring instance.
 * @ctx: Target context to which the message is sent.
 * @req: The request structure to post.
 * @res: Result value to set in the CQE.
 * @cflags: CQE flags to set.
 * @user_data: User data to set in the CQE.
 *
 * If the target context still has a valid submitter task, sets up
 * the request to complete via task_work and posts it. Otherwise,
 * frees the request and returns -EOWNERDEAD.
 *
 * Returns 0 on success, or a negative error code on failure.
 */

static int io_msg_remote_post(struct io_ring_ctx *ctx, struct io_kiocb *req,
			      int res, u32 cflags, u64 user_data)
{
	if (!READ_ONCE(ctx->submitter_task)) {
		kmem_cache_free(req_cachep, req);
		return -EOWNERDEAD;
	}
	req->cqe.user_data = user_data;
	io_req_set_res(req, res, cflags);
	percpu_ref_get(&ctx->refs);
	req->ctx = ctx;
	req->tctx = NULL;
	req->io_task_work.func = io_msg_tw_complete;
	io_req_task_work_add_remote(req, ctx, IOU_F_TWQ_LAZY_WAKE);
	return 0;
}

/*
 * io_msg_get_kiocb() - Allocate or fetch a message request structure.
 * @ctx: The target io_uring context.
 *
 * Attempts to get a request from the per-context msg_cache using a spinlock.
 * Falls back to a slab allocation if no cached request is available.
 *
 * Returns a valid io_kiocb pointer on success, or NULL on failure.
 */

static struct io_kiocb *io_msg_get_kiocb(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req = NULL;

	if (spin_trylock(&ctx->msg_lock)) {
		req = io_alloc_cache_get(&ctx->msg_cache);
		spin_unlock(&ctx->msg_lock);
		if (req)
			return req;
	}
	return kmem_cache_alloc(req_cachep, GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
}

/*
 * io_msg_data_remote() - Post message data to a remote context.
 * @target_ctx: The target io_uring context.
 * @msg: The message to send.
 *
 * Allocates a request structure and sends it to the target context
 * using io_msg_remote_post(). Sets flags from msg if applicable.
 *
 * Returns 0 on success, or -ENOMEM if allocation fails.
 */

static int io_msg_data_remote(struct io_ring_ctx *target_ctx,
			      struct io_msg *msg)
{
	struct io_kiocb *target;
	u32 flags = 0;

	target = io_msg_get_kiocb(target_ctx);
	if (unlikely(!target))
		return -ENOMEM;

	if (msg->flags & IORING_MSG_RING_FLAGS_PASS)
		flags = msg->cqe_flags;

	return io_msg_remote_post(target_ctx, target, msg->len, flags,
					msg->user_data);
}

/*
 * __io_msg_ring_data() - Core handler for sending a message to another ring.
 * @target_ctx: The target io_uring context.
 * @msg: The message containing data or control info.
 * @issue_flags: Flags controlling submission behavior.
 *
 * This function performs checks and posts a message to a target ring.
 * It handles both remote and local contexts, IOPOLL locking, and error states.
 *
 * Returns 0 on success, or a negative error code on failure.
 */

static int __io_msg_ring_data(struct io_ring_ctx *target_ctx,
			      struct io_msg *msg, unsigned int issue_flags)
{
	u32 flags = 0;
	int ret;

	if (msg->src_fd || msg->flags & ~IORING_MSG_RING_FLAGS_PASS)
		return -EINVAL;
	if (!(msg->flags & IORING_MSG_RING_FLAGS_PASS) && msg->dst_fd)
		return -EINVAL;
	if (target_ctx->flags & IORING_SETUP_R_DISABLED)
		return -EBADFD;

	if (io_msg_need_remote(target_ctx))
		return io_msg_data_remote(target_ctx, msg);

	if (msg->flags & IORING_MSG_RING_FLAGS_PASS)
		flags = msg->cqe_flags;

	ret = -EOVERFLOW;
	if (target_ctx->flags & IORING_SETUP_IOPOLL) {
		if (unlikely(io_double_lock_ctx(target_ctx, issue_flags)))
			return -EAGAIN;
	}
	if (io_post_aux_cqe(target_ctx, msg->user_data, msg->len, flags))
		ret = 0;
	if (target_ctx->flags & IORING_SETUP_IOPOLL)
		io_double_unlock_ctx(target_ctx);
	return ret;
}

/*
 * io_msg_ring_data() - Entry point to send data to another io_uring ring.
 * @req: The io_kiocb request containing the message.
 * @issue_flags: Submission flags from the submitter.
 *
 * Calls the internal __io_msg_ring_data() using data extracted from the request.
 *
 * Returns 0 on success, or a negative error code on failure.
 */

static int io_msg_ring_data(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);

	return __io_msg_ring_data(target_ctx, msg, issue_flags);
}

/*
 * io_msg_grab_file() - Acquire a file reference for message passing.
 * @req: The request which contains the source file descriptor.
 * @issue_flags: Submission flags used for locking.
 *
 * Looks up the file descriptor in the file table and increments the refcount.
 * Marks the request for cleanup if a file is successfully acquired.
 *
 * Returns 0 on success, or -EBADF if the file descriptor is invalid.
 */

static int io_msg_grab_file(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_rsrc_node *node;
	int ret = -EBADF;

	io_ring_submit_lock(ctx, issue_flags);
	node = io_rsrc_node_lookup(&ctx->file_table.data, msg->src_fd);
	if (node) {
		msg->src_file = io_slot_file(node);
		if (msg->src_file)
			get_file(msg->src_file);
		req->flags |= REQ_F_NEED_CLEANUP;
		ret = 0;
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return ret;
}

/*
 * io_msg_install_complete() - Install a passed file descriptor in the target ring.
 * @req: The original request that triggered the file transfer.
 * @issue_flags: Submission flags controlling lock acquisition.
 *
 * Installs the file descriptor into the target io_uring using fixed fd slots.
 * Optionally posts a completion CQE if IORING_MSG_RING_CQE_SKIP is not set.
 *
 * Returns 0 on success or a negative error code on failure.
 */

static int io_msg_install_complete(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct file *src_file = msg->src_file;
	int ret;

	if (unlikely(io_double_lock_ctx(target_ctx, issue_flags)))
		return -EAGAIN;

	ret = __io_fixed_fd_install(target_ctx, src_file, msg->dst_fd);
	if (ret < 0)
		goto out_unlock;

	msg->src_file = NULL;
	req->flags &= ~REQ_F_NEED_CLEANUP;

	if (msg->flags & IORING_MSG_RING_CQE_SKIP)
		goto out_unlock;
	/*
	 * If this fails, the target still received the file descriptor but
	 * wasn't notified of the fact. This means that if this request
	 * completes with -EOVERFLOW, then the sender must ensure that a
	 * later IORING_OP_MSG_RING delivers the message.
	 */
	if (!io_post_aux_cqe(target_ctx, msg->user_data, ret, 0))
		ret = -EOVERFLOW;
out_unlock:
	io_double_unlock_ctx(target_ctx);
	return ret;
}

/*
 * io_msg_tw_fd_complete() - Task work handler for completing fd installation.
 * @head: The callback_head structure embedded in the io_msg.
 *
 * This runs in the context of the target task and installs the file descriptor.
 * If the install fails, the request is completed with an error.
 */

static void io_msg_tw_fd_complete(struct callback_head *head)
{
	struct io_msg *msg = container_of(head, struct io_msg, tw);
	struct io_kiocb *req = cmd_to_io_kiocb(msg);
	int ret = -EOWNERDEAD;

	if (!(current->flags & PF_EXITING))
		ret = io_msg_install_complete(req, IO_URING_F_UNLOCKED);
	if (ret < 0)
		req_set_fail(req);
	io_req_queue_tw_complete(req, ret);
}

/*
 * io_msg_fd_remote() - Schedule a remote file descriptor transfer.
 * @req: The request containing the file descriptor and message metadata.
 *
 * Schedules a task_work handler in the target ring’s submitter task to
 * install the file descriptor. Used when direct locking is not possible.
 *
 * Returns IOU_ISSUE_SKIP_COMPLETE if scheduled, or a negative error code.
 */

static int io_msg_fd_remote(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct task_struct *task = READ_ONCE(ctx->submitter_task);

	if (unlikely(!task))
		return -EOWNERDEAD;

	init_task_work(&msg->tw, io_msg_tw_fd_complete);
	if (task_work_add(task, &msg->tw, TWA_SIGNAL))
		return -EOWNERDEAD;

	return IOU_ISSUE_SKIP_COMPLETE;
}

/*
 * io_msg_send_fd() - Entry point for sending a file descriptor to another ring.
 * @req: The request with message and file info.
 * @issue_flags: Submission flags for lock and context control.
 *
 * Performs validation, ensures the source file is available, and dispatches
 * the installation either directly or through task_work if remote completion
 * is required.
 *
 * Returns 0 on success or a negative error code on failure.
 */

static int io_msg_send_fd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct io_ring_ctx *ctx = req->ctx;

	if (msg->len)
		return -EINVAL;
	if (target_ctx == ctx)
		return -EINVAL;
	if (target_ctx->flags & IORING_SETUP_R_DISABLED)
		return -EBADFD;
	if (!msg->src_file) {
		int ret = io_msg_grab_file(req, issue_flags);
		if (unlikely(ret))
			return ret;
	}

	if (io_msg_need_remote(target_ctx))
		return io_msg_fd_remote(req);
	return io_msg_install_complete(req, issue_flags);
}

/*
 * __io_msg_ring_prep() - Prepare a message ring command from a SQE.
 * @msg: The io_msg structure to populate.
 * @sqe: Submission queue entry containing the user-supplied data.
 *
 * Extracts fields from the SQE and initializes the io_msg structure.
 * Validates flags to ensure only supported ones are used.
 *
 * Returns 0 on success or -EINVAL on invalid input.
 */

static int __io_msg_ring_prep(struct io_msg *msg, const struct io_uring_sqe *sqe)
{
	if (unlikely(sqe->buf_index || sqe->personality))
		return -EINVAL;

	msg->src_file = NULL;
	msg->user_data = READ_ONCE(sqe->off);
	msg->len = READ_ONCE(sqe->len);
	msg->cmd = READ_ONCE(sqe->addr);
	msg->src_fd = READ_ONCE(sqe->addr3);
	msg->dst_fd = READ_ONCE(sqe->file_index);
	msg->flags = READ_ONCE(sqe->msg_ring_flags);
	if (msg->flags & ~IORING_MSG_RING_MASK)
		return -EINVAL;

	return 0;
}

/*
 * io_msg_ring_prep() - Public interface for message ring preparation.
 * @req: The request structure to initialize.
 * @sqe: The submission queue entry.
 *
 * Wraps the internal prep function for message ring operations.
 *
 * Returns 0 on success or -EINVAL on invalid input.
 */

int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_msg_ring_prep(io_kiocb_to_cmd(req, struct io_msg), sqe);
}

/*
 * io_msg_ring() - Execute a message ring operation.
 * @req: The prepared io_kiocb request.
 * @issue_flags: Flags controlling submission and locking behavior.
 *
 * Validates the file type, then dispatches the operation based on
 * the command type in the io_msg (e.g., data send or fd send).
 * Handles error codes appropriately and sets the result.
 *
 * Returns IOU_OK on handled completion, or negative error code to retry.
 */

int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	int ret;

	ret = -EBADFD;
	if (!io_is_uring_fops(req->file))
		goto done;

	switch (msg->cmd) {
	case IORING_MSG_DATA:
		ret = io_msg_ring_data(req, issue_flags);
		break;
	case IORING_MSG_SEND_FD:
		ret = io_msg_send_fd(req, issue_flags);
		break;
	default:
		ret = -EINVAL;
		break;
	}

done:
	if (ret < 0) {
		if (ret == -EAGAIN || ret == IOU_ISSUE_SKIP_COMPLETE)
			return ret;
		req_set_fail(req);
	}
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_uring_sync_msg_ring() - Synchronous message ring submission.
 * @sqe: Submission queue entry representing the message.
 *
 * Intended for in-kernel or internal use where an sqe needs to be
 * executed synchronously, without a full request lifecycle.
 * Only supports IORING_MSG_DATA (not file descriptor transfers).
 *
 * Returns 0 on success, or a negative error code.
 */

int io_uring_sync_msg_ring(struct io_uring_sqe *sqe)
{
	struct io_msg io_msg = { };
	int ret;

	ret = __io_msg_ring_prep(&io_msg, sqe);
	if (unlikely(ret))
		return ret;

	/*
	 * Only data sending supported, not IORING_MSG_SEND_FD as that one
	 * doesn't make sense without a source ring to send files from.
	 */
	if (io_msg.cmd != IORING_MSG_DATA)
		return -EINVAL;

	CLASS(fd, f)(sqe->fd);
	if (fd_empty(f))
		return -EBADF;
	if (!io_is_uring_fops(fd_file(f)))
		return -EBADFD;
	return  __io_msg_ring_data(fd_file(f)->private_data,
				   &io_msg, IO_URING_F_UNLOCKED);
}
