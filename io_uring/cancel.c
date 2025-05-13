// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "tctx.h"
#include "poll.h"
#include "timeout.h"
#include "waitid.h"
#include "futex.h"
#include "cancel.h"

struct io_cancel {
	struct file			*file;
	u64				addr;
	u32				flags;
	s32				fd;
	u8				opcode;
};

#define CANCEL_FLAGS	(IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_FD | \
			 IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_FD_FIXED | \
			 IORING_ASYNC_CANCEL_USERDATA | IORING_ASYNC_CANCEL_OP)

/*
 * Returns true if the request matches the criteria outlined by 'cd'.
 */

/*
 * io_cancel_req_match - Check whether a request matches the cancellation criteria
 *
 * @req: the io_kiocb request to compare
 * @cd: cancellation data containing matching flags and values
 *
 * Determines whether the given request matches the specified criteria
 * for cancellation. These criteria can include matching context, file
 * descriptor, opcode, user data, and sequence constraints.
 *
 * Returns true if the request matches and is eligible for cancellation,
 * false otherwise.
 */
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd)
{
	bool match_user_data = cd->flags & IORING_ASYNC_CANCEL_USERDATA;

	if (req->ctx != cd->ctx)
		return false;

	if (!(cd->flags & (IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_OP)))
		match_user_data = true;

	if (cd->flags & IORING_ASYNC_CANCEL_ANY)
		goto check_seq;
	if (cd->flags & IORING_ASYNC_CANCEL_FD) {
		if (req->file != cd->file)
			return false;
	}
	if (cd->flags & IORING_ASYNC_CANCEL_OP) {
		if (req->opcode != cd->opcode)
			return false;
	}
	if (match_user_data && req->cqe.user_data != cd->data)
		return false;
	if (cd->flags & IORING_ASYNC_CANCEL_ALL) {
check_seq:
		if (io_cancel_match_sequence(req, cd->seq))
			return false;
	}

	return true;
}

/*
 * io_cancel_cb - Callback used during cancellation to find a matching request
 *
 * @work: work item being considered for cancellation
 * @data: cancellation data passed into the cancel operation
 *
 * Casts the generic work item back to an io_kiocb and invokes
 * io_cancel_req_match to determine if this work should be canceled.
 *
 * Returns true if the request matches the cancellation conditions,
 * false otherwise.
 */
static bool io_cancel_cb(struct io_wq_work *work, void *data)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_cancel_data *cd = data;

	return io_cancel_req_match(req, cd);
}

/*
 * io_async_cancel_one - Attempt to cancel a single async request
 *
 * @tctx: the io_uring task context of the submitting thread
 * @cd: cancellation data specifying match criteria
 *
 * Initiates cancellation of an asynchronous work item in the io_wq
 * based on the given criteria. Returns appropriate error codes depending
 * on the result of the cancellation attempt.
 *
 * Return values:
 *  0            - request canceled successfully
 * -EALREADY     - request is currently running and cannot be canceled
 * -ENOENT       - no matching request found or io_wq is unavailable
 */
static int io_async_cancel_one(struct io_uring_task *tctx,
			       struct io_cancel_data *cd)
{
	enum io_wq_cancel cancel_ret;
	int ret = 0;
	bool all;

	if (!tctx || !tctx->io_wq)
		return -ENOENT;

	all = cd->flags & (IORING_ASYNC_CANCEL_ALL|IORING_ASYNC_CANCEL_ANY);
	cancel_ret = io_wq_cancel_cb(tctx->io_wq, io_cancel_cb, cd, all);
	switch (cancel_ret) {
	case IO_WQ_CANCEL_OK:
		ret = 0;
		break;
	case IO_WQ_CANCEL_RUNNING:
		ret = -EALREADY;
		break;
	case IO_WQ_CANCEL_NOTFOUND:
		ret = -ENOENT;
		break;
	}

	return ret;
}

/*
 * io_try_cancel - Attempt to cancel a request from multiple sources
 *
 * @tctx:     io_uring task context associated with the request
 * @cd:       cancellation data specifying match criteria
 * @issue_flags: submission flags
 *
 * Tries to cancel a matching request in the async workqueue. If not found,
 * attempts cancellation in other subsystems including poll, waitid, futex,
 * and timeouts. If a timeout match is attempted, the completion_lock is held.
 *
 * Returns 0 on successful cancelation, or a negative error code if not found.
 */
int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned issue_flags)
{
	struct io_ring_ctx *ctx = cd->ctx;
	int ret;

	WARN_ON_ONCE(!io_wq_current_is_worker() && tctx != current->io_uring);

	ret = io_async_cancel_one(tctx, cd);
	/*
	 * Fall-through even for -EALREADY, as we may have poll armed
	 * that need unarming.
	 */
	if (!ret)
		return 0;

	ret = io_poll_cancel(ctx, cd, issue_flags);
	if (ret != -ENOENT)
		return ret;

	ret = io_waitid_cancel(ctx, cd, issue_flags);
	if (ret != -ENOENT)
		return ret;

	ret = io_futex_cancel(ctx, cd, issue_flags);
	if (ret != -ENOENT)
		return ret;

	spin_lock(&ctx->completion_lock);
	if (!(cd->flags & IORING_ASYNC_CANCEL_FD))
		ret = io_timeout_cancel(ctx, cd);
	spin_unlock(&ctx->completion_lock);
	return ret;
}

/*
 * io_async_cancel_prep - Prepare an async cancel request
 *
 * @req: the request context
 * @sqe: the submission queue entry from userspace
 *
 * Parses and validates fields from the SQE needed for an async cancellation
 * request. Ensures valid flag combinations and extracts the cancellation
 * target data, such as fd or opcode.
 *
 * Returns 0 on success, or -EINVAL if parameters are invalid.
 */
int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_cancel *cancel = io_kiocb_to_cmd(req, struct io_cancel);

	if (unlikely(req->flags & REQ_F_BUFFER_SELECT))
		return -EINVAL;
	if (sqe->off || sqe->splice_fd_in)
		return -EINVAL;

	cancel->addr = READ_ONCE(sqe->addr);
	cancel->flags = READ_ONCE(sqe->cancel_flags);
	if (cancel->flags & ~CANCEL_FLAGS)
		return -EINVAL;
	if (cancel->flags & IORING_ASYNC_CANCEL_FD) {
		if (cancel->flags & IORING_ASYNC_CANCEL_ANY)
			return -EINVAL;
		cancel->fd = READ_ONCE(sqe->fd);
	}
	if (cancel->flags & IORING_ASYNC_CANCEL_OP) {
		if (cancel->flags & IORING_ASYNC_CANCEL_ANY)
			return -EINVAL;
		cancel->opcode = READ_ONCE(sqe->len);
	}

	return 0;
}

/*
 * __io_async_cancel - Internal implementation of async cancellation
 *
 * @cd:           cancellation data
 * @tctx:         task context of the originating request
 * @issue_flags:  submission flags
 *
 * Attempts to cancel the request identified by @cd first using the provided
 * @tctx. If the 'all' flag is set, continues trying across all io_uring
 * task contexts. Used internally by io_async_cancel.
 *
 * Returns the number of requests canceled if 'all' is set,
 * or 0/-ENOENT/-EALREADY for single cancel operations.
 */
static int __io_async_cancel(struct io_cancel_data *cd,
			     struct io_uring_task *tctx,
			     unsigned int issue_flags)
{
	bool all = cd->flags & (IORING_ASYNC_CANCEL_ALL|IORING_ASYNC_CANCEL_ANY);
	struct io_ring_ctx *ctx = cd->ctx;
	struct io_tctx_node *node;
	int ret, nr = 0;

	do {
		ret = io_try_cancel(tctx, cd, issue_flags);
		if (ret == -ENOENT)
			break;
		if (!all)
			return ret;
		nr++;
	} while (1);

	/* slow path, try all io-wq's */
	io_ring_submit_lock(ctx, issue_flags);
	ret = -ENOENT;
	list_for_each_entry(node, &ctx->tctx_list, ctx_node) {
		ret = io_async_cancel_one(node->task->io_uring, cd);
		if (ret != -ENOENT) {
			if (!all)
				break;
			nr++;
		}
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return all ? nr : ret;
}

/*
 * io_async_cancel - Main handler for asynchronous cancellation requests
 *
 * @req:         the original request to cancel another operation
 * @issue_flags: submission flags
 *
 * This function dispatches an asynchronous cancellation attempt using the
 * parameters parsed and stored in the request. It handles setup for file
 * descriptors, builds the cancellation data, and calls the internal cancel
 * logic (__io_async_cancel). The result is stored in the request's result
 * field for later reporting.
 *
 * Always returns IOU_OK. The actual success/failure is indicated in the result.
 */
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_cancel *cancel = io_kiocb_to_cmd(req, struct io_cancel);
	struct io_cancel_data cd = {
		.ctx	= req->ctx,
		.data	= cancel->addr,
		.flags	= cancel->flags,
		.opcode	= cancel->opcode,
		.seq	= atomic_inc_return(&req->ctx->cancel_seq),
	};
	struct io_uring_task *tctx = req->tctx;
	int ret;

	if (cd.flags & IORING_ASYNC_CANCEL_FD) {
		if (req->flags & REQ_F_FIXED_FILE ||
		    cd.flags & IORING_ASYNC_CANCEL_FD_FIXED) {
			req->flags |= REQ_F_FIXED_FILE;
			req->file = io_file_get_fixed(req, cancel->fd,
							issue_flags);
		} else {
			req->file = io_file_get_normal(req, cancel->fd);
		}
		if (!req->file) {
			ret = -EBADF;
			goto done;
		}
		cd.file = req->file;
	}

	ret = __io_async_cancel(&cd, tctx, issue_flags);
done:
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * __io_sync_cancel - Internal synchronous cancelation helper
 *
 * @tctx: io_uring task context to cancel within
 * @cd:   cancelation data with matching criteria
 * @fd:   file descriptor, used if cancelation is FD-based
 *
 * Looks up the associated file if FD cancelation is requested and marked as
 * fixed. If the file lookup succeeds, it sets up the `cd->file` field and
 * invokes `__io_async_cancel` to perform the actual cancellation logic.
 *
 * Returns 0 on success, or a negative error code if the file is invalid or
 * no matching operation is found.
 */
static int __io_sync_cancel(struct io_uring_task *tctx,
			    struct io_cancel_data *cd, int fd)
{
	struct io_ring_ctx *ctx = cd->ctx;

	/* fixed must be grabbed every time since we drop the uring_lock */
	if ((cd->flags & IORING_ASYNC_CANCEL_FD) &&
	    (cd->flags & IORING_ASYNC_CANCEL_FD_FIXED)) {
		struct io_rsrc_node *node;

		node = io_rsrc_node_lookup(&ctx->file_table.data, fd);
		if (unlikely(!node))
			return -EBADF;
		cd->file = io_slot_file(node);
		if (!cd->file)
			return -EBADF;
	}

	return __io_async_cancel(cd, tctx, 0);
}

/*
 * io_sync_cancel - Handle a synchronous cancel request from userspace
 *
 * @ctx: io_ring_ctx of the calling process
 * @arg: userspace pointer to a struct io_uring_sync_cancel_reg
 *
 * Validates the user-provided cancelation parameters and attempts to cancel
 * a matching request synchronously. If the cancelation is not immediately
 * successful (e.g., the target is still running), waits for completion or
 * until a timeout is reached. Supports both fixed and non-fixed file
 * descriptors and optional timeout.
 *
 * Must be called with `ctx->uring_lock` held.
 *
 * Returns 0 on success (including if no matching request is found),
 * -EBADF if file lookup fails, -EINVAL for invalid input,
 * -EFAULT if copy_from_user fails, or -ETIME if timeout expires.
 */
int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg)
	__must_hold(&ctx->uring_lock)
{
	struct io_cancel_data cd = {
		.ctx	= ctx,
		.seq	= atomic_inc_return(&ctx->cancel_seq),
	};
	ktime_t timeout = KTIME_MAX;
	struct io_uring_sync_cancel_reg sc;
	struct file *file = NULL;
	DEFINE_WAIT(wait);
	int ret, i;

	if (copy_from_user(&sc, arg, sizeof(sc)))
		return -EFAULT;
	if (sc.flags & ~CANCEL_FLAGS)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(sc.pad); i++)
		if (sc.pad[i])
			return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(sc.pad2); i++)
		if (sc.pad2[i])
			return -EINVAL;

	cd.data = sc.addr;
	cd.flags = sc.flags;
	cd.opcode = sc.opcode;

	/* we can grab a normal file descriptor upfront */
	if ((cd.flags & IORING_ASYNC_CANCEL_FD) &&
	   !(cd.flags & IORING_ASYNC_CANCEL_FD_FIXED)) {
		file = fget(sc.fd);
		if (!file)
			return -EBADF;
		cd.file = file;
	}

	ret = __io_sync_cancel(current->io_uring, &cd, sc.fd);

	/* found something, done! */
	if (ret != -EALREADY)
		goto out;

	if (sc.timeout.tv_sec != -1UL || sc.timeout.tv_nsec != -1UL) {
		struct timespec64 ts = {
			.tv_sec		= sc.timeout.tv_sec,
			.tv_nsec	= sc.timeout.tv_nsec
		};

		timeout = ktime_add_ns(timespec64_to_ktime(ts), ktime_get_ns());
	}

	/*
	 * Keep looking until we get -ENOENT. we'll get woken everytime
	 * every time a request completes and will retry the cancelation.
	 */
	do {
		cd.seq = atomic_inc_return(&ctx->cancel_seq);

		prepare_to_wait(&ctx->cq_wait, &wait, TASK_INTERRUPTIBLE);

		ret = __io_sync_cancel(current->io_uring, &cd, sc.fd);

		mutex_unlock(&ctx->uring_lock);
		if (ret != -EALREADY)
			break;

		ret = io_run_task_work_sig(ctx);
		if (ret < 0)
			break;
		ret = schedule_hrtimeout(&timeout, HRTIMER_MODE_ABS);
		if (!ret) {
			ret = -ETIME;
			break;
		}
		mutex_lock(&ctx->uring_lock);
	} while (1);

	finish_wait(&ctx->cq_wait, &wait);
	mutex_lock(&ctx->uring_lock);

	if (ret == -ENOENT || ret > 0)
		ret = 0;
out:
	if (file)
		fput(file);
	return ret;
}
