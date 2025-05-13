// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../kernel/futex/futex.h"
#include "io_uring.h"
#include "alloc_cache.h"
#include "futex.h"

struct io_futex {
	struct file	*file;
	union {
		u32 __user			*uaddr;
		struct futex_waitv __user	*uwaitv;
	};
	unsigned long	futex_val;
	unsigned long	futex_mask;
	unsigned long	futexv_owned;
	u32		futex_flags;
	unsigned int	futex_nr;
	bool		futexv_unqueued;
};

struct io_futex_data {
	struct futex_q	q;
	struct io_kiocb	*req;
};

#define IO_FUTEX_ALLOC_CACHE_MAX	32

/*
 * io_futex_cache_init - Initialize futex-specific memory cache
 * @ctx: Pointer to the io_ring_ctx associated with this ring
 *
 * Initializes a memory cache to store `struct io_futex_data` objects
 * for futex operations.
 *
 * Return:
 * * true if the cache was initialized successfully
 * * false on failure
 */
bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return io_alloc_cache_init(&ctx->futex_cache, IO_FUTEX_ALLOC_CACHE_MAX,
				sizeof(struct io_futex_data), 0);
}

/*
 * io_futex_cache_free - Free futex memory cache
 * @ctx: io_ring_ctx from which to free futex cache
 *
 * Frees all memory in the futex cache, using `kfree()` as the final
 * deallocation function.
 */
void io_futex_cache_free(struct io_ring_ctx *ctx)
{
	io_alloc_cache_free(&ctx->futex_cache, kfree);
}

/*
 * __io_futex_complete - Internal futex request completion
 * @req: io_kiocb to complete
 * @ts: Task work state
 *
 * Finalizes completion for a futex request: clears async data, removes
 * it from the hash list, and invokes `io_req_task_complete()`.
 */
static void __io_futex_complete(struct io_kiocb *req, struct io_tw_state *ts)
{
	req->async_data = NULL;
	hlist_del_init(&req->hash_node);
	io_req_task_complete(req, ts);
}

/*
 * io_futex_complete - Complete a futex wait request
 * @req: io_kiocb to complete
 * @ts: Task work state
 *
 * Releases cached futex memory, if applicable, and finalizes the request
 * using `__io_futex_complete()`.
 */
static void io_futex_complete(struct io_kiocb *req, struct io_tw_state *ts)
{
	struct io_futex_data *ifd = req->async_data;
	struct io_ring_ctx *ctx = req->ctx;

	io_tw_lock(ctx, ts);
	if (!io_alloc_cache_put(&ctx->futex_cache, ifd))
		kfree(ifd);
	__io_futex_complete(req, ts);
}

/*
 * io_futexv_complete - Complete a futexv request (multi-futex wait)
 * @req: io_kiocb to complete
 * @ts: Task work state
 *
 * Unqueues futexes if needed, releases async data, and finalizes
 * the request.
 */
static void io_futexv_complete(struct io_kiocb *req, struct io_tw_state *ts)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv = req->async_data;

	io_tw_lock(req->ctx, ts);

	if (!iof->futexv_unqueued) {
		int res;

		res = futex_unqueue_multiple(futexv, iof->futex_nr);
		if (res != -1)
			io_req_set_res(req, res, 0);
	}

	kfree(req->async_data);
	req->flags &= ~REQ_F_ASYNC_DATA;
	__io_futex_complete(req, ts);
}

/*
 * io_futexv_claim - Claim exclusive access to futexv
 * @iof: io_futex object representing the futexv request
 *
 * Tries to set an atomic bit to ensure only one context operates
 * on the futexv request. Used for cancellation safety.
 *
 * Return:
 * * true if successfully claimed
 * * false otherwise
 */
static bool io_futexv_claim(struct io_futex *iof)
{
	if (test_bit(0, &iof->futexv_owned) ||
	    test_and_set_bit_lock(0, &iof->futexv_owned))
		return false;
	return true;
}

/*
 * __io_futex_cancel - Attempt to cancel a futex or futexv request
 * @ctx: io_uring context
 * @req: Request to cancel
 *
 * Cancels a request by unqueuing it (for futex) or claiming it (for futexv),
 * setting result to -ECANCELED, and scheduling task work completion.
 *
 * Return:
 * * true if successfully cancelled
 * * false if it was already completed or unqueue failed
 */
static bool __io_futex_cancel(struct io_ring_ctx *ctx, struct io_kiocb *req)
{
	/* futex wake already done or in progress */
	if (req->opcode == IORING_OP_FUTEX_WAIT) {
		struct io_futex_data *ifd = req->async_data;

		if (!futex_unqueue(&ifd->q))
			return false;
		req->io_task_work.func = io_futex_complete;
	} else {
		struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);

		if (!io_futexv_claim(iof))
			return false;
		req->io_task_work.func = io_futexv_complete;
	}

	hlist_del_init(&req->hash_node);
	io_req_set_res(req, -ECANCELED, 0);
	io_req_task_work_add(req);
	return true;
}
/*
 * io_futex_cancel - Cancel futex-related requests
 * @ctx: io_uring context
 * @cd: Cancel data indicating what to match
 * @issue_flags: Submission flags
 *
 * Searches the futex list for matching requests and attempts to cancel them.
 *
 * Return:
 * * Number of cancelled requests
 * * -ENOENT if no matching requests were found
 */
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags)
{
	struct hlist_node *tmp;
	struct io_kiocb *req;
	int nr = 0;

	if (cd->flags & (IORING_ASYNC_CANCEL_FD|IORING_ASYNC_CANCEL_FD_FIXED))
		return -ENOENT;

	io_ring_submit_lock(ctx, issue_flags);
	hlist_for_each_entry_safe(req, tmp, &ctx->futex_list, hash_node) {
		if (req->cqe.user_data != cd->data &&
		    !(cd->flags & IORING_ASYNC_CANCEL_ANY))
			continue;
		if (__io_futex_cancel(ctx, req))
			nr++;
		if (!(cd->flags & IORING_ASYNC_CANCEL_ALL))
			break;
	}
	io_ring_submit_unlock(ctx, issue_flags);

	if (nr)
		return nr;

	return -ENOENT;
}

/*
 * io_futex_remove_all - Cancel all futex operations for a task
 * @ctx: io_uring context
 * @tctx: io_uring task context
 * @cancel_all: If true, cancel all; otherwise only matching ones
 *
 * Iterates through the futex list and cancels any requests owned by
 * the task context.
 *
 * Return:
 * * true if any requests were removed
 * * false if none matched
 */
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all)
{
	struct hlist_node *tmp;
	struct io_kiocb *req;
	bool found = false;

	lockdep_assert_held(&ctx->uring_lock);

	hlist_for_each_entry_safe(req, tmp, &ctx->futex_list, hash_node) {
		if (!io_match_task_safe(req, tctx, cancel_all))
			continue;
		hlist_del_init(&req->hash_node);
		__io_futex_cancel(ctx, req);
		found = true;
	}

	return found;
}

/*
 * io_futex_prep - Prepare a futex-based operation in io_uring
 * @req: io_kiocb request structure
 * @sqe: submission queue entry structure
 *
 * Prepares a futex operation for io_uring by validating the input fields
 * from the submission queue entry (SQE). It extracts the futex address,
 * value, mask, and flags, ensuring they conform to expected requirements.
 * Returns 0 on success or -EINVAL on invalid input.
 */
int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	u32 flags;

	if (unlikely(sqe->len || sqe->futex_flags || sqe->buf_index ||
		     sqe->file_index))
		return -EINVAL;

	iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	iof->futex_val = READ_ONCE(sqe->addr2);
	iof->futex_mask = READ_ONCE(sqe->addr3);
	flags = READ_ONCE(sqe->fd);

	if (flags & ~FUTEX2_VALID_MASK)
		return -EINVAL;

	iof->futex_flags = futex2_to_flags(flags);
	if (!futex_flags_valid(iof->futex_flags))
		return -EINVAL;

	if (!futex_validate_input(iof->futex_flags, iof->futex_val) ||
	    !futex_validate_input(iof->futex_flags, iof->futex_mask))
		return -EINVAL;

	return 0;
}

/*
 * io_futex_wakev_fn - Wakeup handler for vectorized futex operations
 * @wake_q: wake queue head structure
 * @q: futex queue structure
 *
 * Handles the wakeup for vectorized futex operations. Checks if the
 * futex can be claimed and attempts to mark it as woken. Sets the result
 * of the I/O request to success if the wake operation succeeds.
 */
static void io_futex_wakev_fn(struct wake_q_head *wake_q, struct futex_q *q)
{
	struct io_kiocb *req = q->wake_data;
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);

	if (!io_futexv_claim(iof))
		return;
	if (unlikely(!__futex_wake_mark(q)))
		return;

	io_req_set_res(req, 0, 0);
	req->io_task_work.func = io_futexv_complete;
	io_req_task_work_add(req);
}

/*
 * io_futexv_prep - Prepare a vectorized futex operation
 * @req: io_kiocb request structure
 * @sqe: submission queue entry structure
 *
 * Prepares a vectorized futex operation for io_uring. Validates that no
 * unsupported fields are set in the SQE and allocates memory for futex
 * vector entries. Parses the futex wait vector and sets up async data
 * for the request. Returns 0 on success or a negative error code on failure.
 */
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv;
	int ret;

	/* No flags or mask supported for waitv */
	if (unlikely(sqe->fd || sqe->buf_index || sqe->file_index ||
		     sqe->addr2 || sqe->futex_flags || sqe->addr3))
		return -EINVAL;

	iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	iof->futex_nr = READ_ONCE(sqe->len);
	if (!iof->futex_nr || iof->futex_nr > FUTEX_WAITV_MAX)
		return -EINVAL;

	futexv = kcalloc(iof->futex_nr, sizeof(*futexv), GFP_KERNEL);
	if (!futexv)
		return -ENOMEM;

	ret = futex_parse_waitv(futexv, iof->uwaitv, iof->futex_nr,
				io_futex_wakev_fn, req);
	if (ret) {
		kfree(futexv);
		return ret;
	}

	iof->futexv_owned = 0;
	iof->futexv_unqueued = 0;
	req->flags |= REQ_F_ASYNC_DATA;
	req->async_data = futexv;
	return 0;
}

/*
 * io_futex_wake_fn - Wakeup handler for single futex operation
 * @wake_q: wake queue head structure
 * @q: futex queue structure
 *
 * Handles the wakeup for a single futex operation. Marks the futex queue
 * as woken, sets the I/O request result to success, and schedules completion.
 */
static void io_futex_wake_fn(struct wake_q_head *wake_q, struct futex_q *q)
{
	struct io_futex_data *ifd = container_of(q, struct io_futex_data, q);
	struct io_kiocb *req = ifd->req;

	if (unlikely(!__futex_wake_mark(q)))
		return;

	io_req_set_res(req, 0, 0);
	req->io_task_work.func = io_futex_complete;
	io_req_task_work_add(req);
}

/*
 * io_futexv_wait - Handle asynchronous futex wait operations in io_uring
 * @req: io_kiocb request structure
 * @issue_flags: issue flags used during submission
 *
 * Prepares and initiates an asynchronous futex wait operation. This function
 * locks the submission context, sets up multiple futex waiters, and handles
 * wakeups that may occur during setup. If the setup is successful, the request
 * is added to the futex wait list. Returns IOU_OK on failure or 
 * IOU_ISSUE_SKIP_COMPLETE on success.
 */
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv = req->async_data;
	struct io_ring_ctx *ctx = req->ctx;
	int ret, woken = -1;

	io_ring_submit_lock(ctx, issue_flags);

	ret = futex_wait_multiple_setup(futexv, iof->futex_nr, &woken);

	/*
	 * Error case, ret is < 0. Mark the request as failed.
	 */
	if (unlikely(ret < 0)) {
		io_ring_submit_unlock(ctx, issue_flags);
		req_set_fail(req);
		io_req_set_res(req, ret, 0);
		kfree(futexv);
		req->async_data = NULL;
		req->flags &= ~REQ_F_ASYNC_DATA;
		return IOU_OK;
	}

	/*
	 * 0 return means that we successfully setup the waiters, and that
	 * nobody triggered a wakeup while we were doing so. If the wakeup
	 * happened post setup, the task_work will be run post this issue and
	 * under the submission lock. 1 means We got woken while setting up,
	 * let that side do the completion. Note that
	 * futex_wait_multiple_setup() will have unqueued all the futexes in
	 * this case. Mark us as having done that already, since this is
	 * different from normal wakeup.
	 */
	if (!ret) {
		/*
		 * If futex_wait_multiple_setup() returns 0 for a
		 * successful setup, then the task state will not be
		 * runnable. This is fine for the sync syscall, as
		 * it'll be blocking unless we already got one of the
		 * futexes woken, but it obviously won't work for an
		 * async invocation. Mark us runnable again.
		 */
		__set_current_state(TASK_RUNNING);
		hlist_add_head(&req->hash_node, &ctx->futex_list);
	} else {
		iof->futexv_unqueued = 1;
		if (woken != -1)
			io_req_set_res(req, woken, 0);
	}

	io_ring_submit_unlock(ctx, issue_flags);
	return IOU_ISSUE_SKIP_COMPLETE;
}

/*
 * io_futex_wait - Handle synchronous futex wait operations in io_uring
 * @req: io_kiocb request structure
 * @issue_flags: issue flags used during submission
 *
 * Prepares a synchronous futex wait operation by allocating a futex queue
 * structure and setting up the futex wait. If successful, the futex is 
 * enqueued, and the request is marked for async completion. Returns 
 * IOU_OK on failure or IOU_ISSUE_SKIP_COMPLETE on success.
 */
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_futex_data *ifd = NULL;
	struct futex_hash_bucket *hb;
	int ret;

	if (!iof->futex_mask) {
		ret = -EINVAL;
		goto done;
	}

	io_ring_submit_lock(ctx, issue_flags);
	ifd = io_cache_alloc(&ctx->futex_cache, GFP_NOWAIT);
	if (!ifd) {
		ret = -ENOMEM;
		goto done_unlock;
	}

	req->async_data = ifd;
	ifd->q = futex_q_init;
	ifd->q.bitset = iof->futex_mask;
	ifd->q.wake = io_futex_wake_fn;
	ifd->req = req;

	ret = futex_wait_setup(iof->uaddr, iof->futex_val, iof->futex_flags,
			       &ifd->q, &hb);
	if (!ret) {
		hlist_add_head(&req->hash_node, &ctx->futex_list);
		io_ring_submit_unlock(ctx, issue_flags);

		futex_queue(&ifd->q, hb, NULL);
		return IOU_ISSUE_SKIP_COMPLETE;
	}

done_unlock:
	io_ring_submit_unlock(ctx, issue_flags);
done:
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	kfree(ifd);
	return IOU_OK;
}

/*
 * io_futex_wake - Trigger a wakeup on a futex in io_uring
 * @req: io_kiocb request structure
 * @issue_flags: issue flags used during submission
 *
 * Wakes up any threads waiting on the specified futex address. The function
 * ensures that waking zero futexes will return zero as per strict flag rules.
 * Returns IOU_OK on success or failure, with the result indicating the number
 * of woken threads.
 */
int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	int ret;

	/*
	 * Strict flags - ensure that waking 0 futexes yields a 0 result.
	 * See commit 43adf8449510 ("futex: FLAGS_STRICT") for details.
	 */
	ret = futex_wake(iof->uaddr, FLAGS_STRICT | iof->futex_flags,
			 iof->futex_val, iof->futex_mask);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
