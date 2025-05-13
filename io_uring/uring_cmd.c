// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring/cmd.h>
#include <linux/io_uring/net.h>
#include <linux/security.h>
#include <linux/nospec.h>
#include <net/sock.h>

#include <uapi/linux/io_uring.h>
#include <asm/ioctls.h>

#include "io_uring.h"
#include "alloc_cache.h"
#include "rsrc.h"
#include "uring_cmd.h"

/*
 * io_cmd_cache_free - free an io_async_cmd cache entry
 * @entry: pointer to cache entry to free
 *
 * Frees the dynamically allocated io_async_cmd object and its associated
 * io_vec data.
 */
void io_cmd_cache_free(const void *entry)
{
	struct io_async_cmd *ac = (struct io_async_cmd *)entry;

	io_vec_free(&ac->vec);
	kfree(ac);
}

/*
 * io_req_uring_cleanup - cleanup resources associated with an io_uring_cmd
 * @req: io_kiocb request to clean up
 * @issue_flags: submission flags
 *
 * Cleans up async command data, optionally returns it to the per-context
 * cmd_cache. Handles both direct and deferred completion cases.
 */
static void io_req_uring_cleanup(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	struct io_async_cmd *ac = req->async_data;
	struct io_uring_cmd_data *cache = &ac->data;

	if (cache->op_data) {
		kfree(cache->op_data);
		cache->op_data = NULL;
	}

	if (issue_flags & IO_URING_F_UNLOCKED)
		return;

	io_alloc_cache_vec_kasan(&ac->vec);
	if (ac->vec.nr > IO_VEC_CACHE_SOFT_CAP)
		io_vec_free(&ac->vec);

	if (io_alloc_cache_put(&req->ctx->cmd_cache, cache)) {
		ioucmd->sqe = NULL;
		req->async_data = NULL;
		req->flags &= ~(REQ_F_ASYNC_DATA|REQ_F_NEED_CLEANUP);
	}
}

/*
 * io_uring_cmd_cleanup - public entrypoint to cleanup io_uring_cmd resources
 * @req: io_kiocb request to clean up
 *
 * Wrapper around io_req_uring_cleanup with default issue_flags of 0.
 */
void io_uring_cmd_cleanup(struct io_kiocb *req)
{
	io_req_uring_cleanup(req, 0);
}

/*
 * io_uring_try_cancel_uring_cmd - attempt to cancel cancelable uring_cmd requests
 * @ctx: io_uring context
 * @tctx: task context to match if !cancel_all
 * @cancel_all: if true, cancel all requests regardless of tctx
 *
 * Iterates over cancelable uring_cmd requests and attempts to cancel
 * each by calling ->uring_cmd with IO_URING_F_CANCEL | IO_URING_F_COMPLETE_DEFER.
 *
 * Return: true if any command was canceled, false otherwise.
 */
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
				   struct io_uring_task *tctx, bool cancel_all)
{
	struct hlist_node *tmp;
	struct io_kiocb *req;
	bool ret = false;

	lockdep_assert_held(&ctx->uring_lock);

	hlist_for_each_entry_safe(req, tmp, &ctx->cancelable_uring_cmd,
			hash_node) {
		struct io_uring_cmd *cmd = io_kiocb_to_cmd(req,
				struct io_uring_cmd);
		struct file *file = req->file;

		if (!cancel_all && req->tctx != tctx)
			continue;

		if (cmd->flags & IORING_URING_CMD_CANCELABLE) {
			file->f_op->uring_cmd(cmd, IO_URING_F_CANCEL |
						   IO_URING_F_COMPLETE_DEFER);
			ret = true;
		}
	}
	io_submit_flush_completions(ctx);
	return ret;
}

/*
 * io_uring_cmd_del_cancelable - remove a cancelable command from the cancel list
 * @cmd: io_uring_cmd to remove
 * @issue_flags: submission flags
 *
 * Clears the cancelable flag and removes the request from the hash list of
 * cancelable uring_cmds, using appropriate submission locking.
 */
static void io_uring_cmd_del_cancelable(struct io_uring_cmd *cmd,
		unsigned int issue_flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(cmd);
	struct io_ring_ctx *ctx = req->ctx;

	if (!(cmd->flags & IORING_URING_CMD_CANCELABLE))
		return;

	cmd->flags &= ~IORING_URING_CMD_CANCELABLE;
	io_ring_submit_lock(ctx, issue_flags);
	hlist_del(&req->hash_node);
	io_ring_submit_unlock(ctx, issue_flags);
}

/*
 * Mark this command as concelable, then io_uring_try_cancel_uring_cmd()
 * will try to cancel this issued command by sending ->uring_cmd() with
 * issue_flags of IO_URING_F_CANCEL.
 *
 * The command is guaranteed to not be done when calling ->uring_cmd()
 * with IO_URING_F_CANCEL, but it is driver's responsibility to deal
 * with race between io_uring canceling and normal completion.
 */
 /*
 * io_uring_cmd_mark_cancelable - mark an uring_cmd as cancelable
 * @cmd: io_uring_cmd to mark
 * @issue_flags: submission flags
 *
 * Marks a command as cancelable and adds it to the per-context list of
 * cancelable commands. The cancel logic will later attempt to cancel this
 * command by calling ->uring_cmd with cancel flags.
 */
void io_uring_cmd_mark_cancelable(struct io_uring_cmd *cmd,
		unsigned int issue_flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(cmd);
	struct io_ring_ctx *ctx = req->ctx;

	if (!(cmd->flags & IORING_URING_CMD_CANCELABLE)) {
		cmd->flags |= IORING_URING_CMD_CANCELABLE;
		io_ring_submit_lock(ctx, issue_flags);
		hlist_add_head(&req->hash_node, &ctx->cancelable_uring_cmd);
		io_ring_submit_unlock(ctx, issue_flags);
	}
}
EXPORT_SYMBOL_GPL(io_uring_cmd_mark_cancelable);

/*
 * io_uring_cmd_work - task_work callback for executing uring_cmd completion
 * @req: io_kiocb containing the request
 * @tw: unused task_work token
 *
 * Executes the command's task_work callback with flags based on context
 * (e.g. termination or deferred completion).
 */
static void io_uring_cmd_work(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	unsigned int flags = IO_URING_F_COMPLETE_DEFER;

	if (io_should_terminate_tw())
		flags |= IO_URING_F_TASK_DEAD;

	/* task_work executor checks the deffered list completion */
	ioucmd->task_work_cb(ioucmd, flags);
}

/*
 * __io_uring_cmd_do_in_task - schedule command callback in task context
 * @ioucmd: uring command to execute
 * @task_work_cb: callback function to execute
 * @flags: task_work flags
 *
 * Sets up the given task_work callback and schedules it on the
 * associated task using task_work infrastructure.
 */
void __io_uring_cmd_do_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *, unsigned),
			unsigned flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	ioucmd->task_work_cb = task_work_cb;
	req->io_task_work.func = io_uring_cmd_work;
	__io_req_task_work_add(req, flags);
}
EXPORT_SYMBOL_GPL(__io_uring_cmd_do_in_task);

/*
 * io_req_set_cqe32_extra - fill extra fields of 32-byte CQE
 * @req: request to update
 * @extra1: first extra result field
 * @extra2: second extra result field
 *
 * Sets the extended result fields for 32-byte CQEs when supported
 * by the ring.
 */
static inline void io_req_set_cqe32_extra(struct io_kiocb *req,
					  u64 extra1, u64 extra2)
{
	req->big_cqe.extra1 = extra1;
	req->big_cqe.extra2 = extra2;
}

/*
 * Called by consumers of io_uring_cmd, if they originally returned
 * -EIOCBQUEUED upon receiving the command.
 */
 /*
 * io_uring_cmd_done - complete a uring command
 * @ioucmd: command to complete
 * @ret: result of the operation
 * @res2: optional second result for 32-byte CQEs
 * @issue_flags: submission flags
 *
 * Handles cleanup, cancellation state, and request completion.
 * Supports deferred completion and iopoll synchronization as needed.
 */
void io_uring_cmd_done(struct io_uring_cmd *ioucmd, ssize_t ret, u64 res2,
		       unsigned issue_flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	io_uring_cmd_del_cancelable(ioucmd, issue_flags);

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);
	if (req->ctx->flags & IORING_SETUP_CQE32)
		io_req_set_cqe32_extra(req, res2, 0);
	io_req_uring_cleanup(req, issue_flags);
	if (req->ctx->flags & IORING_SETUP_IOPOLL) {
		/* order with io_iopoll_req_issued() checking ->iopoll_complete */
		smp_store_release(&req->iopoll_completed, 1);
	} else if (issue_flags & IO_URING_F_COMPLETE_DEFER) {
		if (WARN_ON_ONCE(issue_flags & IO_URING_F_UNLOCKED))
			return;
		io_req_complete_defer(req);
	} else {
		req->io_task_work.func = io_req_task_complete;
		io_req_task_work_add(req);
	}
}
EXPORT_SYMBOL_GPL(io_uring_cmd_done);

/*
 * io_uring_cmd_prep_setup - internal helper to setup async data for uring_cmd
 * @req: request to prepare
 * @sqe: submission queue entry
 *
 * Allocates and initializes async command data, including copying
 * the submission SQE for later use. This ensures command handlers can
 * safely refer to stable SQE data during async processing.
 *
 * Return: 0 on success, -ENOMEM on failure.
 */
static int io_uring_cmd_prep_setup(struct io_kiocb *req,
				   const struct io_uring_sqe *sqe)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	struct io_async_cmd *ac;

	/* see io_uring_cmd_get_async_data() */
	BUILD_BUG_ON(offsetof(struct io_async_cmd, data) != 0);

	ac = io_uring_alloc_async_data(&req->ctx->cmd_cache, req);
	if (!ac)
		return -ENOMEM;
	ac->data.op_data = NULL;

	/*
	 * Unconditionally cache the SQE for now - this is only needed for
	 * requests that go async, but prep handlers must ensure that any
	 * sqe data is stable beyond prep. Since uring_cmd is special in
	 * that it doesn't read in per-op data, play it safe and ensure that
	 * any SQE data is stable beyond prep. This can later get relaxed.
	 */
	memcpy(ac->sqes, sqe, uring_sqe_size(req->ctx));
	ioucmd->sqe = ac->sqes;
	return 0;
}

/*
 * io_uring_cmd_prep - prepare an io_uring_cmd request
 * @req: request to prepare
 * @sqe: submission queue entry from userspace
 *
 * Validates and parses uring_cmd SQE parameters, including command flags,
 * cmd_op, and optional fixed buffer index. Also sets up async data storage.
 *
 * Return: 0 on success, -EINVAL on invalid input, -ENOMEM on allocation failure.
 */
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);

	if (sqe->__pad1)
		return -EINVAL;

	ioucmd->flags = READ_ONCE(sqe->uring_cmd_flags);
	if (ioucmd->flags & ~IORING_URING_CMD_MASK)
		return -EINVAL;

	if (ioucmd->flags & IORING_URING_CMD_FIXED)
		req->buf_index = READ_ONCE(sqe->buf_index);

	ioucmd->cmd_op = READ_ONCE(sqe->cmd_op);

	return io_uring_cmd_prep_setup(req, sqe);
}

/*
 * io_uring_cmd - execute a uring_cmd request
 * @req: io_kiocb structure representing the request
 * @issue_flags: execution context flags
 *
 * This is the main entry point for submitting a `uring_cmd` request.
 * It checks for the presence of the `uring_cmd` file operation, verifies
 * security permissions, adjusts issue flags based on context state,
 * and invokes the appropriate command handler.
 *
 * Return:
 * * < 0: Error code on failure
 * * == -EAGAIN or -EIOCBQUEUED: Command will be retried or completed later
 * * == 0: Command successfully completed
 */
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	struct io_ring_ctx *ctx = req->ctx;
	struct file *file = req->file;
	int ret;

	if (!file->f_op->uring_cmd)
		return -EOPNOTSUPP;

	ret = security_uring_cmd(ioucmd);
	if (ret)
		return ret;

	if (ctx->flags & IORING_SETUP_SQE128)
		issue_flags |= IO_URING_F_SQE128;
	if (ctx->flags & IORING_SETUP_CQE32)
		issue_flags |= IO_URING_F_CQE32;
	if (io_is_compat(ctx))
		issue_flags |= IO_URING_F_COMPAT;
	if (ctx->flags & IORING_SETUP_IOPOLL) {
		if (!file->f_op->uring_cmd_iopoll)
			return -EOPNOTSUPP;
		issue_flags |= IO_URING_F_IOPOLL;
		req->iopoll_completed = 0;
	}

	ret = file->f_op->uring_cmd(ioucmd, issue_flags);
	if (ret == -EAGAIN || ret == -EIOCBQUEUED)
		return ret;
	if (ret < 0)
		req_set_fail(req);
	io_req_uring_cleanup(req, issue_flags);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_uring_cmd_import_fixed - import fixed buffer from user for a uring_cmd
 * @ubuf: user buffer address
 * @len: length of buffer
 * @rw: read or write direction
 * @iter: destination iov_iter
 * @ioucmd: uring command to associate buffer with
 * @issue_flags: execution context flags
 *
 * Wrapper around `io_import_reg_buf()` to support buffer import from
 * fixed user memory for use in `uring_cmd` handlers.
 */
int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter,
			      struct io_uring_cmd *ioucmd,
			      unsigned int issue_flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	return io_import_reg_buf(req, iter, ubuf, len, rw, issue_flags);
}
EXPORT_SYMBOL_GPL(io_uring_cmd_import_fixed);

/*
 * io_uring_cmd_import_fixed_vec - import a fixed iovec vector from user space
 * @ioucmd: uring command associated with the request
 * @uvec: pointer to user-space iovec array
 * @uvec_segs: number of segments in the vector
 * @ddir: data direction
 * @iter: iov_iter to fill
 * @issue_flags: execution flags
 *
 * Validates and imports a user iovec array into the kernel's fixed iovec
 * cache, used for vectored IO in uring_cmd.
 *
 * Return:
 * * < 0 on failure
 * * 0 on success
 */
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
				  const struct iovec __user *uvec,
				  size_t uvec_segs,
				  int ddir, struct iov_iter *iter,
				  unsigned issue_flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);
	struct io_async_cmd *ac = req->async_data;
	int ret;

	ret = io_prep_reg_iovec(req, &ac->vec, uvec, uvec_segs);
	if (ret)
		return ret;

	return io_import_reg_vec(ddir, iter, req, &ac->vec, uvec_segs,
				 issue_flags);
}
EXPORT_SYMBOL_GPL(io_uring_cmd_import_fixed_vec);

/*
 * io_uring_cmd_issue_blocking - reissue a blocking uring_cmd to IOWQ
 * @ioucmd: the command to queue
 *
 * Queues the request to the io-wq worker thread pool for deferred execution.
 */
void io_uring_cmd_issue_blocking(struct io_uring_cmd *ioucmd)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	io_req_queue_iowq(req);
}

/*
 * io_uring_cmd_getsockopt - handle SOL_SOCKET getsockopt through uring_cmd
 * @sock: socket structure
 * @cmd: uring command with sqe describing the getsockopt
 * @issue_flags: execution flags
 *
 * Fetch socket option via getsockopt. Currently only supports SOL_SOCKET.
 *
 * Return:
 * * > 0: length of the returned option value
 * * < 0: error code
 */
static inline int io_uring_cmd_getsockopt(struct socket *sock,
					  struct io_uring_cmd *cmd,
					  unsigned int issue_flags)
{
	const struct io_uring_sqe *sqe = cmd->sqe;
	bool compat = !!(issue_flags & IO_URING_F_COMPAT);
	int optlen, optname, level, err;
	void __user *optval;

	level = READ_ONCE(sqe->level);
	if (level != SOL_SOCKET)
		return -EOPNOTSUPP;

	optval = u64_to_user_ptr(READ_ONCE(sqe->optval));
	optname = READ_ONCE(sqe->optname);
	optlen = READ_ONCE(sqe->optlen);

	err = do_sock_getsockopt(sock, compat, level, optname,
				 USER_SOCKPTR(optval),
				 KERNEL_SOCKPTR(&optlen));
	if (err)
		return err;

	/* On success, return optlen */
	return optlen;
}

/*
 * io_uring_cmd_setsockopt - handle SOL_SOCKET setsockopt through uring_cmd
 * @sock: socket structure
 * @cmd: uring command with sqe describing the setsockopt
 * @issue_flags: execution flags
 *
 * Sets a socket option. Only supports SOL_SOCKET level.
 *
 * Return:
 * * 0: on success
 * * < 0: error code
 */
static inline int io_uring_cmd_setsockopt(struct socket *sock,
					  struct io_uring_cmd *cmd,
					  unsigned int issue_flags)
{
	const struct io_uring_sqe *sqe = cmd->sqe;
	bool compat = !!(issue_flags & IO_URING_F_COMPAT);
	int optname, optlen, level;
	void __user *optval;
	sockptr_t optval_s;

	optval = u64_to_user_ptr(READ_ONCE(sqe->optval));
	optname = READ_ONCE(sqe->optname);
	optlen = READ_ONCE(sqe->optlen);
	level = READ_ONCE(sqe->level);
	optval_s = USER_SOCKPTR(optval);

	return do_sock_setsockopt(sock, compat, level, optname, optval_s,
				  optlen);
}

/*
 * io_uring_cmd_sock - generic handler for socket-level uring_cmd operations
 * @cmd: uring command
 * @issue_flags: execution context flags
 *
 * Dispatches socket-specific uring_cmd requests, including ioctls such
 * as SIOCINQ, SIOCOUTQ, and SOL_SOCKET getsockopt/setsockopt.
 *
 * Return:
 * * >= 0: success (e.g., length of optval)
 * * < 0: error code
 */
#if defined(CONFIG_NET)
int io_uring_cmd_sock(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct socket *sock = cmd->file->private_data;
	struct sock *sk = sock->sk;
	struct proto *prot = READ_ONCE(sk->sk_prot);
	int ret, arg = 0;

	if (!prot || !prot->ioctl)
		return -EOPNOTSUPP;

	switch (cmd->cmd_op) {
	case SOCKET_URING_OP_SIOCINQ:
		ret = prot->ioctl(sk, SIOCINQ, &arg);
		if (ret)
			return ret;
		return arg;
	case SOCKET_URING_OP_SIOCOUTQ:
		ret = prot->ioctl(sk, SIOCOUTQ, &arg);
		if (ret)
			return ret;
		return arg;
	case SOCKET_URING_OP_GETSOCKOPT:
		return io_uring_cmd_getsockopt(sock, cmd, issue_flags);
	case SOCKET_URING_OP_SETSOCKOPT:
		return io_uring_cmd_setsockopt(sock, cmd, issue_flags);
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL_GPL(io_uring_cmd_sock);
#endif
