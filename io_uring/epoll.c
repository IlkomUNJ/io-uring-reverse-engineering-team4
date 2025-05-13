// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/io_uring.h>
#include <linux/eventpoll.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "epoll.h"

#if defined(CONFIG_EPOLL)
struct io_epoll {
	struct file			*file;
	int				epfd;
	int				op;
	int				fd;
	struct epoll_event		event;
};

/*
 * io_epoll_ctl_prep - Prepare an epoll_ctl operation for submission
 *
 * @req: io_kiocb representing the request
 * @sqe: submission queue entry from userspace
 *
 * Extracts and validates epoll_ctl parameters from the submission queue entry.
 * Specifically:
 *   - Validates that `buf_index` and `splice_fd_in` are not used (must be 0).
 *   - Reads `epfd`, `op`, and `fd` fields for epoll_ctl from SQE.
 *   - If the operation involves an epoll_event (e.g., EPOLL_CTL_ADD/MOD),
 *     attempts to copy the event structure from userspace to kernel space.
 *
 * Returns 0 on success, -EINVAL on invalid flags, or -EFAULT if copying the
 * event from userspace fails.
 */
int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_epoll *epoll = io_kiocb_to_cmd(req, struct io_epoll);

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	epoll->epfd = READ_ONCE(sqe->fd);
	epoll->op = READ_ONCE(sqe->len);
	epoll->fd = READ_ONCE(sqe->off);

	if (ep_op_has_event(epoll->op)) {
		struct epoll_event __user *ev;

		ev = u64_to_user_ptr(READ_ONCE(sqe->addr));
		if (copy_from_user(&epoll->event, ev, sizeof(*ev)))
			return -EFAULT;
	}

	return 0;
}

/*
 * io_epoll_ctl() - Handles the epoll_ctl() operation for io_uring.
 * @ctx:      the current io_uring context
 * @req:      the request structure representing this operation
 * 
 * This function executes an epoll_ctl command in the context of io_uring,
 * allowing epoll operations to be asynchronously submitted.
 */

int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_epoll *ie = io_kiocb_to_cmd(req, struct io_epoll);
	int ret;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	ret = do_epoll_ctl(ie->epfd, ie->op, ie->fd, &ie->event, force_nonblock);
	if (force_nonblock && ret == -EAGAIN)
		return -EAGAIN;

	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
#endif
