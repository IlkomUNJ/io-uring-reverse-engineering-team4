// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "statx.h"

struct io_statx {
	struct file			*file;
	int				dfd;
	unsigned int			mask;
	unsigned int			flags;
	struct filename			*filename;
	struct statx __user		*buffer;
};

/*
 * io_statx_prep - prepare a statx request
 * @req: io_kiocb for the request
 * @sqe: submission queue entry
 *
 * Validates and prepares a statx request by parsing arguments from
 * the SQE. The statx path, flags, and mask are extracted and stored.
 * The filename is resolved via getname_uflags() and stored in the
 * request. Marks the request for cleanup and forces async execution.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
	const char __user *path;

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (req->flags & REQ_F_FIXED_FILE)
		return -EBADF;

	sx->dfd = READ_ONCE(sqe->fd);
	sx->mask = READ_ONCE(sqe->len);
	path = u64_to_user_ptr(READ_ONCE(sqe->addr));
	sx->buffer = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	sx->flags = READ_ONCE(sqe->statx_flags);

	sx->filename = getname_uflags(path, sx->flags);

	if (IS_ERR(sx->filename)) {
		int ret = PTR_ERR(sx->filename);

		sx->filename = NULL;
		return ret;
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_statx - issue a statx system call
 * @req: io_kiocb for the request
 * @issue_flags: flags for issuing request
 *
 * Executes the statx system call using previously prepared parameters.
 * The result of the syscall is stored in the CQE. This function is
 * expected to be called asynchronously (REQ_F_FORCE_ASYNC set).
 *
 * Returns IOU_OK unconditionally, as completion is always handled.
 */
int io_statx(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_statx(sx->dfd, sx->filename, sx->flags, sx->mask, sx->buffer);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_statx_cleanup - clean up resources after statx
 * @req: io_kiocb for the request
 *
 * Releases resources allocated during statx preparation, such as
 * the filename resolved from userspace.
 */
void io_statx_cleanup(struct io_kiocb *req)
{
	struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);

	if (sx->filename)
		putname(sx->filename);
}
