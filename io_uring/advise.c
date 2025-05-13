// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>

#include <uapi/linux/fadvise.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "advise.h"

struct io_fadvise {
	struct file			*file;
	u64				offset;
	u64				len;
	u32				advice;
};

struct io_madvise {
	struct file			*file;
	u64				addr;
	u64				len;
	u32				advice;
};

/*
 * io_madvise_prep - Prepare a MADVISE operation request
 *
 * @req: io_kiocb representing the request
 * @sqe: submission queue entry containing parameters
 *
 * Parses and validates the parameters for a MADVISE operation from the SQE,
 * and populates the internal io_madvise command structure.
 *
 * Returns 0 on success, -EINVAL on invalid parameters, or -EOPNOTSUPP if
 * the system does not support MADVISE.
 */
int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
#if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)
	struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);

	if (sqe->buf_index || s		return -EINVAL;
qe->splice_fd_in)

	ma->addr = READ_ONCE(sqe->addr);
	ma->len = READ_ONCE(sqe->off);
	if (!ma->len)
		ma->len = READ_ONCE(sqe->len);
	ma->advice = READ_ONCE(sqe->fadvise_advice);
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

/*
 * io_madvise - Execute a MADVISE operation
 *
 * @req: io_kiocb representing the request
 * @issue_flags: flags indicating how the request should be issued
 *
 * Performs the MADVISE system call on the specified memory range
 * using parameters prepared earlier. Stores the result in the request.
 *
 * Returns IOU_OK on completion, or -EOPNOTSUPP if MADVISE is not supported.
 */
int io_madvise(struct io_kiocb *req, unsigned int issue_flags)
{
#if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)
	struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_madvise(current->mm, ma->addr, ma->len, ma->advice);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
#else
	return -EOPNOTSUPP;
#endif
}

/*
 * io_fadvise_force_async - Determine if the FADVISE request requires async execution
 *
 * @fa: Pointer to the io_fadvise command structure
 *
 * Returns true if the FADVISE advice type requires the operation to be forced
 * asynchronously; false otherwise.
 */
static bool io_fadvise_force_async(struct io_fadvise *fa)
{
	switch (fa->advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_SEQUENTIAL:
		return false;
	default:
		return true;
	}
}

/*
 * io_fadvise_prep - Prepare a FADVISE operation request
 *
 * @req: io_kiocb representing the request
 * @sqe: submission queue entry containing parameters
 *
 * Parses and validates the parameters for a FADVISE operation from the SQE,
 * and populates the internal io_fadvise command structure. If the advice type
 * requires async execution, sets the appropriate request flag.
 *
 * Returns 0 on success, or -EINVAL if the parameters are invalid.
 */
int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_fadvise *fa = io_kiocb_to_cmd(req, struct io_fadvise);

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	fa->offset = READ_ONCE(sqe->off);
	fa->len = READ_ONCE(sqe->addr);
	if (!fa->len)
		fa->len = READ_ONCE(sqe->len);
	fa->advice = READ_ONCE(sqe->fadvise_advice);
	if (io_fadvise_force_async(fa))
		req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_fadvise - Execute a FADVISE operation
 *
 * @req: io_kiocb representing the request
 * @issue_flags: flags indicating how the request should be issued
 *
 * Performs the FADVISE system call using the prepared parameters.
 * If an error occurs, marks the request as failed and sets the result.
 *
 * Returns IOU_OK after completion.
 */
int io_fadvise(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_fadvise *fa = io_kiocb_to_cmd(req, struct io_fadvise);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK && io_fadvise_force_async(fa));

	ret = vfs_fadvise(req->file, fa->offset, fa->len, fa->advice);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
