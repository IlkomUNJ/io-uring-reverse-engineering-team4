// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/xattr.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "xattr.h"

struct io_xattr {
	struct file			*file;
	struct kernel_xattr_ctx		ctx;
	struct filename			*filename;
};

/*
 * io_xattr_cleanup - Cleanup resources allocated for xattr operation.
 * @req: I/O request associated with the xattr operation.
 *
 * Frees allocated kernel name and value, and drops filename reference
 * if present.
 */
void io_xattr_cleanup(struct io_kiocb *req)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);

	if (ix->filename)
		putname(ix->filename);

	kfree(ix->ctx.kname);
	kvfree(ix->ctx.kvalue);
}

/*
 * io_xattr_finish - Finalize xattr operation.
 * @req: I/O request.
 * @ret: Result code to set as operation result.
 *
 * Clears cleanup flag, performs cleanup, and sets result.
 */
static void io_xattr_finish(struct io_kiocb *req, int ret)
{
	req->flags &= ~REQ_F_NEED_CLEANUP;

	io_xattr_cleanup(req);
	io_req_set_res(req, ret, 0);
}

/*
 * __io_getxattr_prep - Common prep for xattr operations.
 * @req: I/O request.
 * @sqe: Submission queue entry.
 *
 * Allocates and imports xattr name, sets value pointer and size.
 * Marks request for forced async and cleanup on completion.
 */
static int __io_getxattr_prep(struct io_kiocb *req,
			      const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *name;
	int ret;

	ix->filename = NULL;
	ix->ctx.kvalue = NULL;
	name = u64_to_user_ptr(READ_ONCE(sqe->addr));
	ix->ctx.value = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ix->ctx.size = READ_ONCE(sqe->len);
	ix->ctx.flags = READ_ONCE(sqe->xattr_flags);

	if (ix->ctx.flags)
		return -EINVAL;

	ix->ctx.kname = kmalloc(sizeof(*ix->ctx.kname), GFP_KERNEL);
	if (!ix->ctx.kname)
		return -ENOMEM;

	ret = import_xattr_name(ix->ctx.kname, name);
	if (ret) {
		kfree(ix->ctx.kname);
		return ret;
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_fgetxattr_prep - Prepare fgetxattr request.
 * @req: I/O request.
 * @sqe: Submission queue entry.
 *
 * Delegates to common xattr prep logic.
 */
int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_getxattr_prep(req, sqe);
}

/*
 * io_getxattr_prep - Prepare getxattr request using path.
 * @req: I/O request.
 * @sqe: Submission queue entry.
 *
 * Performs standard xattr prep and resolves filename from userspace.
 * Returns error if file is fixed (not supported).
 */
int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *path;
	int ret;

	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ret = __io_getxattr_prep(req, sqe);
	if (ret)
		return ret;

	path = u64_to_user_ptr(READ_ONCE(sqe->addr3));

	ix->filename = getname(path);
	if (IS_ERR(ix->filename))
		return PTR_ERR(ix->filename);

	return 0;
}

/*
 * io_fgetxattr - Execute fgetxattr operation.
 * @req: I/O request.
 * @issue_flags: Issue-time execution flags.
 *
 * Invokes file-based getxattr. Must not be used with non-blocking flag.
 * Cleans up on completion.
 */
int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = file_getxattr(req->file, &ix->ctx);
	io_xattr_finish(req, ret);
	return IOU_OK;
}

/*
 * io_getxattr - Execute getxattr operation using path.
 * @req: I/O request.
 * @issue_flags: Issue-time execution flags.
 *
 * Performs getxattr using path-based access. Caller must have resolved
 * filename during prep. Cleans up and clears filename on completion.
 */
int io_getxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = filename_getxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);
	ix->filename = NULL;
	io_xattr_finish(req, ret);
	return IOU_OK;
}

/*
 * __io_setxattr_prep - Common prep for setxattr operations.
 * @req: I/O request.
 * @sqe: Submission queue entry.
 *
 * Imports xattr name and value from userspace. Allocates kernel xattr
 * name structure and copies userspace data. Marks request for cleanup
 * and forced async execution.
 */
static int __io_setxattr_prep(struct io_kiocb *req,
			const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *name;
	int ret;

	ix->filename = NULL;
	name = u64_to_user_ptr(READ_ONCE(sqe->addr));
	ix->ctx.cvalue = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ix->ctx.kvalue = NULL;
	ix->ctx.size = READ_ONCE(sqe->len);
	ix->ctx.flags = READ_ONCE(sqe->xattr_flags);

	ix->ctx.kname = kmalloc(sizeof(*ix->ctx.kname), GFP_KERNEL);
	if (!ix->ctx.kname)
		return -ENOMEM;

	ret = setxattr_copy(name, &ix->ctx);
	if (ret) {
		kfree(ix->ctx.kname);
		return ret;
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_setxattr_prep - Prepare setxattr operation using path.
 * @req: I/O request.
 * @sqe: Submission queue entry.
 *
 * Performs standard setxattr preparation and resolves path to filename.
 * Fixed files are not supported for path-based operations.
 */
int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *path;
	int ret;

	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ret = __io_setxattr_prep(req, sqe);
	if (ret)
		return ret;

	path = u64_to_user_ptr(READ_ONCE(sqe->addr3));

	ix->filename = getname(path);
	if (IS_ERR(ix->filename))
		return PTR_ERR(ix->filename);

	return 0;
}

/*
 * io_fsetxattr_prep - Prepare fsetxattr operation.
 * @req: I/O request.
 * @sqe: Submission queue entry.
 *
 * Delegates to common setxattr prep logic. Used for file descriptor variant.
 */
int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_setxattr_prep(req, sqe);
}

/*
 * io_fsetxattr - Execute fsetxattr operation using file descriptor.
 * @req: I/O request.
 * @issue_flags: Flags at execution time.
 *
 * Applies extended attribute to file via descriptor. Requires blocking context.
 * Cleans up and completes request.
 */
int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = file_setxattr(req->file, &ix->ctx);
	io_xattr_finish(req, ret);
	return IOU_OK;
}

/*
 * io_setxattr - Execute setxattr operation using path.
 * @req: I/O request.
 * @issue_flags: Flags at execution time.
 *
 * Sets extended attribute using path-based access. Must have prepared
 * filename earlier. Cleans up and clears filename after use.
 */
int io_setxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = filename_setxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);
	ix->filename = NULL;
	io_xattr_finish(req, ret);
	return IOU_OK;
}
