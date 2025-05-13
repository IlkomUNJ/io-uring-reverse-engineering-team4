// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "fs.h"

struct io_rename {
	struct file			*file;
	int				old_dfd;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
	int				flags;
};

struct io_unlink {
	struct file			*file;
	int				dfd;
	int				flags;
	struct filename			*filename;
};

struct io_mkdir {
	struct file			*file;
	int				dfd;
	umode_t				mode;
	struct filename			*filename;
};

struct io_link {
	struct file			*file;
	int				old_dfd;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
	int				flags;
};

/*
 * io_renameat_prep - Prepare a renameat2 operation
 * @req: The io_kiocb associated with the request
 * @sqe: Submission queue entry containing rename parameters
 *
 * Validates the sqe fields, extracts file descriptors, flags, and file names,
 * and prepares the rename operation. Allocates memory for old and new paths,
 * and sets request flags for async execution and cleanup.
 *
 * Return:
 * * 0 on success
 * * -EINVAL for invalid SQE fields
 * * -EBADF if fixed files are used
 * * PTR_ERR on failure to get path names
 */
int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_rename *ren = io_kiocb_to_cmd(req, struct io_rename);
	const char __user *oldf, *newf;

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ren->old_dfd = READ_ONCE(sqe->fd);
	oldf = u64_to_user_ptr(READ_ONCE(sqe->addr));
	newf = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ren->new_dfd = READ_ONCE(sqe->len);
	ren->flags = READ_ONCE(sqe->rename_flags);

	ren->oldpath = getname(oldf);
	if (IS_ERR(ren->oldpath))
		return PTR_ERR(ren->oldpath);

	ren->newpath = getname(newf);
	if (IS_ERR(ren->newpath)) {
		putname(ren->oldpath);
		return PTR_ERR(ren->newpath);
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_renameat - Perform a renameat2 syscall
 * @req:          The io_kiocb request
 * @issue_flags:  Flags indicating how the request is issued
 *
 * Executes the renameat2 syscall with parameters prepared by io_renameat_prep().
 * Assumes the operation must run synchronously. Clears cleanup flags after execution.
 *
 * Return:
 * * IOU_OK after storing the syscall result into the request
 */
int io_renameat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rename *ren = io_kiocb_to_cmd(req, struct io_rename);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_renameat2(ren->old_dfd, ren->oldpath, ren->new_dfd,
				ren->newpath, ren->flags);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_renameat_cleanup - Cleanup allocated pathnames for renameat
 * @req: The io_kiocb request to clean up
 *
 * Frees the old and new pathnames allocated during preparation of the rename request.
 */
void io_renameat_cleanup(struct io_kiocb *req)
{
	struct io_rename *ren = io_kiocb_to_cmd(req, struct io_rename);

	putname(ren->oldpath);
	putname(ren->newpath);
}

/*
 * io_unlinkat_prep - Prepare an unlinkat or rmdir operation
 * @req: The io_kiocb request
 * @sqe: Submission queue entry with unlink parameters
 *
 * Parses the unlink SQE, validates flags, and retrieves the target path.
 * Only AT_REMOVEDIR is supported as a valid flag. Allocates memory for the path.
 *
 * Return:
 * * 0 on success
 * * -EINVAL for invalid flags or SQE fields
 * * -EBADF if fixed file is used
 * * PTR_ERR on failure to get path name
 */
int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_unlink *un = io_kiocb_to_cmd(req, struct io_unlink);
	const char __user *fname;

	if (sqe->off || sqe->len || sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	un->dfd = READ_ONCE(sqe->fd);

	un->flags = READ_ONCE(sqe->unlink_flags);
	if (un->flags & ~AT_REMOVEDIR)
		return -EINVAL;

	fname = u64_to_user_ptr(READ_ONCE(sqe->addr));
	un->filename = getname(fname);
	if (IS_ERR(un->filename))
		return PTR_ERR(un->filename);

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_unlinkat - Execute unlinkat or rmdir syscall
 * @req:          The io_kiocb request
 * @issue_flags:  Flags indicating how the request is issued
 *
 * Executes either unlinkat() or rmdir() depending on the flags set during
 * request preparation. Stores the result in the request and clears cleanup flags.
 *
 * Return:
 * * IOU_OK after storing the syscall result
 */
int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_unlink *un = io_kiocb_to_cmd(req, struct io_unlink);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	if (un->flags & AT_REMOVEDIR)
		ret = do_rmdir(un->dfd, un->filename);
	else
		ret = do_unlinkat(un->dfd, un->filename);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_unlinkat_cleanup - Cleanup unlinkat request resources
 * @req: The io_kiocb request to clean up
 *
 * Releases the filename allocated during unlinkat request preparation.
 */
void io_unlinkat_cleanup(struct io_kiocb *req)
{
	struct io_unlink *ul = io_kiocb_to_cmd(req, struct io_unlink);

	putname(ul->filename);
}

/*
 * io_mkdirat_prep - Prepare a mkdirat operation
 * @req: The io_kiocb request
 * @sqe: Submission queue entry containing mkdir parameters
 *
 * Validates the SQE fields, extracts the directory file descriptor and mode,
 * and retrieves the filename. Sets flags for async execution and resource cleanup.
 *
 * Return:
 * * 0 on success
 * * -EINVAL for invalid SQE fields
 * * -EBADF if fixed files are used
 * * PTR_ERR on failure to retrieve the filename
 */
int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_mkdir *mkd = io_kiocb_to_cmd(req, struct io_mkdir);
	const char __user *fname;

	if (sqe->off || sqe->rw_flags || sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	mkd->dfd = READ_ONCE(sqe->fd);
	mkd->mode = READ_ONCE(sqe->len);

	fname = u64_to_user_ptr(READ_ONCE(sqe->addr));
	mkd->filename = getname(fname);
	if (IS_ERR(mkd->filename))
		return PTR_ERR(mkd->filename);

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_mkdirat - Execute mkdirat syscall
 * @req:          The io_kiocb request
 * @issue_flags:  Flags indicating how the request is issued
 *
 * Performs a mkdirat syscall using parameters prepared by io_mkdirat_prep().
 * Stores the syscall result in the request and clears the cleanup flag.
 *
 * Return:
 * * IOU_OK after completing the mkdirat syscall
 */
int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_mkdir *mkd = io_kiocb_to_cmd(req, struct io_mkdir);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_mkdirat(mkd->dfd, mkd->filename, mkd->mode);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_mkdirat_cleanup - Cleanup mkdirat request resources
 * @req: The io_kiocb request to clean up
 *
 * Releases the filename allocated during mkdirat preparation.
 */
void io_mkdirat_cleanup(struct io_kiocb *req)
{
	struct io_mkdir *md = io_kiocb_to_cmd(req, struct io_mkdir);

	putname(md->filename);
}

/*
 * io_symlinkat_prep - Prepare a symlinkat operation
 * @req: The io_kiocb request
 * @sqe: Submission queue entry containing symlink parameters
 *
 * Parses the SQE, validates fields, and retrieves both the target path
 * (oldpath) and the link path (newpath). Sets flags for async execution
 * and resource cleanup.
 *
 * Return:
 * * 0 on success
 * * -EINVAL for invalid SQE fields
 * * -EBADF if fixed file is used
 * * PTR_ERR on failure to retrieve paths
 */
int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_link *sl = io_kiocb_to_cmd(req, struct io_link);
	const char __user *oldpath, *newpath;

	if (sqe->len || sqe->rw_flags || sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	sl->new_dfd = READ_ONCE(sqe->fd);
	oldpath = u64_to_user_ptr(READ_ONCE(sqe->addr));
	newpath = u64_to_user_ptr(READ_ONCE(sqe->addr2));

	sl->oldpath = getname(oldpath);
	if (IS_ERR(sl->oldpath))
		return PTR_ERR(sl->oldpath);

	sl->newpath = getname(newpath);
	if (IS_ERR(sl->newpath)) {
		putname(sl->oldpath);
		return PTR_ERR(sl->newpath);
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_symlinkat - Execute symlinkat syscall
 * @req:          The io_kiocb request
 * @issue_flags:  Flags indicating how the request is issued
 *
 * Performs a symlinkat syscall using the parameters set in the preparation
 * phase. Stores the result and clears any cleanup flags.
 *
 * Return:
 * * IOU_OK after executing the syscall
 */
int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_link *sl = io_kiocb_to_cmd(req, struct io_link);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_symlinkat(sl->oldpath, sl->new_dfd, sl->newpath);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_linkat_prep - Prepare a linkat (hard link) operation
 * @req: The io_kiocb request
 * @sqe: Submission queue entry with hard link parameters
 *
 * Extracts old and new pathnames and corresponding file descriptors.
 * Supports flag parsing (e.g., AT_SYMLINK_FOLLOW) via hardlink_flags.
 * Allocates the required paths and sets flags for cleanup and async.
 *
 * Return:
 * * 0 on success
 * * -EINVAL for invalid SQE fields
 * * -EBADF if fixed file is used
 * * PTR_ERR on failure to retrieve path names
 */
int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_link *lnk = io_kiocb_to_cmd(req, struct io_link);
	const char __user *oldf, *newf;

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	lnk->old_dfd = READ_ONCE(sqe->fd);
	lnk->new_dfd = READ_ONCE(sqe->len);
	oldf = u64_to_user_ptr(READ_ONCE(sqe->addr));
	newf = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	lnk->flags = READ_ONCE(sqe->hardlink_flags);

	lnk->oldpath = getname_uflags(oldf, lnk->flags);
	if (IS_ERR(lnk->oldpath))
		return PTR_ERR(lnk->oldpath);

	lnk->newpath = getname(newf);
	if (IS_ERR(lnk->newpath)) {
		putname(lnk->oldpath);
		return PTR_ERR(lnk->newpath);
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_linkat - Execute linkat syscall
 * @req:          The io_kiocb request
 * @issue_flags:  Flags indicating how the request is issued
 *
 * Performs the hard link creation via linkat syscall with arguments
 * prepared earlier. Clears the cleanup flag after completion.
 *
 * Return:
 * * IOU_OK after storing the syscall result
 */
int io_linkat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_link *lnk = io_kiocb_to_cmd(req, struct io_link);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_linkat(lnk->old_dfd, lnk->oldpath, lnk->new_dfd,
				lnk->newpath, lnk->flags);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_link_cleanup - Cleanup resources used by linkat/symlinkat requests
 * @req: The io_kiocb request to clean up
 *
 * Frees the memory allocated for old and new pathnames.
 */
void io_link_cleanup(struct io_kiocb *req)
{
	struct io_link *sl = io_kiocb_to_cmd(req, struct io_link);

	putname(sl->oldpath);
	putname(sl->newpath);
}
