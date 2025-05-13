// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/splice.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "splice.h"

/**
 * struct io_splice - Data structure for splice and tee operations in io_uring
 * @file_out:     Destination file for splice/tee output
 * @off_out:      Output file offset; -1 if current position should be used
 * @off_in:       Input file offset; -1 if current position should be used
 * @len:          Number of bytes to splice or tee
 * @splice_fd_in: Input file descriptor (used if not SPLICE_F_FD_IN_FIXED)
 * @flags:        Splice operation flags (e.g., SPLICE_F_MOVE, SPLICE_F_MORE)
 * @rsrc_node:    Resource node for fixed input file descriptor (if used)
 *
 * This structure holds all relevant parameters for performing splice or tee
 * operations asynchronously through io_uring. It supports both dynamic and
 * fixed file descriptor sources and tracks offset, size, and operation flags.
 */

struct io_splice {
	struct file			*file_out;
	loff_t				off_out;
	loff_t				off_in;
	u64				len;
	int				splice_fd_in;
	unsigned int			flags;
	struct io_rsrc_node		*rsrc_node;
};

/**
 * __io_splice_prep - Common preparation logic for splice and tee requests
 * @req:  io_kiocb request structure
 * @sqe:  Submission Queue Entry containing the splice parameters
 *
 * Extracts and validates common splice/tee parameters:
 *   - Reads length, flags, and input file descriptor
 *   - Verifies that no invalid flags are used
 *   - Marks request for asynchronous execution
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if unsupported flags are present
 */

static int __io_splice_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	unsigned int valid_flags = SPLICE_F_FD_IN_FIXED | SPLICE_F_ALL;

	sp->len = READ_ONCE(sqe->len);
	sp->flags = READ_ONCE(sqe->splice_flags);
	if (unlikely(sp->flags & ~valid_flags))
		return -EINVAL;
	sp->splice_fd_in = READ_ONCE(sqe->splice_fd_in);
	sp->rsrc_node = NULL;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/**
 * io_tee_prep - Prepare a tee operation
 * @req:  io_kiocb request structure
 * @sqe:  Submission Queue Entry containing tee parameters
 *
 * Validates that offsets are zero (required for tee), then delegates
 * common preparation to __io_splice_prep().
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if any offset is non-zero
 */

int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (READ_ONCE(sqe->splice_off_in) || READ_ONCE(sqe->off))
		return -EINVAL;
	return __io_splice_prep(req, sqe);
}

/**
 * io_splice_cleanup - Release resources associated with a splice request
 * @req:  io_kiocb request whose resources are to be released
 *
 * Decrements the reference count of the fixed file resource node if used.
 * Called after the splice operation is complete to prevent resource leaks.
 */

void io_splice_cleanup(struct io_kiocb *req)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);

	if (sp->rsrc_node)
		io_put_rsrc_node(req->ctx, sp->rsrc_node);
}

/**
 * io_splice_get_file - Retrieve the input file for splice or tee
 * @req:          io_kiocb request containing splice parameters
 * @issue_flags:  Issue-time flags for locking context
 *
 * Resolves the input file descriptor for splice:
 *   - If SPLICE_F_FD_IN_FIXED is not set, uses standard file lookup
 *   - If fixed, locates file from fixed file table and bumps reference
 *
 * Returns:
 *   - Pointer to the input file on success
 *   - NULL if the file cannot be resolved
 */

static struct file *io_splice_get_file(struct io_kiocb *req,
				       unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_rsrc_node *node;
	struct file *file = NULL;

	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		return io_file_get_normal(req, sp->splice_fd_in);

	io_ring_submit_lock(ctx, issue_flags);
	node = io_rsrc_node_lookup(&ctx->file_table.data, sp->splice_fd_in);
	if (node) {
		node->refs++;
		sp->rsrc_node = node;
		file = io_slot_file(node);
		req->flags |= REQ_F_NEED_CLEANUP;
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return file;
}
/**
 * io_tee - Perform a tee operation between two pipes
 * @req:          io_kiocb representing the tee request
 * @issue_flags:  Flags used during request submission
 *
 * Uses `do_tee()` to duplicate pipe data without consuming it:
 *   - Retrieves input file from descriptor or fixed slot
 *   - Performs tee from input pipe to output pipe for given length
 *   - Releases input file if not fixed
 *
 * Completion result is set to the number of bytes tee'd or an error.
 *
 * Returns:
 *   - IOU_OK always (completion status handled internally)
 */

int io_tee(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	struct file *in;
	ssize_t ret = 0;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	in = io_splice_get_file(req, issue_flags);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	if (sp->len)
		ret = do_tee(in, out, sp->len, flags);

	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);
done:
	if (ret != sp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
/**
 * io_splice_prep - Prepare a splice operation
 * @req:  io_kiocb request structure
 * @sqe:  Submission Queue Entry containing splice parameters
 *
 * Reads and stores input and output offsets, then delegates
 * the rest of the preparation to __io_splice_prep().
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL for invalid flags or parameters
 */

int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);

	sp->off_in = READ_ONCE(sqe->splice_off_in);
	sp->off_out = READ_ONCE(sqe->off);
	return __io_splice_prep(req, sqe);
}
/**
 * io_splice - Perform a splice operation between two files
 * @req:          io_kiocb representing the splice request
 * @issue_flags:  Submission-time flags
 *
 * Uses `do_splice()` to transfer data between files or pipes:
 *   - Resolves input and output files
 *   - Applies optional offsets if provided
 *   - Performs the splice for the specified length and flags
 *   - Cleans up input file reference if not fixed
 *
 * Sets completion result to the number of bytes spliced or error.
 *
 * Returns:
 *   - IOU_OK always (completion is handled internally)
 */

int io_splice(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	loff_t *poff_in, *poff_out;
	struct file *in;
	ssize_t ret = 0;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	in = io_splice_get_file(req, issue_flags);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	poff_in = (sp->off_in == -1) ? NULL : &sp->off_in;
	poff_out = (sp->off_out == -1) ? NULL : &sp->off_out;

	if (sp->len)
		ret = do_splice(in, poff_in, out, poff_out, sp->len, flags);

	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);
done:
	if (ret != sp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
