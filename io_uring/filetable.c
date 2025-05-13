// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"

/*
 * io_file_bitmap_get - Find a free file slot in the fixed file bitmap
 * @ctx: Pointer to io_uring context
 *
 * Scans the bitmap of fixed file slots to locate the next available slot
 * for use. It attempts allocation starting from `alloc_hint`, wrapping
 * around if necessary to `file_alloc_start`.
 *
 * Return:
 * * Slot index on success
 * * -ENFILE if no slots are available
 */
static int io_file_bitmap_get(struct io_ring_ctx *ctx)
{
	struct io_file_table *table = &ctx->file_table;
	unsigned long nr = ctx->file_alloc_end;
	int ret;

	if (!table->bitmap)
		return -ENFILE;

	do {
		ret = find_next_zero_bit(table->bitmap, nr, table->alloc_hint);
		if (ret != nr)
			return ret;

		if (table->alloc_hint == ctx->file_alloc_start)
			break;
		nr = table->alloc_hint;
		table->alloc_hint = ctx->file_alloc_start;
	} while (1);

	return -ENFILE;
}

/*
 * io_alloc_file_tables - Allocate bitmap and resource table for fixed files
 * @ctx:       Pointer to io_uring context
 * @table:     Pointer to the file table to initialize
 * @nr_files:  Number of slots to allocate
 *
 * Allocates the internal data structures (resource table and bitmap)
 * required to manage fixed file slots. If bitmap allocation fails,
 * the function ensures all resources are freed before returning.
 *
 * Return:
 * * true if allocation succeeded
 * * false on failure
 */
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table,
			  unsigned nr_files)
{
	if (io_rsrc_data_alloc(&table->data, nr_files))
		return false;
	table->bitmap = bitmap_zalloc(nr_files, GFP_KERNEL_ACCOUNT);
	if (table->bitmap)
		return true;
	io_rsrc_data_free(ctx, &table->data);
	return false;
}

/*
 * io_free_file_tables - Free file table and bitmap for fixed file slots
 * @ctx:   Pointer to io_uring context
 * @table: Pointer to the file table to free
 *
 * Frees the bitmap and resource data associated with a file table
 * used for fixed file slot management.
 */
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table)
{
	io_rsrc_data_free(ctx, &table->data);
	bitmap_free(table->bitmap);
	table->bitmap = NULL;
}

/*
 * io_install_fixed_file - Install a file into a fixed file slot
 * @ctx:        Pointer to io_uring context
 * @file:       File pointer to install
 * @slot_index: Index in the fixed file table
 *
 * Installs a given file into the fixed file table at a specified index.
 * Ensures the file is not an io_uring file and that the slot index is
 * within bounds. If the slot was previously unused, the bitmap is updated.
 *
 * Context:
 * Must be called with uring_lock held.
 *
 * Return:
 * * 0 on success
 * * -EBADF if attempting to register an io_uring file
 * * -ENXIO if the file table is uninitialized
 * * -EINVAL if the slot index is invalid
 * * -ENOMEM if allocation of resource node fails
 */
static int io_install_fixed_file(struct io_ring_ctx *ctx, struct file *file,
				 u32 slot_index)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_rsrc_node *node;

	if (io_is_uring_fops(file))
		return -EBADF;
	if (!ctx->file_table.data.nr)
		return -ENXIO;
	if (slot_index >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_alloc(IORING_RSRC_FILE);
	if (!node)
		return -ENOMEM;

	if (!io_reset_rsrc_node(ctx, &ctx->file_table.data, slot_index))
		io_file_bitmap_set(&ctx->file_table, slot_index);

	ctx->file_table.data.nodes[slot_index] = node;
	io_fixed_file_set(node, file);
	return 0;
}

/*
 * __io_fixed_fd_install - Install or allocate a file into fixed file slots
 * @ctx:        Pointer to io_uring context
 * @file:       File pointer to install
 * @file_slot:  Slot to install into, or IORING_FILE_INDEX_ALLOC to auto-allocate
 *
 * Installs a file into the fixed file table. If @file_slot is set to
 * IORING_FILE_INDEX_ALLOC, the function automatically finds a free slot
 * using io_file_bitmap_get(). Otherwise, installs at the specified slot.
 *
 * Return:
 * * 0 on success
 * * Slot index if auto-allocation was used and succeeded
 * * Appropriate negative error code on failure
 */
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
			  unsigned int file_slot)
{
	bool alloc_slot = file_slot == IORING_FILE_INDEX_ALLOC;
	int ret;

	if (alloc_slot) {
		ret = io_file_bitmap_get(ctx);
		if (unlikely(ret < 0))
			return ret;
		file_slot = ret;
	} else {
		file_slot--;
	}

	ret = io_install_fixed_file(ctx, file, file_slot);
	if (!ret && alloc_slot)
		ret = file_slot;
	return ret;
}
/*
 * Note when io_fixed_fd_install() returns error value, it will ensure
 * fput() is called correspondingly.
 */

/*
 * io_fixed_fd_install - Public wrapper to install a file into a fixed slot
 * @req:         The io_kiocb request structure
 * @issue_flags: Submission flags passed to the request
 * @file:        File to install
 * @file_slot:   Slot to install into, or IORING_FILE_INDEX_ALLOC to auto-allocate
 *
 * Acquires the submit lock and calls __io_fixed_fd_install() to install
 * a file into the fixed file table. If the install fails, the file is released.
 *
 * Return:
 * * 0 on success
 * * Slot index if auto-allocation succeeded
 * * Negative error code on failure
 */
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	io_ring_submit_lock(ctx, issue_flags);
	ret = __io_fixed_fd_install(ctx, file, file_slot);
	io_ring_submit_unlock(ctx, issue_flags);

	if (unlikely(ret < 0))
		fput(file);
	return ret;
}

/*
 * io_fixed_fd_remove - Remove a file from the fixed file table
 * @ctx:    Pointer to io_uring context
 * @offset: Slot index of the file to remove
 *
 * Removes the file at the given offset from the fixed file table.
 * Frees the resource node and clears the corresponding bit in the bitmap.
 *
 * Return:
 * * 0 on success
 * * -ENXIO if the file table is not initialized
 * * -EINVAL if the offset is out of bounds
 * * -EBADF if no file is registered at the given offset
 */
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset)
{
	struct io_rsrc_node *node;

	if (unlikely(!ctx->file_table.data.nr))
		return -ENXIO;
	if (offset >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_lookup(&ctx->file_table.data, offset);
	if (!node)
		return -EBADF;
	io_reset_rsrc_node(ctx, &ctx->file_table.data, offset);
	io_file_bitmap_clear(&ctx->file_table, offset);
	return 0;
}

/*
 * io_register_file_alloc_range - Set allocation range for fixed file table
 * @ctx: Pointer to io_uring context
 * @arg: User pointer to struct io_uring_file_index_range
 *
 * Validates and sets a range within the fixed file table to be used
 * for automatic allocation. Prevents overflow and out-of-bounds access.
 *
 * Return:
 * * 0 on success
 * * -EFAULT if user memory cannot be accessed
 * * -EOVERFLOW if range causes an overflow
 * * -EINVAL if reserved field is non-zero or range exceeds table size
 */
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg)
{
	struct io_uring_file_index_range range;
	u32 end;

	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;
	if (check_add_overflow(range.off, range.len, &end))
		return -EOVERFLOW;
	if (range.resv || end > ctx->file_table.data.nr)
		return -EINVAL;

	io_file_table_set_alloc_range(ctx, range.off, range.len);
	return 0;
}
