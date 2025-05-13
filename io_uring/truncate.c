// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "truncate.h"

/*
 * struct io_ftrunc - Struktur konteks untuk operasi ftruncate pada io_uring.
 * @file:  File yang menjadi target operasi truncate.
 * @len:   Panjang akhir file setelah truncate.
 */
struct io_ftrunc {
	struct file			*file;
	loff_t				len;
};

/*
 * io_ftruncate_prep - Mempersiapkan operasi ftruncate.
 * @req: io_kiocb untuk permintaan operasi.
 * @sqe: Submission Queue Entry yang berisi parameter permintaan dari user space.
 *
 * Memvalidasi bahwa hanya field `off` dari sqe yang digunakan (field lainnya harus nol).
 * Field `off` digunakan sebagai panjang file baru, yang disimpan dalam `ft->len`.
 * Operasi ini disiapkan sebagai operasi asynchronous.
 *
 * Return:
 *   0 jika sukses,
 *  -EINVAL jika ada field yang tidak valid digunakan.
 */
int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ftrunc *ft = io_kiocb_to_cmd(req, struct io_ftrunc);

	if (sqe->rw_flags || sqe->addr || sqe->len || sqe->buf_index ||
	    sqe->splice_fd_in || sqe->addr3)
		return -EINVAL;

	ft->len = READ_ONCE(sqe->off);

	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_ftruncate - Menjalankan operasi ftruncate.
 * @req: io_kiocb untuk permintaan operasi.
 * @issue_flags: Flag untuk eksekusi, seperti non-blocking.
 *
 * Memanggil `do_ftruncate()` untuk memotong file yang ditunjuk oleh `req->file`
 * menjadi panjang yang ditentukan dalam `ft->len`. Operasi ini dilakukan secara blocking.
 *
 * Hasil dari operasi dikembalikan ke user space melalui `io_req_set_res()`.
 *
 * Return:
 *   IOU_OK selalu, hasil disimpan di `req->cqe.res`.
 */
int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ftrunc *ft = io_kiocb_to_cmd(req, struct io_ftrunc);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_ftruncate(req->file, ft->len, 1);

	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
