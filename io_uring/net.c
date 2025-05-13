// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/compat.h>
#include <net/compat.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "alloc_cache.h"
#include "net.h"
#include "notif.h"
#include "rsrc.h"

#if defined(CONFIG_NET)
struct io_shutdown {
	struct file			*file;
	int				how;
};

struct io_accept {
	struct file			*file;
	struct sockaddr __user		*addr;
	int __user			*addr_len;
	int				flags;
	int				iou_flags;
	u32				file_slot;
	unsigned long			nofile;
};

struct io_socket {
	struct file			*file;
	int				domain;
	int				type;
	int				protocol;
	int				flags;
	u32				file_slot;
	unsigned long			nofile;
};

struct io_connect {
	struct file			*file;
	struct sockaddr __user		*addr;
	int				addr_len;
	bool				in_progress;
	bool				seen_econnaborted;
};

struct io_bind {
	struct file			*file;
	int				addr_len;
};

struct io_listen {
	struct file			*file;
	int				backlog;
};

struct io_sr_msg {
	struct file			*file;
	union {
		struct compat_msghdr __user	*umsg_compat;
		struct user_msghdr __user	*umsg;
		void __user			*buf;
	};
	int				len;
	unsigned			done_io;
	unsigned			msg_flags;
	unsigned			nr_multishot_loops;
	u16				flags;
	/* initialised and used only by !msg send variants */
	u16				buf_group;
	u16				buf_index;
	void __user			*msg_control;
	/* used only for send zerocopy */
	struct io_kiocb 		*notif;
};

/*
 * Number of times we'll try and do receives if there's more data. If we
 * exceed this limit, then add us to the back of the queue and retry from
 * there. This helps fairness between flooding clients.
 */
#define MULTISHOT_MAX_RETRY	32

/*
 * io_shutdown_prep - Prepare a shutdown request
 * @req: io_kiocb request to prepare
 * @sqe: Submission queue entry from userspace
 *
 * Validates that unsupported SQE fields are unset and copies the shutdown mode
 * (e.g., SHUT_RD, SHUT_WR) from sqe->len into the request. Forces the request
 * to be handled asynchronously.
 *
 * Return: 0 on success, -EINVAL if unsupported fields are set.
 */

int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_shutdown *shutdown = io_kiocb_to_cmd(req, struct io_shutdown);

	if (unlikely(sqe->off || sqe->addr || sqe->rw_flags ||
		     sqe->buf_index || sqe->splice_fd_in))
		return -EINVAL;

	shutdown->how = READ_ONCE(sqe->len);
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_shutdown - Execute a socket shutdown request
 * @req: The io_kiocb prepared request
 * @issue_flags: Submission flags (unused here except WARN_ON check)
 *
 * Attempts to retrieve the socket from the file associated with the request.
 * If successful, performs a shutdown operation with the specified mode.
 * Sets the result of the request.
 *
 * Return: IOU_OK after setting the result, -ENOTSOCK if file is not a socket.
 */

int io_shutdown(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_shutdown *shutdown = io_kiocb_to_cmd(req, struct io_shutdown);
	struct socket *sock;
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	ret = __sys_shutdown_sock(sock, shutdown->how);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_net_retry - Determine if socket operation can be retried
 * @sock: Target socket
 * @flags: Message flags passed by user
 *
 * Determines if a retry should be attempted for stream or sequenced packet
 * sockets using MSG_WAITALL.
 *
 * Return: true if retry is allowed, false otherwise.
 */

static bool io_net_retry(struct socket *sock, int flags)
{
	if (!(flags & MSG_WAITALL))
		return false;
	return sock->type == SOCK_STREAM || sock->type == SOCK_SEQPACKET;
}

/*
 * io_netmsg_iovec_free - Free dynamic iovec in async message header
 * @kmsg: Pointer to the async message header
 *
 * Frees any dynamically allocated iovec array associated with the async
 * msghdr, and resets tracking fields.
 */

static void io_netmsg_iovec_free(struct io_async_msghdr *kmsg)
{
	if (kmsg->free_iov) {
		kfree(kmsg->free_iov);
		kmsg->free_iov_nr = 0;
		kmsg->free_iov = NULL;
	}
}

/*
 * io_netmsg_recycle - Recycle async network message header
 * @req: The request associated with the async header
 * @issue_flags: Issue context flags
 *
 * Frees iovec if the request is unlocked. Otherwise, attempts to return
 * the header to the io_uring async data cache. If successful, clears
 * references in the request.
 */

static void io_netmsg_recycle(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_async_msghdr *hdr = req->async_data;

	/* can't recycle, ensure we free the iovec if we have one */
	if (unlikely(issue_flags & IO_URING_F_UNLOCKED)) {
		io_netmsg_iovec_free(hdr);
		return;
	}

	/* Let normal cleanup path reap it if we fail adding to the cache */
	io_alloc_cache_kasan(&hdr->free_iov, &hdr->free_iov_nr);
	if (io_alloc_cache_put(&req->ctx->netmsg_cache, hdr)) {
		req->async_data = NULL;
		req->flags &= ~(REQ_F_ASYNC_DATA|REQ_F_NEED_CLEANUP);
	}
}

/*
 * io_msg_alloc_async - Allocate async network message header
 * @req: The io_kiocb request
 *
 * Allocates (or reuses) an io_async_msghdr from the context's netmsg_cache.
 * Sets REQ_F_NEED_CLEANUP if an old iovec is still cached inside.
 *
 * Return: Pointer to allocated header or NULL on failure.
 */

static struct io_async_msghdr *io_msg_alloc_async(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_async_msghdr *hdr;

	hdr = io_uring_alloc_async_data(&ctx->netmsg_cache, req);
	if (!hdr)
		return NULL;

	/* If the async data was cached, we might have an iov cached inside. */
	if (hdr->free_iov)
		req->flags |= REQ_F_NEED_CLEANUP;
	return hdr;
}

/* assign new iovec to kmsg, if we need to */
/*
 * io_net_vec_assign - Assign iovec to async message header
 * @req: The io_kiocb request
 * @kmsg: Async message header to assign to
 * @iov: Pointer to new iovec to assign
 *
 * Updates kmsg with a new iovec and marks the request for cleanup.
 * Frees any previously assigned iovec.
 */

static void io_net_vec_assign(struct io_kiocb *req, struct io_async_msghdr *kmsg,
			     struct iovec *iov)
{
	if (iov) {
		req->flags |= REQ_F_NEED_CLEANUP;
		kmsg->free_iov_nr = kmsg->msg.msg_iter.nr_segs;
		if (kmsg->free_iov)
			kfree(kmsg->free_iov);
		kmsg->free_iov = iov;
	}
}

/*
 * io_mshot_prep_retry - Prepare multi-shot request for retry
 * @req: The io_kiocb request
 * @kmsg: The async message header associated with the request
 *
 * Resets state for a multi-shot message (e.g., recvmsg), clearing partial I/O
 * markers and resetting length.
 */

static inline void io_mshot_prep_retry(struct io_kiocb *req,
				       struct io_async_msghdr *kmsg)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);

	req->flags &= ~REQ_F_BL_EMPTY;
	sr->done_io = 0;
	sr->len = 0; /* get from the provided buffer */
	req->buf_index = sr->buf_group;
}

#ifdef CONFIG_COMPAT
/*
 * io_compat_msg_copy_hdr - Copy and import a compat msghdr
 * @req: The io_kiocb request
 * @iomsg: Async message header
 * @msg: Destination for copied compat msghdr
 * @ddir: Data direction (read/write)
 *
 * Imports iovec data from a compat userspace message. Validates length,
 * handles buffer selection mode, and ensures safe memory access.
 *
 * Return: 0 on success, negative error code on failure.
 */

static int io_compat_msg_copy_hdr(struct io_kiocb *req,
				  struct io_async_msghdr *iomsg,
				  struct compat_msghdr *msg, int ddir)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct compat_iovec __user *uiov;
	struct iovec *iov;
	int ret, nr_segs;

	if (iomsg->free_iov) {
		nr_segs = iomsg->free_iov_nr;
		iov = iomsg->free_iov;
	} else {
		iov = &iomsg->fast_iov;
		nr_segs = 1;
	}

	if (copy_from_user(msg, sr->umsg_compat, sizeof(*msg)))
		return -EFAULT;

	uiov = compat_ptr(msg->msg_iov);
	if (req->flags & REQ_F_BUFFER_SELECT) {
		compat_ssize_t clen;

		if (msg->msg_iovlen == 0) {
			sr->len = iov->iov_len = 0;
			iov->iov_base = NULL;
		} else if (msg->msg_iovlen > 1) {
			return -EINVAL;
		} else {
			if (!access_ok(uiov, sizeof(*uiov)))
				return -EFAULT;
			if (__get_user(clen, &uiov->iov_len))
				return -EFAULT;
			if (clen < 0)
				return -EINVAL;
			sr->len = clen;
		}

		return 0;
	}

	ret = __import_iovec(ddir, (struct iovec __user *)uiov, msg->msg_iovlen,
				nr_segs, &iov, &iomsg->msg.msg_iter, true);
	if (unlikely(ret < 0))
		return ret;

	io_net_vec_assign(req, iomsg, iov);
	return 0;
}
#endif

/*
 * io_msg_copy_hdr - Copy and import a userspace msghdr
 * @req: The io_kiocb request
 * @iomsg: Async message header
 * @msg: Destination for copied msghdr
 * @ddir: Data direction (read/write)
 *
 * Copies and safely accesses fields from the user-provided msghdr.
 * If the request uses buffer selection, it only verifies the iovec length.
 * Otherwise, it imports the iovec for the message and assigns it to the
 * async header.
 *
 * Return: 0 on success, negative error code on failure.
 */

static int io_msg_copy_hdr(struct io_kiocb *req, struct io_async_msghdr *iomsg,
			   struct user_msghdr *msg, int ddir)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct user_msghdr __user *umsg = sr->umsg;
	struct iovec *iov;
	int ret, nr_segs;

	if (iomsg->free_iov) {
		nr_segs = iomsg->free_iov_nr;
		iov = iomsg->free_iov;
	} else {
		iov = &iomsg->fast_iov;
		nr_segs = 1;
	}

	if (!user_access_begin(umsg, sizeof(*umsg)))
		return -EFAULT;

	ret = -EFAULT;
	unsafe_get_user(msg->msg_name, &umsg->msg_name, ua_end);
	unsafe_get_user(msg->msg_namelen, &umsg->msg_namelen, ua_end);
	unsafe_get_user(msg->msg_iov, &umsg->msg_iov, ua_end);
	unsafe_get_user(msg->msg_iovlen, &umsg->msg_iovlen, ua_end);
	unsafe_get_user(msg->msg_control, &umsg->msg_control, ua_end);
	unsafe_get_user(msg->msg_controllen, &umsg->msg_controllen, ua_end);
	msg->msg_flags = 0;

	if (req->flags & REQ_F_BUFFER_SELECT) {
		if (msg->msg_iovlen == 0) {
			sr->len = iov->iov_len = 0;
			iov->iov_base = NULL;
		} else if (msg->msg_iovlen > 1) {
			ret = -EINVAL;
			goto ua_end;
		} else {
			struct iovec __user *uiov = msg->msg_iov;

			/* we only need the length for provided buffers */
			if (!access_ok(&uiov->iov_len, sizeof(uiov->iov_len)))
				goto ua_end;
			unsafe_get_user(iov->iov_len, &uiov->iov_len, ua_end);
			sr->len = iov->iov_len;
		}
		ret = 0;
ua_end:
		user_access_end();
		return ret;
	}

	user_access_end();
	ret = __import_iovec(ddir, msg->msg_iov, msg->msg_iovlen, nr_segs,
				&iov, &iomsg->msg.msg_iter, false);
	if (unlikely(ret < 0))
		return ret;

	io_net_vec_assign(req, iomsg, iov);
	return 0;
}

/*
 * io_sendmsg_copy_hdr - copy and prepare user msghdr into kernel format
 * @req: the io_kiocb request
 * @iomsg: async msghdr buffer used to store the parsed header
 *
 * Copies the user-space message header into the kernel-space structure.
 * Supports both native and compat (32-bit) versions.
 *
 * Return: 0 on success, or negative error code on failure.
 */

static int io_sendmsg_copy_hdr(struct io_kiocb *req,
			       struct io_async_msghdr *iomsg)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct user_msghdr msg;
	int ret;

	iomsg->msg.msg_name = &iomsg->addr;
	iomsg->msg.msg_iter.nr_segs = 0;

#ifdef CONFIG_COMPAT
	if (unlikely(req->ctx->compat)) {
		struct compat_msghdr cmsg;

		ret = io_compat_msg_copy_hdr(req, iomsg, &cmsg, ITER_SOURCE);
		if (unlikely(ret))
			return ret;

		ret = __get_compat_msghdr(&iomsg->msg, &cmsg, NULL);
		sr->msg_control = iomsg->msg.msg_control_user;
		return ret;
	}
#endif

	ret = io_msg_copy_hdr(req, iomsg, &msg, ITER_SOURCE);
	if (unlikely(ret))
		return ret;

	ret = __copy_msghdr(&iomsg->msg, &msg, NULL);

	/* save msg_control as sys_sendmsg() overwrites it */
	sr->msg_control = iomsg->msg.msg_control_user;
	return ret;
}

/*
 * io_sendmsg_recvmsg_cleanup - cleanup for async msghdr after send/recv
 * @req: the io_kiocb request
 *
 * Frees the allocated iovec in the async message structure.
 */

void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req)
{
	struct io_async_msghdr *io = req->async_data;

	io_netmsg_iovec_free(io);
}

/*
 * io_send_setup - setup for IORING_OP_SEND
 * @req: the io_kiocb request
 * @sqe: submission queue entry
 *
 * Initializes necessary fields for a send operation, including buffer import
 * and optional socket address copy.
 *
 * Return: 0 on success, or negative error code.
 */

static int io_send_setup(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	void __user *addr;
	u16 addr_len;
	int ret;

	sr->buf = u64_to_user_ptr(READ_ONCE(sqe->addr));

	if (READ_ONCE(sqe->__pad3[0]))
		return -EINVAL;

	kmsg->msg.msg_name = NULL;
	kmsg->msg.msg_namelen = 0;
	kmsg->msg.msg_control = NULL;
	kmsg->msg.msg_controllen = 0;
	kmsg->msg.msg_ubuf = NULL;

	addr = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	addr_len = READ_ONCE(sqe->addr_len);
	if (addr) {
		ret = move_addr_to_kernel(addr, addr_len, &kmsg->addr);
		if (unlikely(ret < 0))
			return ret;
		kmsg->msg.msg_name = &kmsg->addr;
		kmsg->msg.msg_namelen = addr_len;
	}
	if (!io_do_buffer_select(req)) {
		ret = import_ubuf(ITER_SOURCE, sr->buf, sr->len,
				  &kmsg->msg.msg_iter);
		if (unlikely(ret < 0))
			return ret;
	}
	return 0;
}

/*
 * io_sendmsg_setup - setup for IORING_OP_SENDMSG
 * @req: the io_kiocb request
 * @sqe: submission queue entry
 *
 * Copies and initializes msghdr for sendmsg from user space.
 *
 * Return: 0 on success, or negative error code.
 */

static int io_sendmsg_setup(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	int ret;

	sr->umsg = u64_to_user_ptr(READ_ONCE(sqe->addr));

	ret = io_sendmsg_copy_hdr(req, kmsg);
	if (!ret)
		req->flags |= REQ_F_NEED_CLEANUP;
	return ret;
}

#define SENDMSG_FLAGS (IORING_RECVSEND_POLL_FIRST | IORING_RECVSEND_BUNDLE)
/*
 * io_sendmsg_prep - prepares send or sendmsg operation
 * @req: the io_kiocb request
 * @sqe: submission queue entry
 *
 * Parses and validates SQE fields, allocates async message structure,
 * and performs setup for either send or sendmsg depending on opcode.
 *
 * Return: 0 on success, -ENOMEM on memory error, or -EINVAL on invalid parameters.
 */

int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);

	sr->done_io = 0;

	if (req->opcode != IORING_OP_SEND) {
		if (sqe->addr2 || sqe->file_index)
			return -EINVAL;
	}

	sr->len = READ_ONCE(sqe->len);
	sr->flags = READ_ONCE(sqe->ioprio);
	if (sr->flags & ~SENDMSG_FLAGS)
		return -EINVAL;
	sr->msg_flags = READ_ONCE(sqe->msg_flags) | MSG_NOSIGNAL;
	if (sr->msg_flags & MSG_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;
	if (sr->flags & IORING_RECVSEND_BUNDLE) {
		if (req->opcode == IORING_OP_SENDMSG)
			return -EINVAL;
		if (!(req->flags & REQ_F_BUFFER_SELECT))
			return -EINVAL;
		sr->msg_flags |= MSG_WAITALL;
		sr->buf_group = req->buf_index;
		req->buf_list = NULL;
	}

#ifdef CONFIG_COMPAT
	if (req->ctx->compat)
		sr->msg_flags |= MSG_CMSG_COMPAT;
#endif
	if (unlikely(!io_msg_alloc_async(req)))
		return -ENOMEM;
	if (req->opcode != IORING_OP_SENDMSG)
		return io_send_setup(req, sqe);
	return io_sendmsg_setup(req, sqe);
}

/*
 * io_req_msg_cleanup - cleans up after send/recvmsg request
 * @req: the io_kiocb request
 * @issue_flags: flags passed during issue stage
 *
 * Frees or recycles network message-related data structures.
 */

static void io_req_msg_cleanup(struct io_kiocb *req,
			       unsigned int issue_flags)
{
	io_netmsg_recycle(req, issue_flags);
}

/*
 * For bundle completions, we need to figure out how many segments we consumed.
 * A bundle could be using a single ITER_UBUF if that's all we mapped, or it
 * could be using an ITER_IOVEC. If the latter, then if we consumed all of
 * the segments, then it's a trivial questiont o answer. If we have residual
 * data in the iter, then loop the segments to figure out how much we
 * transferred.
 */

 /*
 * io_bundle_nbufs - determine number of buffer segments used
 * @kmsg: async msghdr containing the iovec or ubuf
 * @ret: number of bytes transferred
 *
 * Computes how many buffer segments were consumed for a bundled recv/send.
 *
 * Return: number of iovec/ubuf segments used.
 */

static int io_bundle_nbufs(struct io_async_msghdr *kmsg, int ret)
{
	struct iovec *iov;
	int nbufs;

	/* no data is always zero segments, and a ubuf is always 1 segment */
	if (ret <= 0)
		return 0;
	if (iter_is_ubuf(&kmsg->msg.msg_iter))
		return 1;

	iov = kmsg->free_iov;
	if (!iov)
		iov = &kmsg->fast_iov;

	/* if all data was transferred, it's basic pointer math */
	if (!iov_iter_count(&kmsg->msg.msg_iter))
		return iter_iov(&kmsg->msg.msg_iter) - iov;

	/* short transfer, count segments */
	nbufs = 0;
	do {
		int this_len = min_t(int, iov[nbufs].iov_len, ret);

		nbufs++;
		ret -= this_len;
	} while (ret);

	return nbufs;
}

/*
 * io_send_finish - finalizes a send operation and manages bundled completion
 * @req: the io_kiocb request
 * @ret: pointer to result value of the operation
 * @kmsg: async msghdr used in the operation
 * @issue_flags: submission flags
 *
 * Handles completion, buffer release, and if needed, schedules a retry
 * for multi-shot bundled requests.
 *
 * Return: true if the request is completed, false if it needs a retry.
 */

static inline bool io_send_finish(struct io_kiocb *req, int *ret,
				  struct io_async_msghdr *kmsg,
				  unsigned issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	bool bundle_finished = *ret <= 0;
	unsigned int cflags;

	if (!(sr->flags & IORING_RECVSEND_BUNDLE)) {
		cflags = io_put_kbuf(req, *ret, issue_flags);
		goto finish;
	}

	cflags = io_put_kbufs(req, *ret, io_bundle_nbufs(kmsg, *ret), issue_flags);

	if (bundle_finished || req->flags & REQ_F_BL_EMPTY)
		goto finish;

	/*
	 * Fill CQE for this receive and see if we should keep trying to
	 * receive from this socket.
	 */
	if (io_req_post_cqe(req, *ret, cflags | IORING_CQE_F_MORE)) {
		io_mshot_prep_retry(req, kmsg);
		return false;
	}

	/* Otherwise stop bundle and use the current result. */
finish:
	io_req_set_res(req, *ret, cflags);
	*ret = IOU_OK;
	return true;
}

/*
 * io_sendmsg - handle IORING_OP_SENDMSG request
 * @req: io_kiocb request structure
 * @issue_flags: flags passed by the submission context
 *
 * Handles a sendmsg operation for a socket using data previously
 * prepared in @req->async_data. Performs retry logic if the
 * send is partial and socket supports retry.
 *
 * Return: IOU_OK on success, negative error code on failure.
 */
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	struct socket *sock;
	unsigned flags;
	int min_ret = 0;
	int ret;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	if (!(req->flags & REQ_F_POLLED) &&
	    (sr->flags & IORING_RECVSEND_POLL_FIRST))
		return -EAGAIN;

	flags = sr->msg_flags;
	if (issue_flags & IO_URING_F_NONBLOCK)
		flags |= MSG_DONTWAIT;
	if (flags & MSG_WAITALL)
		min_ret = iov_iter_count(&kmsg->msg.msg_iter);

	kmsg->msg.msg_control_user = sr->msg_control;

	ret = __sys_sendmsg_sock(sock, &kmsg->msg, flags);

	if (ret < min_ret) {
		if (ret == -EAGAIN && (issue_flags & IO_URING_F_NONBLOCK))
			return -EAGAIN;
		if (ret > 0 && io_net_retry(sock, flags)) {
			kmsg->msg.msg_controllen = 0;
			kmsg->msg.msg_control = NULL;
			sr->done_io += ret;
			req->flags |= REQ_F_BL_NO_RECYCLE;
			return -EAGAIN;
		}
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	}
	io_req_msg_cleanup(req, issue_flags);
	if (ret >= 0)
		ret += sr->done_io;
	else if (sr->done_io)
		ret = sr->done_io;
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_send_select_buffer - select a buffer and prepare send message iterator
 * @req: io_kiocb request structure
 * @issue_flags: flags passed by the submission context
 * @kmsg: async message header used to store buffer/iterator
 *
 * Selects a buffer for sending, imports it, and prepares the iov_iter.
 * If only one buffer is selected, sets up a single iterator; otherwise
 * initializes an iov_iter from selected buffers.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int io_send_select_buffer(struct io_kiocb *req, unsigned int issue_flags,
				 struct io_async_msghdr *kmsg)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);

	int ret;
	struct buf_sel_arg arg = {
		.iovs = &kmsg->fast_iov,
		.max_len = min_not_zero(sr->len, INT_MAX),
		.nr_iovs = 1,
	};

	if (kmsg->free_iov) {
		arg.nr_iovs = kmsg->free_iov_nr;
		arg.iovs = kmsg->free_iov;
		arg.mode = KBUF_MODE_FREE;
	}

	if (!(sr->flags & IORING_RECVSEND_BUNDLE))
		arg.nr_iovs = 1;
	else
		arg.mode |= KBUF_MODE_EXPAND;

	ret = io_buffers_select(req, &arg, issue_flags);
	if (unlikely(ret < 0))
		return ret;

	if (arg.iovs != &kmsg->fast_iov && arg.iovs != kmsg->free_iov) {
		kmsg->free_iov_nr = ret;
		kmsg->free_iov = arg.iovs;
		req->flags |= REQ_F_NEED_CLEANUP;
	}
	sr->len = arg.out_len;

	if (ret == 1) {
		sr->buf = arg.iovs[0].iov_base;
		ret = import_ubuf(ITER_SOURCE, sr->buf, sr->len,
					&kmsg->msg.msg_iter);
		if (unlikely(ret))
			return ret;
	} else {
		iov_iter_init(&kmsg->msg.msg_iter, ITER_SOURCE,
				arg.iovs, ret, arg.out_len);
	}

	return 0;
}

/*
 * io_send - handle IORING_OP_SEND request
 * @req: io_kiocb request structure
 * @issue_flags: flags passed by the submission context
 *
 * Sends data over a socket using the prepared msghdr. Handles buffer
 * selection, short sends, and retry for bundle operations.
 *
 * Return: number of bytes sent or negative error code.
 */
int io_send(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	struct socket *sock;
	unsigned flags;
	int min_ret = 0;
	int ret;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	if (!(req->flags & REQ_F_POLLED) &&
	    (sr->flags & IORING_RECVSEND_POLL_FIRST))
		return -EAGAIN;

	flags = sr->msg_flags;
	if (issue_flags & IO_URING_F_NONBLOCK)
		flags |= MSG_DONTWAIT;

retry_bundle:
	if (io_do_buffer_select(req)) {
		ret = io_send_select_buffer(req, issue_flags, kmsg);
		if (ret)
			return ret;
	}

	/*
	 * If MSG_WAITALL is set, or this is a bundle send, then we need
	 * the full amount. If just bundle is set, if we do a short send
	 * then we complete the bundle sequence rather than continue on.
	 */
	if (flags & MSG_WAITALL || sr->flags & IORING_RECVSEND_BUNDLE)
		min_ret = iov_iter_count(&kmsg->msg.msg_iter);

	flags &= ~MSG_INTERNAL_SENDMSG_FLAGS;
	kmsg->msg.msg_flags = flags;
	ret = sock_sendmsg(sock, &kmsg->msg);
	if (ret < min_ret) {
		if (ret == -EAGAIN && (issue_flags & IO_URING_F_NONBLOCK))
			return -EAGAIN;

		if (ret > 0 && io_net_retry(sock, flags)) {
			sr->len -= ret;
			sr->buf += ret;
			sr->done_io += ret;
			req->flags |= REQ_F_BL_NO_RECYCLE;
			return -EAGAIN;
		}
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	}
	if (ret >= 0)
		ret += sr->done_io;
	else if (sr->done_io)
		ret = sr->done_io;

	if (!io_send_finish(req, &ret, kmsg, issue_flags))
		goto retry_bundle;

	io_req_msg_cleanup(req, issue_flags);
	return ret;
}

/*
 * io_recvmsg_mshot_prep - prepare multishot receive metadata
 * @req: io_kiocb request structure
 * @iomsg: async message header
 * @namelen: length of name buffer
 * @controllen: length of control buffer
 *
 * Prepares header data for multishot recvmsg, ensuring no overflows
 * occur in buffer calculations.
 *
 * Return: 0 on success, -EOVERFLOW on error.
 */
static int io_recvmsg_mshot_prep(struct io_kiocb *req,
				 struct io_async_msghdr *iomsg,
				 int namelen, size_t controllen)
{
	if ((req->flags & (REQ_F_APOLL_MULTISHOT|REQ_F_BUFFER_SELECT)) ==
			  (REQ_F_APOLL_MULTISHOT|REQ_F_BUFFER_SELECT)) {
		int hdr;

		if (unlikely(namelen < 0))
			return -EOVERFLOW;
		if (check_add_overflow(sizeof(struct io_uring_recvmsg_out),
					namelen, &hdr))
			return -EOVERFLOW;
		if (check_add_overflow(hdr, controllen, &hdr))
			return -EOVERFLOW;

		iomsg->namelen = namelen;
		iomsg->controllen = controllen;
		return 0;
	}

	return 0;
}

/*
 * io_recvmsg_copy_hdr - copy user-space msghdr into kernel msghdr
 * @req: io_kiocb request structure
 * @iomsg: async message header to populate
 *
 * Retrieves the msghdr from user-space and prepares it for recvmsg.
 * Supports both native and compat headers.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int io_recvmsg_copy_hdr(struct io_kiocb *req,
			       struct io_async_msghdr *iomsg)
{
	struct user_msghdr msg;
	int ret;

	iomsg->msg.msg_name = &iomsg->addr;
	iomsg->msg.msg_iter.nr_segs = 0;

#ifdef CONFIG_COMPAT
	if (unlikely(req->ctx->compat)) {
		struct compat_msghdr cmsg;

		ret = io_compat_msg_copy_hdr(req, iomsg, &cmsg, ITER_DEST);
		if (unlikely(ret))
			return ret;

		ret = __get_compat_msghdr(&iomsg->msg, &cmsg, &iomsg->uaddr);
		if (unlikely(ret))
			return ret;

		return io_recvmsg_mshot_prep(req, iomsg, cmsg.msg_namelen,
						cmsg.msg_controllen);
	}
#endif

	ret = io_msg_copy_hdr(req, iomsg, &msg, ITER_DEST);
	if (unlikely(ret))
		return ret;

	ret = __copy_msghdr(&iomsg->msg, &msg, &iomsg->uaddr);
	if (unlikely(ret))
		return ret;

	return io_recvmsg_mshot_prep(req, iomsg, msg.msg_namelen,
					msg.msg_controllen);
}

static int io_recvmsg_prep_setup(struct io_kiocb *req)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg;
	int ret;

	kmsg = io_msg_alloc_async(req);
	if (unlikely(!kmsg))
		return -ENOMEM;

	if (req->opcode == IORING_OP_RECV) {
		kmsg->msg.msg_name = NULL;
		kmsg->msg.msg_namelen = 0;
		kmsg->msg.msg_inq = 0;
		kmsg->msg.msg_control = NULL;
		kmsg->msg.msg_get_inq = 1;
		kmsg->msg.msg_controllen = 0;
		kmsg->msg.msg_iocb = NULL;
		kmsg->msg.msg_ubuf = NULL;

		if (!io_do_buffer_select(req)) {
			ret = import_ubuf(ITER_DEST, sr->buf, sr->len,
					  &kmsg->msg.msg_iter);
			if (unlikely(ret))
				return ret;
		}
		return 0;
	}

	ret = io_recvmsg_copy_hdr(req, kmsg);
	if (!ret)
		req->flags |= REQ_F_NEED_CLEANUP;
	return ret;
}

#define RECVMSG_FLAGS (IORING_RECVSEND_POLL_FIRST | IORING_RECV_MULTISHOT | \
			IORING_RECVSEND_BUNDLE)

/*
 * io_recvmsg_prep_setup - initialize data for recvmsg operation
 * @req: io_kiocb request structure
 *
 * Allocates and sets up the async message header structure and iterator
 * for recvmsg. Supports both IORING_OP_RECV and IORING_OP_RECVMSG.
 *
 * Return: 0 on success, negative error code on failure.
 */
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);

	sr->done_io = 0;

	if (unlikely(sqe->file_index || sqe->addr2))
		return -EINVAL;

	sr->umsg = u64_to_user_ptr(READ_ONCE(sqe->addr));
	sr->len = READ_ONCE(sqe->len);
	sr->flags = READ_ONCE(sqe->ioprio);
	if (sr->flags & ~RECVMSG_FLAGS)
		return -EINVAL;
	sr->msg_flags = READ_ONCE(sqe->msg_flags);
	if (sr->msg_flags & MSG_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;
	if (sr->msg_flags & MSG_ERRQUEUE)
		req->flags |= REQ_F_CLEAR_POLLIN;
	if (req->flags & REQ_F_BUFFER_SELECT) {
		/*
		 * Store the buffer group for this multishot receive separately,
		 * as if we end up doing an io-wq based issue that selects a
		 * buffer, it has to be committed immediately and that will
		 * clear ->buf_list. This means we lose the link to the buffer
		 * list, and the eventual buffer put on completion then cannot
		 * restore it.
		 */
		sr->buf_group = req->buf_index;
		req->buf_list = NULL;
	}
	if (sr->flags & IORING_RECV_MULTISHOT) {
		if (!(req->flags & REQ_F_BUFFER_SELECT))
			return -EINVAL;
		if (sr->msg_flags & MSG_WAITALL)
			return -EINVAL;
		if (req->opcode == IORING_OP_RECV && sr->len)
			return -EINVAL;
		req->flags |= REQ_F_APOLL_MULTISHOT;
	}
	if (sr->flags & IORING_RECVSEND_BUNDLE) {
		if (req->opcode == IORING_OP_RECVMSG)
			return -EINVAL;
	}

#ifdef CONFIG_COMPAT
	if (req->ctx->compat)
		sr->msg_flags |= MSG_CMSG_COMPAT;
#endif
	sr->nr_multishot_loops = 0;
	return io_recvmsg_prep_setup(req);
}

/*
 * Finishes io_recv and io_recvmsg.
 *
 * Returns true if it is actually finished, or false if it should run
 * again (for multishot).
 */
static inline bool io_recv_finish(struct io_kiocb *req, int *ret,
				  struct io_async_msghdr *kmsg,
				  bool mshot_finished, unsigned issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	unsigned int cflags = 0;

	if (kmsg->msg.msg_inq > 0)
		cflags |= IORING_CQE_F_SOCK_NONEMPTY;

	if (sr->flags & IORING_RECVSEND_BUNDLE) {
		cflags |= io_put_kbufs(req, *ret, io_bundle_nbufs(kmsg, *ret),
				      issue_flags);
		/* bundle with no more immediate buffers, we're done */
		if (req->flags & REQ_F_BL_EMPTY)
			goto finish;
	} else {
		cflags |= io_put_kbuf(req, *ret, issue_flags);
	}

	/*
	 * Fill CQE for this receive and see if we should keep trying to
	 * receive from this socket.
	 */
	if ((req->flags & REQ_F_APOLL_MULTISHOT) && !mshot_finished &&
	    io_req_post_cqe(req, *ret, cflags | IORING_CQE_F_MORE)) {
		int mshot_retry_ret = IOU_ISSUE_SKIP_COMPLETE;

		io_mshot_prep_retry(req, kmsg);
		/* Known not-empty or unknown state, retry */
		if (cflags & IORING_CQE_F_SOCK_NONEMPTY || kmsg->msg.msg_inq < 0) {
			if (sr->nr_multishot_loops++ < MULTISHOT_MAX_RETRY)
				return false;
			/* mshot retries exceeded, force a requeue */
			sr->nr_multishot_loops = 0;
			mshot_retry_ret = IOU_REQUEUE;
		}
		if (issue_flags & IO_URING_F_MULTISHOT)
			*ret = mshot_retry_ret;
		else
			*ret = -EAGAIN;
		return true;
	}

	/* Finish the request / stop multishot. */
finish:
	io_req_set_res(req, *ret, cflags);

	if (issue_flags & IO_URING_F_MULTISHOT)
		*ret = IOU_STOP_MULTISHOT;
	else
		*ret = IOU_OK;
	io_req_msg_cleanup(req, issue_flags);
	return true;
}

/*
 * io_recvmsg_prep_multishot - prepare multishot recvmsg buffer
 * @kmsg: async message header
 * @sr: io_sr_msg structure
 * @buf: pointer to the user buffer pointer
 * @len: pointer to length of the user buffer
 *
 * Prepares the user buffer for a multishot recvmsg operation by reserving
 * space for the header and setting up control data locations if needed.
 *
 * Return: 0 on success, -EFAULT if buffer too small.
 */
static int io_recvmsg_prep_multishot(struct io_async_msghdr *kmsg,
				     struct io_sr_msg *sr, void __user **buf,
				     size_t *len)
{
	unsigned long ubuf = (unsigned long) *buf;
	unsigned long hdr;

	hdr = sizeof(struct io_uring_recvmsg_out) + kmsg->namelen +
		kmsg->controllen;
	if (*len < hdr)
		return -EFAULT;

	if (kmsg->controllen) {
		unsigned long control = ubuf + hdr - kmsg->controllen;

		kmsg->msg.msg_control_user = (void __user *) control;
		kmsg->msg.msg_controllen = kmsg->controllen;
	}

	sr->buf = *buf; /* stash for later copy */
	*buf = (void __user *) (ubuf + hdr);
	kmsg->payloadlen = *len = *len - hdr;
	return 0;
}


struct io_recvmsg_multishot_hdr {
	struct io_uring_recvmsg_out msg;
	struct sockaddr_storage addr;
};

/*
 * io_recvmsg_multishot - perform a multishot recvmsg
 * @sock: socket to receive from
 * @io: io_sr_msg structure with user buffer info
 * @kmsg: async message header
 * @flags: message flags
 * @finished: set to true if this is the last shot
 *
 * Receives a message from a socket into a temporary kernel buffer,
 * and copies the result (header and address) to user space. Handles
 * truncation and flags appropriately.
 *
 * Return: total number of bytes written to user buffer on success,
 *         negative error code on failure.
 */
static int io_recvmsg_multishot(struct socket *sock, struct io_sr_msg *io,
				struct io_async_msghdr *kmsg,
				unsigned int flags, bool *finished)
{
	int err;
	int copy_len;
	struct io_recvmsg_multishot_hdr hdr;

	if (kmsg->namelen)
		kmsg->msg.msg_name = &hdr.addr;
	kmsg->msg.msg_flags = flags & (MSG_CMSG_CLOEXEC|MSG_CMSG_COMPAT);
	kmsg->msg.msg_namelen = 0;

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;

	err = sock_recvmsg(sock, &kmsg->msg, flags);
	*finished = err <= 0;
	if (err < 0)
		return err;

	hdr.msg = (struct io_uring_recvmsg_out) {
		.controllen = kmsg->controllen - kmsg->msg.msg_controllen,
		.flags = kmsg->msg.msg_flags & ~MSG_CMSG_COMPAT
	};

	hdr.msg.payloadlen = err;
	if (err > kmsg->payloadlen)
		err = kmsg->payloadlen;

	copy_len = sizeof(struct io_uring_recvmsg_out);
	if (kmsg->msg.msg_namelen > kmsg->namelen)
		copy_len += kmsg->namelen;
	else
		copy_len += kmsg->msg.msg_namelen;

	/*
	 *      "fromlen shall refer to the value before truncation.."
	 *                      1003.1g
	 */
	hdr.msg.namelen = kmsg->msg.msg_namelen;

	/* ensure that there is no gap between hdr and sockaddr_storage */
	BUILD_BUG_ON(offsetof(struct io_recvmsg_multishot_hdr, addr) !=
		     sizeof(struct io_uring_recvmsg_out));
	if (copy_to_user(io->buf, &hdr, copy_len)) {
		*finished = true;
		return -EFAULT;
	}

	return sizeof(struct io_uring_recvmsg_out) + kmsg->namelen +
			kmsg->controllen + err;
}

/*
 * io_recvmsg - handle IORING_OP_RECVMSG request
 * @req: io_kiocb request
 * @issue_flags: submission flags
 *
 * Handles both single-shot and multishot recvmsg operations. Supports
 * buffer selection, polling, and retry logic. Sets up control and
 * address structures if needed, and manages buffer recycling.
 *
 * Return: number of bytes received on success, negative error code on failure.
 */
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	struct socket *sock;
	unsigned flags;
	int ret, min_ret = 0;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
	bool mshot_finished = true;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	if (!(req->flags & REQ_F_POLLED) &&
	    (sr->flags & IORING_RECVSEND_POLL_FIRST))
		return -EAGAIN;

	flags = sr->msg_flags;
	if (force_nonblock)
		flags |= MSG_DONTWAIT;

retry_multishot:
	if (io_do_buffer_select(req)) {
		void __user *buf;
		size_t len = sr->len;

		buf = io_buffer_select(req, &len, issue_flags);
		if (!buf)
			return -ENOBUFS;

		if (req->flags & REQ_F_APOLL_MULTISHOT) {
			ret = io_recvmsg_prep_multishot(kmsg, sr, &buf, &len);
			if (ret) {
				io_kbuf_recycle(req, issue_flags);
				return ret;
			}
		}

		iov_iter_ubuf(&kmsg->msg.msg_iter, ITER_DEST, buf, len);
	}

	kmsg->msg.msg_get_inq = 1;
	kmsg->msg.msg_inq = -1;
	if (req->flags & REQ_F_APOLL_MULTISHOT) {
		ret = io_recvmsg_multishot(sock, sr, kmsg, flags,
					   &mshot_finished);
	} else {
		/* disable partial retry for recvmsg with cmsg attached */
		if (flags & MSG_WAITALL && !kmsg->msg.msg_controllen)
			min_ret = iov_iter_count(&kmsg->msg.msg_iter);

		ret = __sys_recvmsg_sock(sock, &kmsg->msg, sr->umsg,
					 kmsg->uaddr, flags);
	}

	if (ret < min_ret) {
		if (ret == -EAGAIN && force_nonblock) {
			if (issue_flags & IO_URING_F_MULTISHOT) {
				io_kbuf_recycle(req, issue_flags);
				return IOU_ISSUE_SKIP_COMPLETE;
			}
			return -EAGAIN;
		}
		if (ret > 0 && io_net_retry(sock, flags)) {
			sr->done_io += ret;
			req->flags |= REQ_F_BL_NO_RECYCLE;
			return -EAGAIN;
		}
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	} else if ((flags & MSG_WAITALL) && (kmsg->msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
		req_set_fail(req);
	}

	if (ret > 0)
		ret += sr->done_io;
	else if (sr->done_io)
		ret = sr->done_io;
	else
		io_kbuf_recycle(req, issue_flags);

	if (!io_recv_finish(req, &ret, kmsg, mshot_finished, issue_flags))
		goto retry_multishot;

	return ret;
}

/*
 * io_recv_buf_select - select and import buffer for recv
 * @req: io_kiocb request
 * @kmsg: async message header
 * @len: pointer to requested buffer length
 * @issue_flags: submission flags
 *
 * Selects a buffer for a receive operation based on buffer selection
 * mode. If bundle mode is used and multiple buffers are available,
 * sets up an iterator for them. Otherwise, maps a single user buffer.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int io_recv_buf_select(struct io_kiocb *req, struct io_async_msghdr *kmsg,
			      size_t *len, unsigned int issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	int ret;

	/*
	 * If the ring isn't locked, then don't use the peek interface
	 * to grab multiple buffers as we will lock/unlock between
	 * this selection and posting the buffers.
	 */
	if (!(issue_flags & IO_URING_F_UNLOCKED) &&
	    sr->flags & IORING_RECVSEND_BUNDLE) {
		struct buf_sel_arg arg = {
			.iovs = &kmsg->fast_iov,
			.nr_iovs = 1,
			.mode = KBUF_MODE_EXPAND,
		};

		if (kmsg->free_iov) {
			arg.nr_iovs = kmsg->free_iov_nr;
			arg.iovs = kmsg->free_iov;
			arg.mode |= KBUF_MODE_FREE;
		}

		if (kmsg->msg.msg_inq > 0)
			arg.max_len = min_not_zero(sr->len, kmsg->msg.msg_inq);

		ret = io_buffers_peek(req, &arg);
		if (unlikely(ret < 0))
			return ret;

		/* special case 1 vec, can be a fast path */
		if (ret == 1) {
			sr->buf = arg.iovs[0].iov_base;
			sr->len = arg.iovs[0].iov_len;
			goto map_ubuf;
		}
		iov_iter_init(&kmsg->msg.msg_iter, ITER_DEST, arg.iovs, ret,
				arg.out_len);
		if (arg.iovs != &kmsg->fast_iov && arg.iovs != kmsg->free_iov) {
			kmsg->free_iov_nr = ret;
			kmsg->free_iov = arg.iovs;
			req->flags |= REQ_F_NEED_CLEANUP;
		}
	} else {
		void __user *buf;

		*len = sr->len;
		buf = io_buffer_select(req, len, issue_flags);
		if (!buf)
			return -ENOBUFS;
		sr->buf = buf;
		sr->len = *len;
map_ubuf:
		ret = import_ubuf(ITER_DEST, sr->buf, sr->len,
				  &kmsg->msg.msg_iter);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

/*
 * io_recv - Handle IORING_OP_RECV operation
 * @req: io_kiocb representing the recv request
 * @issue_flags: execution control flags for the request
 *
 * This function processes a recv request for io_uring. It handles options
 * such as non-blocking operation, multishot support, buffer selection, and
 * partial receives with MSG_WAITALL. It uses sock_recvmsg() to receive
 * data from a socket.
 *
 * Return: number of bytes received on success, or negative error code.
 */
int io_recv(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	struct socket *sock;
	unsigned flags;
	int ret, min_ret = 0;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
	size_t len = sr->len;
	bool mshot_finished;

	if (!(req->flags & REQ_F_POLLED) &&
	    (sr->flags & IORING_RECVSEND_POLL_FIRST))
		return -EAGAIN;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	flags = sr->msg_flags;
	if (force_nonblock)
		flags |= MSG_DONTWAIT;

retry_multishot:
	if (io_do_buffer_select(req)) {
		ret = io_recv_buf_select(req, kmsg, &len, issue_flags);
		if (unlikely(ret)) {
			kmsg->msg.msg_inq = -1;
			goto out_free;
		}
		sr->buf = NULL;
	}

	kmsg->msg.msg_flags = 0;
	kmsg->msg.msg_inq = -1;

	if (flags & MSG_WAITALL)
		min_ret = iov_iter_count(&kmsg->msg.msg_iter);

	ret = sock_recvmsg(sock, &kmsg->msg, flags);
	if (ret < min_ret) {
		if (ret == -EAGAIN && force_nonblock) {
			if (issue_flags & IO_URING_F_MULTISHOT) {
				io_kbuf_recycle(req, issue_flags);
				return IOU_ISSUE_SKIP_COMPLETE;
			}

			return -EAGAIN;
		}
		if (ret > 0 && io_net_retry(sock, flags)) {
			sr->len -= ret;
			sr->buf += ret;
			sr->done_io += ret;
			req->flags |= REQ_F_BL_NO_RECYCLE;
			return -EAGAIN;
		}
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	} else if ((flags & MSG_WAITALL) && (kmsg->msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
out_free:
		req_set_fail(req);
	}

	mshot_finished = ret <= 0;
	if (ret > 0)
		ret += sr->done_io;
	else if (sr->done_io)
		ret = sr->done_io;
	else
		io_kbuf_recycle(req, issue_flags);

	if (!io_recv_finish(req, &ret, kmsg, mshot_finished, issue_flags))
		goto retry_multishot;

	return ret;
}

/*
 * io_send_zc_cleanup - Clean up after zero-copy send operation
 * @req: io_kiocb representing the send_zc request
 *
 * Frees associated iovec memory if async data exists, and flushes
 * notification if it was used.
 */

void io_send_zc_cleanup(struct io_kiocb *req)
{
	struct io_sr_msg *zc = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *io = req->async_data;

	if (req_has_async_data(req))
		io_netmsg_iovec_free(io);
	if (zc->notif) {
		io_notif_flush(zc->notif);
		zc->notif = NULL;
	}
}

#define IO_ZC_FLAGS_COMMON (IORING_RECVSEND_POLL_FIRST | IORING_RECVSEND_FIXED_BUF)
#define IO_ZC_FLAGS_VALID  (IO_ZC_FLAGS_COMMON | IORING_SEND_ZC_REPORT_USAGE)

/*
 * io_send_zc_prep - Prepare a zero-copy send or sendmsg request
 * @req: io_kiocb representing the request
 * @sqe: submission queue entry describing the operation
 *
 * Initializes internal data structures for a zero-copy send operation,
 * including notification setup and validation of sqe flags. Also sets
 * required socket message flags like MSG_ZEROCOPY and MSG_NOSIGNAL.
 *
 * Return: 0 on success, or a negative error code on failure.
 */

int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sr_msg *zc = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_kiocb *notif;

	zc->done_io = 0;
	req->flags |= REQ_F_POLL_NO_LAZY;

	if (unlikely(READ_ONCE(sqe->__pad2[0]) || READ_ONCE(sqe->addr3)))
		return -EINVAL;
	/* we don't support IOSQE_CQE_SKIP_SUCCESS just yet */
	if (req->flags & REQ_F_CQE_SKIP)
		return -EINVAL;

	notif = zc->notif = io_alloc_notif(ctx);
	if (!notif)
		return -ENOMEM;
	notif->cqe.user_data = req->cqe.user_data;
	notif->cqe.res = 0;
	notif->cqe.flags = IORING_CQE_F_NOTIF;
	req->flags |= REQ_F_NEED_CLEANUP;

	zc->flags = READ_ONCE(sqe->ioprio);
	if (unlikely(zc->flags & ~IO_ZC_FLAGS_COMMON)) {
		if (zc->flags & ~IO_ZC_FLAGS_VALID)
			return -EINVAL;
		if (zc->flags & IORING_SEND_ZC_REPORT_USAGE) {
			struct io_notif_data *nd = io_notif_to_data(notif);

			nd->zc_report = true;
			nd->zc_used = false;
			nd->zc_copied = false;
		}
	}

	if (req->opcode != IORING_OP_SEND_ZC) {
		if (unlikely(sqe->addr2 || sqe->file_index))
			return -EINVAL;
		if (unlikely(zc->flags & IORING_RECVSEND_FIXED_BUF))
			return -EINVAL;
	}

	zc->len = READ_ONCE(sqe->len);
	zc->msg_flags = READ_ONCE(sqe->msg_flags) | MSG_NOSIGNAL | MSG_ZEROCOPY;
	zc->buf_index = READ_ONCE(sqe->buf_index);
	if (zc->msg_flags & MSG_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;

#ifdef CONFIG_COMPAT
	if (req->ctx->compat)
		zc->msg_flags |= MSG_CMSG_COMPAT;
#endif
	if (unlikely(!io_msg_alloc_async(req)))
		return -ENOMEM;
	if (req->opcode != IORING_OP_SENDMSG_ZC)
		return io_send_setup(req, sqe);
	return io_sendmsg_setup(req, sqe);
}

/*
 * io_sg_from_iter_iovec - Fill skb from a user iovec iterator
 * @skb: target socket buffer
 * @from: source iov_iter
 * @length: total length to fill
 *
 * Helper to populate the skb with user data using zero-copy capable
 * mechanism, using iovec-based iteration.
 *
 * Return: 0 on success, or negative error on failure.
 */
static int io_sg_from_iter_iovec(struct sk_buff *skb,
				 struct iov_iter *from, size_t length)
{
	skb_zcopy_downgrade_managed(skb);
	return zerocopy_fill_skb_from_iter(skb, from, length);
}

/*
 * io_sg_from_iter - Fill skb from a bvec-style iov_iter
 * @skb: target socket buffer
 * @from: source iov_iter
 * @length: total length to fill
 *
 * Adds pages to the socket buffer's fragment list based on data from
 * a bio_vec-style iov_iter. Updates skb length and truesize accordingly.
 *
 * Return: 0 on success, -EMSGSIZE if fragment limit is exceeded.
 */

static int io_sg_from_iter(struct sk_buff *skb,
			   struct iov_iter *from, size_t length)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int frag = shinfo->nr_frags;
	int ret = 0;
	struct bvec_iter bi;
	ssize_t copied = 0;
	unsigned long truesize = 0;

	if (!frag)
		shinfo->flags |= SKBFL_MANAGED_FRAG_REFS;
	else if (unlikely(!skb_zcopy_managed(skb)))
		return zerocopy_fill_skb_from_iter(skb, from, length);

	bi.bi_size = min(from->count, length);
	bi.bi_bvec_done = from->iov_offset;
	bi.bi_idx = 0;

	while (bi.bi_size && frag < MAX_SKB_FRAGS) {
		struct bio_vec v = mp_bvec_iter_bvec(from->bvec, bi);

		copied += v.bv_len;
		truesize += PAGE_ALIGN(v.bv_len + v.bv_offset);
		__skb_fill_page_desc_noacc(shinfo, frag++, v.bv_page,
					   v.bv_offset, v.bv_len);
		bvec_iter_advance_single(from->bvec, &bi, v.bv_len);
	}
	if (bi.bi_size)
		ret = -EMSGSIZE;

	shinfo->nr_frags = frag;
	from->bvec += bi.bi_idx;
	from->nr_segs -= bi.bi_idx;
	from->count -= copied;
	from->iov_offset = bi.bi_bvec_done;

	skb->data_len += copied;
	skb->len += copied;
	skb->truesize += truesize;
	return ret;
}

/*
 * io_send_zc_import - Import user or fixed buffer into request
 * @req: io_kiocb representing the zero-copy send request
 * @issue_flags: flags for submission context
 *
 * Imports user-supplied or fixed buffer memory into the request's iov_iter
 * and sets the appropriate sg_from_iter function for skb preparation.
 * Also handles accounting for memory usage via notification object.
 *
 * Return: 0 on success, or negative error code on failure.
 */

static int io_send_zc_import(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	int ret;

	if (sr->flags & IORING_RECVSEND_FIXED_BUF) {
		struct io_ring_ctx *ctx = req->ctx;
		struct io_rsrc_node *node;

		ret = -EFAULT;
		io_ring_submit_lock(ctx, issue_flags);
		node = io_rsrc_node_lookup(&ctx->buf_table, sr->buf_index);
		if (node) {
			io_req_assign_buf_node(sr->notif, node);
			ret = 0;
		}
		io_ring_submit_unlock(ctx, issue_flags);

		if (unlikely(ret))
			return ret;

		ret = io_import_fixed(ITER_SOURCE, &kmsg->msg.msg_iter,
					node->buf, (u64)(uintptr_t)sr->buf,
					sr->len);
		if (unlikely(ret))
			return ret;
		kmsg->msg.sg_from_iter = io_sg_from_iter;
	} else {
		ret = import_ubuf(ITER_SOURCE, sr->buf, sr->len, &kmsg->msg.msg_iter);
		if (unlikely(ret))
			return ret;
		ret = io_notif_account_mem(sr->notif, sr->len);
		if (unlikely(ret))
			return ret;
		kmsg->msg.sg_from_iter = io_sg_from_iter_iovec;
	}

	return ret;
}

/*
 * io_send_zc - Handle zero-copy send for simple send operation
 * @req: io_kiocb request context
 * @issue_flags: flags used for request submission
 *
 * This function performs a zero-copy send on a socket. It first verifies
 * that the socket supports ZC (zero-copy), handles polling logic, and 
 * prepares the message if not already done. It uses sock_sendmsg() to 
 * perform the actual send.
 *
 * Returns:
 *   * >= 0 - number of bytes sent
 *   * -EAGAIN - if operation needs to be retried
 *   * -ENOTSOCK, -EOPNOTSUPP, -EINTR - on error
 */

int io_send_zc(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *zc = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	struct socket *sock;
	unsigned msg_flags;
	int ret, min_ret = 0;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;
	if (!test_bit(SOCK_SUPPORT_ZC, &sock->flags))
		return -EOPNOTSUPP;

	if (!(req->flags & REQ_F_POLLED) &&
	    (zc->flags & IORING_RECVSEND_POLL_FIRST))
		return -EAGAIN;

	if (!zc->done_io) {
		ret = io_send_zc_import(req, issue_flags);
		if (unlikely(ret))
			return ret;
	}

	msg_flags = zc->msg_flags;
	if (issue_flags & IO_URING_F_NONBLOCK)
		msg_flags |= MSG_DONTWAIT;
	if (msg_flags & MSG_WAITALL)
		min_ret = iov_iter_count(&kmsg->msg.msg_iter);
	msg_flags &= ~MSG_INTERNAL_SENDMSG_FLAGS;

	kmsg->msg.msg_flags = msg_flags;
	kmsg->msg.msg_ubuf = &io_notif_to_data(zc->notif)->uarg;
	ret = sock_sendmsg(sock, &kmsg->msg);

	if (unlikely(ret < min_ret)) {
		if (ret == -EAGAIN && (issue_flags & IO_URING_F_NONBLOCK))
			return -EAGAIN;

		if (ret > 0 && io_net_retry(sock, kmsg->msg.msg_flags)) {
			zc->len -= ret;
			zc->buf += ret;
			zc->done_io += ret;
			req->flags |= REQ_F_BL_NO_RECYCLE;
			return -EAGAIN;
		}
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	}

	if (ret >= 0)
		ret += zc->done_io;
	else if (zc->done_io)
		ret = zc->done_io;

	/*
	 * If we're in io-wq we can't rely on tw ordering guarantees, defer
	 * flushing notif to io_send_zc_cleanup()
	 */
	if (!(issue_flags & IO_URING_F_UNLOCKED)) {
		io_notif_flush(zc->notif);
		zc->notif = NULL;
		io_req_msg_cleanup(req, 0);
	}
	io_req_set_res(req, ret, IORING_CQE_F_MORE);
	return IOU_OK;
}

/*
 * io_sendmsg_zc - Handle zero-copy sendmsg operation
 * @req: io_kiocb request context
 * @issue_flags: flags used for request submission
 *
 * Similar to io_send_zc(), but for the `sendmsg` syscall. This handles
 * more complex message formats including control messages, scatter-gather
 * iovecs, and allows user-supplied msghdr structures. Uses __sys_sendmsg_sock().
 *
 * Returns:
 *   * >= 0 - number of bytes sent
 *   * -EAGAIN - if operation needs to be retried
 *   * -ENOTSOCK, -EOPNOTSUPP, -EINTR - on error
 */

int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);
	struct io_async_msghdr *kmsg = req->async_data;
	struct socket *sock;
	unsigned flags;
	int ret, min_ret = 0;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;
	if (!test_bit(SOCK_SUPPORT_ZC, &sock->flags))
		return -EOPNOTSUPP;

	if (!(req->flags & REQ_F_POLLED) &&
	    (sr->flags & IORING_RECVSEND_POLL_FIRST))
		return -EAGAIN;

	flags = sr->msg_flags;
	if (issue_flags & IO_URING_F_NONBLOCK)
		flags |= MSG_DONTWAIT;
	if (flags & MSG_WAITALL)
		min_ret = iov_iter_count(&kmsg->msg.msg_iter);

	kmsg->msg.msg_control_user = sr->msg_control;
	kmsg->msg.msg_ubuf = &io_notif_to_data(sr->notif)->uarg;
	kmsg->msg.sg_from_iter = io_sg_from_iter_iovec;
	ret = __sys_sendmsg_sock(sock, &kmsg->msg, flags);

	if (unlikely(ret < min_ret)) {
		if (ret == -EAGAIN && (issue_flags & IO_URING_F_NONBLOCK))
			return -EAGAIN;

		if (ret > 0 && io_net_retry(sock, flags)) {
			sr->done_io += ret;
			req->flags |= REQ_F_BL_NO_RECYCLE;
			return -EAGAIN;
		}
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	}

	if (ret >= 0)
		ret += sr->done_io;
	else if (sr->done_io)
		ret = sr->done_io;

	/*
	 * If we're in io-wq we can't rely on tw ordering guarantees, defer
	 * flushing notif to io_send_zc_cleanup()
	 */
	if (!(issue_flags & IO_URING_F_UNLOCKED)) {
		io_notif_flush(sr->notif);
		sr->notif = NULL;
		io_req_msg_cleanup(req, 0);
	}
	io_req_set_res(req, ret, IORING_CQE_F_MORE);
	return IOU_OK;
}

/*
 * io_sendrecv_fail - Finalize partially completed send/recv on failure
 * @req: io_kiocb request context
 *
 * If some data was already transferred (tracked in done_io),
 * this function ensures the result (`req->cqe.res`) reflects the
 * partial success. It also marks the CQE with IORING_CQE_F_MORE
 * if the request required additional cleanup.
 */

void io_sendrecv_fail(struct io_kiocb *req)
{
	struct io_sr_msg *sr = io_kiocb_to_cmd(req, struct io_sr_msg);

	if (sr->done_io)
		req->cqe.res = sr->done_io;

	if ((req->flags & REQ_F_NEED_CLEANUP) &&
	    (req->opcode == IORING_OP_SEND_ZC || req->opcode == IORING_OP_SENDMSG_ZC))
		req->cqe.flags |= IORING_CQE_F_MORE;
}

#define ACCEPT_FLAGS	(IORING_ACCEPT_MULTISHOT | IORING_ACCEPT_DONTWAIT | \
			 IORING_ACCEPT_POLL_FIRST)
/*
 * io_accept_prep - Prepare an accept request for io_uring.
 * @req: io_kiocb structure containing request context.
 * @sqe: submission queue entry containing user parameters.
 *
 * Validates and initializes an io_accept structure from user-provided
 * SQE data. Checks for invalid flags, improper file slot usage, and
 * converts user pointers. Prepares the request for execution by setting
 * flags for multishot and non-blocking modes if applicable.
 */
int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_accept *accept = io_kiocb_to_cmd(req, struct io_accept);

	if (sqe->len || sqe->buf_index)
		return -EINVAL;

	accept->addr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	accept->addr_len = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	accept->flags = READ_ONCE(sqe->accept_flags);
	accept->nofile = rlimit(RLIMIT_NOFILE);
	accept->iou_flags = READ_ONCE(sqe->ioprio);
	if (accept->iou_flags & ~ACCEPT_FLAGS)
		return -EINVAL;

	accept->file_slot = READ_ONCE(sqe->file_index);
	if (accept->file_slot) {
		if (accept->flags & SOCK_CLOEXEC)
			return -EINVAL;
		if (accept->iou_flags & IORING_ACCEPT_MULTISHOT &&
		    accept->file_slot != IORING_FILE_INDEX_ALLOC)
			return -EINVAL;
	}
	if (accept->flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	if (SOCK_NONBLOCK != O_NONBLOCK && (accept->flags & SOCK_NONBLOCK))
		accept->flags = (accept->flags & ~SOCK_NONBLOCK) | O_NONBLOCK;
	if (accept->iou_flags & IORING_ACCEPT_MULTISHOT)
		req->flags |= REQ_F_APOLL_MULTISHOT;
	if (accept->iou_flags & IORING_ACCEPT_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;
	return 0;
}

/*
 * io_accept - Execute an accept request for io_uring.
 * @req: io_kiocb structure containing request context.
 * @issue_flags: flags indicating issue-time conditions (e.g., non-blocking).
 *
 * Performs the accept() syscall, handling both fixed and dynamic file
 * descriptors. Implements multishot support and retry-on-EAGAIN behavior.
 * Sets result via io_req_set_res() and manages request lifecycle.
 */
int io_accept(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_accept *accept = io_kiocb_to_cmd(req, struct io_accept);
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
	bool fixed = !!accept->file_slot;
	struct proto_accept_arg arg = {
		.flags = force_nonblock ? O_NONBLOCK : 0,
	};
	struct file *file;
	unsigned cflags;
	int ret, fd;

	if (!(req->flags & REQ_F_POLLED) &&
	    accept->iou_flags & IORING_ACCEPT_POLL_FIRST)
		return -EAGAIN;

retry:
	if (!fixed) {
		fd = __get_unused_fd_flags(accept->flags, accept->nofile);
		if (unlikely(fd < 0))
			return fd;
	}
	arg.err = 0;
	arg.is_empty = -1;
	file = do_accept(req->file, &arg, accept->addr, accept->addr_len,
			 accept->flags);
	if (IS_ERR(file)) {
		if (!fixed)
			put_unused_fd(fd);
		ret = PTR_ERR(file);
		if (ret == -EAGAIN && force_nonblock &&
		    !(accept->iou_flags & IORING_ACCEPT_DONTWAIT)) {
			/*
			 * if it's multishot and polled, we don't need to
			 * return EAGAIN to arm the poll infra since it
			 * has already been done
			 */
			if (issue_flags & IO_URING_F_MULTISHOT)
				return IOU_ISSUE_SKIP_COMPLETE;
			return ret;
		}
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	} else if (!fixed) {
		fd_install(fd, file);
		ret = fd;
	} else {
		ret = io_fixed_fd_install(req, issue_flags, file,
						accept->file_slot);
	}

	cflags = 0;
	if (!arg.is_empty)
		cflags |= IORING_CQE_F_SOCK_NONEMPTY;

	if (!(req->flags & REQ_F_APOLL_MULTISHOT)) {
		io_req_set_res(req, ret, cflags);
		return IOU_OK;
	}

	if (ret < 0)
		return ret;
	if (io_req_post_cqe(req, ret, cflags | IORING_CQE_F_MORE)) {
		if (cflags & IORING_CQE_F_SOCK_NONEMPTY || arg.is_empty == -1)
			goto retry;
		if (issue_flags & IO_URING_F_MULTISHOT)
			return IOU_ISSUE_SKIP_COMPLETE;
		return -EAGAIN;
	}

	io_req_set_res(req, ret, cflags);
	return IOU_STOP_MULTISHOT;
}

/*
 * io_socket_prep - Prepare a socket() request for io_uring.
 * @req: io_kiocb structure containing request context.
 * @sqe: submission queue entry with socket parameters.
 *
 * Validates and extracts socket domain, type, protocol, and file_slot
 * from the SQE. Checks for invalid combinations of socket flags and ensures
 * CLOEXEC is not used with fixed file slots.
 */
int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_socket *sock = io_kiocb_to_cmd(req, struct io_socket);

	if (sqe->addr || sqe->rw_flags || sqe->buf_index)
		return -EINVAL;

	sock->domain = READ_ONCE(sqe->fd);
	sock->type = READ_ONCE(sqe->off);
	sock->protocol = READ_ONCE(sqe->len);
	sock->file_slot = READ_ONCE(sqe->file_index);
	sock->nofile = rlimit(RLIMIT_NOFILE);

	sock->flags = sock->type & ~SOCK_TYPE_MASK;
	if (sock->file_slot && (sock->flags & SOCK_CLOEXEC))
		return -EINVAL;
	if (sock->flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	return 0;
}

/*
 * io_socket - Execute a socket() syscall for io_uring.
 * @req: io_kiocb structure containing request context.
 * @issue_flags: flags indicating issue-time behavior.
 *
 * Calls __sys_socket_file to create a socket. Handles both fixed and
 * dynamic file descriptor installation. Reports errors and sets result
 * via io_req_set_res().
 */
int io_socket(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_socket *sock = io_kiocb_to_cmd(req, struct io_socket);
	bool fixed = !!sock->file_slot;
	struct file *file;
	int ret, fd;

	if (!fixed) {
		fd = __get_unused_fd_flags(sock->flags, sock->nofile);
		if (unlikely(fd < 0))
			return fd;
	}
	file = __sys_socket_file(sock->domain, sock->type, sock->protocol);
	if (IS_ERR(file)) {
		if (!fixed)
			put_unused_fd(fd);
		ret = PTR_ERR(file);
		if (ret == -EAGAIN && (issue_flags & IO_URING_F_NONBLOCK))
			return -EAGAIN;
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail(req);
	} else if (!fixed) {
		fd_install(fd, file);
		ret = fd;
	} else {
		ret = io_fixed_fd_install(req, issue_flags, file,
					    sock->file_slot);
	}
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_connect_prep - Prepare a connect() request for io_uring.
 * @req: io_kiocb structure containing request context.
 * @sqe: submission queue entry with socket address parameters.
 *
 * Initializes the connect structure with sockaddr and length from SQE,
 * and allocates space for asynchronous address handling. Validates unsupported
 * fields and prepares internal buffers via move_addr_to_kernel().
 */
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_connect *conn = io_kiocb_to_cmd(req, struct io_connect);
	struct io_async_msghdr *io;

	if (sqe->len || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	conn->addr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	conn->addr_len =  READ_ONCE(sqe->addr2);
	conn->in_progress = conn->seen_econnaborted = false;

	io = io_msg_alloc_async(req);
	if (unlikely(!io))
		return -ENOMEM;

	return move_addr_to_kernel(conn->addr, conn->addr_len, &io->addr);
}

/*
 * io_connect - issue a connect syscall for io_uring
 * @req: io_kiocb representing the request
 * @issue_flags: flags modifying request behavior
 *
 * Executes the connect() system call on a socket file descriptor. Handles
 * asynchronous connect states including non-blocking operation, EINPROGRESS,
 * ECONNABORTED retries, and final error recovery via sock_error().
 *
 * Cleans up message data and sets the result code for the request.
 *
 * Return: IOU_OK after setting result (success or failure)
 */
int io_connect(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_connect *connect = io_kiocb_to_cmd(req, struct io_connect);
	struct io_async_msghdr *io = req->async_data;
	unsigned file_flags;
	int ret;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	if (unlikely(req->flags & REQ_F_FAIL)) {
		ret = -ECONNRESET;
		goto out;
	}

	file_flags = force_nonblock ? O_NONBLOCK : 0;

	ret = __sys_connect_file(req->file, &io->addr, connect->addr_len,
				 file_flags);
	if ((ret == -EAGAIN || ret == -EINPROGRESS || ret == -ECONNABORTED)
	    && force_nonblock) {
		if (ret == -EINPROGRESS) {
			connect->in_progress = true;
		} else if (ret == -ECONNABORTED) {
			if (connect->seen_econnaborted)
				goto out;
			connect->seen_econnaborted = true;
		}
		return -EAGAIN;
	}
	if (connect->in_progress) {
		/*
		 * At least bluetooth will return -EBADFD on a re-connect
		 * attempt, and it's (supposedly) also valid to get -EISCONN
		 * which means the previous result is good. For both of these,
		 * grab the sock_error() and use that for the completion.
		 */
		if (ret == -EBADFD || ret == -EISCONN)
			ret = sock_error(sock_from_file(req->file)->sk);
	}
	if (ret == -ERESTARTSYS)
		ret = -EINTR;
out:
	if (ret < 0)
		req_set_fail(req);
	io_req_msg_cleanup(req, issue_flags);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_bind_prep - prepare socket bind request
 * @req: io_kiocb representing the request
 * @sqe: submission queue entry
 *
 * Validates and extracts bind parameters from the submission queue entry.
 * Copies the sockaddr structure from userspace to kernel memory and stores
 * it in an async message header.
 *
 * Return: 0 on success, -EINVAL on invalid SQE, -ENOMEM or error from move_addr_to_kernel()
 */
int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_bind *bind = io_kiocb_to_cmd(req, struct io_bind);
	struct sockaddr __user *uaddr;
	struct io_async_msghdr *io;

	if (sqe->len || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	bind->addr_len =  READ_ONCE(sqe->addr2);

	io = io_msg_alloc_async(req);
	if (unlikely(!io))
		return -ENOMEM;
	return move_addr_to_kernel(uaddr, bind->addr_len, &io->addr);
}

/*
 * io_bind - issue a bind syscall for io_uring
 * @req: io_kiocb representing the request
 * @issue_flags: flags modifying request behavior (currently unused)
 *
 * Issues the bind() system call on a socket, binding it to the given address.
 * Retrieves socket from file and applies the address from async msg header.
 * Sets result and fail flag if the bind fails.
 *
 * Return: 0 after setting result (success or failure)
 */
int io_bind(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_bind *bind = io_kiocb_to_cmd(req, struct io_bind);
	struct io_async_msghdr *io = req->async_data;
	struct socket *sock;
	int ret;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	ret = __sys_bind_socket(sock, &io->addr, bind->addr_len);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return 0;
}

/*
 * io_listen_prep - prepare listen syscall request
 * @req: io_kiocb representing the request
 * @sqe: submission queue entry
 *
 * Validates the listen SQE and extracts the backlog parameter. Ensures
 * other fields are zero as they are unused for this operation.
 *
 * Return: 0 on success, -EINVAL on unexpected SQE fields
 */
int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_listen *listen = io_kiocb_to_cmd(req, struct io_listen);

	if (sqe->addr || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in || sqe->addr2)
		return -EINVAL;

	listen->backlog = READ_ONCE(sqe->len);
	return 0;
}

/*
 * io_listen - issue a listen syscall for io_uring
 * @req: io_kiocb representing the request
 * @issue_flags: flags modifying request behavior (currently unused)
 *
 * Calls listen() on the socket associated with the request. Extracts socket
 * and backlog from request data. Sets result and fail flag on error.
 *
 * Return: 0 after setting result (success or failure)
 */
int io_listen(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_listen *listen = io_kiocb_to_cmd(req, struct io_listen);
	struct socket *sock;
	int ret;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	ret = __sys_listen_socket(sock, listen->backlog);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return 0;
}

/*
 * io_netmsg_cache_free - free async network message structure
 * @entry: pointer to io_async_msghdr structure
 *
 * Frees memory associated with async network message, including any
 * dynamically allocated iovec buffers. Intended as a slab cache free callback.
 */
void io_netmsg_cache_free(const void *entry)
{
	struct io_async_msghdr *kmsg = (struct io_async_msghdr *) entry;

	if (kmsg->free_iov)
		io_netmsg_iovec_free(kmsg);
	kfree(kmsg);
}
#endif
