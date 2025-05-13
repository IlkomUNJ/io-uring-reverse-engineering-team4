// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/eventfd.h>
#include <linux/eventpoll.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>

#include "io-wq.h"
#include "eventfd.h"

struct io_ev_fd {
	struct eventfd_ctx	*cq_ev_fd;
	unsigned int		eventfd_async;
	/* protected by ->completion_lock */
	unsigned		last_cq_tail;
	refcount_t		refs;
	atomic_t		ops;
	struct rcu_head		rcu;
};

enum {
	IO_EVENTFD_OP_SIGNAL_BIT,
};

/*
 * io_eventfd_free - RCU callback to free an io_ev_fd structure
 *
 * @rcu: RCU head embedded in io_ev_fd
 *
 * This function is called after the last reference to an io_ev_fd
 * is dropped. It releases the eventfd context and frees the memory.
 */
static void io_eventfd_free(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_ctx_put(ev_fd->cq_ev_fd);
	kfree(ev_fd);
}

/*
 * io_eventfd_put - Release a reference to an io_ev_fd
 *
 * @ev_fd: Pointer to io_ev_fd structure
 *
 * Decrements the reference count. If it reaches zero, schedules the
 * structure to be freed using RCU via io_eventfd_free().
 */
static void io_eventfd_put(struct io_ev_fd *ev_fd)
{
	if (refcount_dec_and_test(&ev_fd->refs))
		call_rcu(&ev_fd->rcu, io_eventfd_free);
}

/*
 * io_eventfd_do_signal - Signal eventfd and release io_ev_fd
 *
 * @rcu: RCU head embedded in io_ev_fd
 *
 * This function is used to signal the eventfd with a specific mask
 * (EPOLL_URING_WAKE) to notify of CQ events, then drops a reference
 * to the io_ev_fd. Called as an RCU callback.
 */
static void io_eventfd_do_signal(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);
	io_eventfd_put(ev_fd);
}

/*
 * io_eventfd_release - Unlock RCU read and optionally put io_ev_fd ref
 *
 * @ev_fd: Pointer to io_ev_fd structure
 * @put_ref: Whether to drop a reference to the io_ev_fd
 *
 * Releases the RCU read lock. If @put_ref is true, also drops a reference,
 * possibly triggering final cleanup via io_eventfd_put().
 */
static void io_eventfd_release(struct io_ev_fd *ev_fd, bool put_ref)
{
	if (put_ref)
		io_eventfd_put(ev_fd);
	rcu_read_unlock();
}

/*
 * Returns true if the caller should put the ev_fd reference, false if not.
*/
/*
 * __io_eventfd_signal - Signal an eventfd if allowed, otherwise defer
 *
 * @ev_fd: Pointer to io_ev_fd structure
 *
 * Attempts to signal the associated eventfd using a specific mask
 * (EPOLL_URING_WAKE). If signaling is not currently allowed (e.g., due to
 * being in an atomic context), sets a flag and schedules a deferred signal
 * using RCU callback.
 *
 * Returns true if the signal was sent immediately or has already been
 * scheduled. Returns false if this is the first time scheduling the deferred
 * signal.
*/
static bool __io_eventfd_signal(struct io_ev_fd *ev_fd)
{
	if (eventfd_signal_allowed()) {
		eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);
		return true;
	}
	if (!atomic_fetch_or(BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops)) {
		call_rcu_hurry(&ev_fd->rcu, io_eventfd_do_signal);
		return false;
	}
	return true;
}

/*
 * Trigger if eventfd_async isn't set, or if it's set and the caller is
 * an async worker. If ev_fd isn't valid, obviously return false.
 */
/*
 * io_eventfd_trigger - Check if the eventfd should be signaled
 *
 * @ev_fd: Pointer to io_ev_fd structure
 *
 * Determines whether it is appropriate to signal the eventfd based on its
 * configuration. If the eventfd is not async or the current context is an
 * io-wq worker, returns true to allow signaling.
 *
 * Returns true if signaling is allowed, false otherwise.
 */
static bool io_eventfd_trigger(struct io_ev_fd *ev_fd)
{
	if (ev_fd)
		return !ev_fd->eventfd_async || io_wq_current_is_worker();
	return false;
}

/*
 * On success, returns with an ev_fd reference grabbed and the RCU read
 * lock held.
 */

/*
 * io_eventfd_grab - Acquire a reference to the eventfd if signaling is enabled
 *
 * @ctx: Pointer to io_ring_ctx structure
 *
 * Checks whether eventfd signaling is enabled via CQ flags and attempts to
 * safely acquire a reference to the eventfd under RCU protection. Ensures
 * the eventfd is still valid and that signaling is allowed.
 *
 * Returns a pointer to a valid io_ev_fd with an increased reference count,
 * or NULL if signaling is disabled or the eventfd is unavailable.
 */
static struct io_ev_fd *io_eventfd_grab(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	if (READ_ONCE(ctx->rings->cq_flags) & IORING_CQ_EVENTFD_DISABLED)
		return NULL;

	rcu_read_lock();

	/*
	 * rcu_dereference ctx->io_ev_fd once and use it for both for checking
	 * and eventfd_signal
	 */
	ev_fd = rcu_dereference(ctx->io_ev_fd);

	/*
	 * Check again if ev_fd exists in case an io_eventfd_unregister call
	 * completed between the NULL check of ctx->io_ev_fd at the start of
	 * the function and rcu_read_lock.
	 */
	if (io_eventfd_trigger(ev_fd) && refcount_inc_not_zero(&ev_fd->refs))
		return ev_fd;

	rcu_read_unlock();
	return NULL;
}

/*
 * io_eventfd_signal - Attempt to signal eventfd associated with the ring
 *
 * @ctx: Pointer to io_ring_ctx structure
 *
 * This function attempts to safely acquire the eventfd associated with the
 * ring context, and signal it if possible. If signaling isn't currently
 * allowed, schedules deferred signaling using RCU.
 */
void io_eventfd_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);
	if (ev_fd)
		io_eventfd_release(ev_fd, __io_eventfd_signal(ev_fd));
}

/*
 * io_eventfd_flush_signal - Conditionally signal eventfd if new CQEs were added
 *
 * @ctx: Pointer to io_ring_ctx structure
 *
 * This function ensures that the eventfd is only signaled if at least one
 * new CQE has been posted since the last time the eventfd was triggered.
 * This avoids unnecessary wakeups and ensures that the eventfd counter only
 * changes when actual completions occur. This behavior is required by
 * applications that depend on eventfd notifications being strictly tied to
 * CQE posting.
 */
void io_eventfd_flush_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);
	if (ev_fd) {
		bool skip, put_ref = true;

		/*
		 * Eventfd should only get triggered when at least one event
		 * has been posted. Some applications rely on the eventfd
		 * notification count only changing IFF a new CQE has been
		 * added to the CQ ring. There's no dependency on 1:1
		 * relationship between how many times this function is called
		 * (and hence the eventfd count) and number of CQEs posted to
		 * the CQ ring.
		 */
		spin_lock(&ctx->completion_lock);
		skip = ctx->cached_cq_tail == ev_fd->last_cq_tail;
		ev_fd->last_cq_tail = ctx->cached_cq_tail;
		spin_unlock(&ctx->completion_lock);

		if (!skip)
			put_ref = __io_eventfd_signal(ev_fd);

		io_eventfd_release(ev_fd, put_ref);
	}
}

/*
 * io_eventfd_register - Register an eventfd to be signaled on CQE postings
 *
 * @ctx: Pointer to io_ring_ctx structure
 * @arg: User pointer to __s32 holding the eventfd file descriptor
 * @eventfd_async: Whether signaling should occur only from async context
 *
 * Registers an eventfd with the given io_uring context. This eventfd will be
 * signaled when new completion events are posted. Returns an error if an
 * eventfd is already registered. Takes an initial snapshot of the CQ tail to
 * support conditional signaling in io_eventfd_flush_signal().
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async)
{
	struct io_ev_fd *ev_fd;
	__s32 __user *fds = arg;
	int fd;

	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd)
		return -EBUSY;

	if (copy_from_user(&fd, fds, sizeof(*fds)))
		return -EFAULT;

	ev_fd = kmalloc(sizeof(*ev_fd), GFP_KERNEL);
	if (!ev_fd)
		return -ENOMEM;

	ev_fd->cq_ev_fd = eventfd_ctx_fdget(fd);
	if (IS_ERR(ev_fd->cq_ev_fd)) {
		int ret = PTR_ERR(ev_fd->cq_ev_fd);

		kfree(ev_fd);
		return ret;
	}

	spin_lock(&ctx->completion_lock);
	ev_fd->last_cq_tail = ctx->cached_cq_tail;
	spin_unlock(&ctx->completion_lock);

	ev_fd->eventfd_async = eventfd_async;
	ctx->has_evfd = true;
	refcount_set(&ev_fd->refs, 1);
	atomic_set(&ev_fd->ops, 0);
	rcu_assign_pointer(ctx->io_ev_fd, ev_fd);
	return 0;
}

/*
 * io_eventfd_unregister - Unregister an eventfd from the io_uring context
 *
 * @ctx: Pointer to io_ring_ctx structure
 *
 * Unregisters the eventfd associated with the given io_uring context. This
 * prevents further signals from being sent. If no eventfd is registered,
 * returns -ENXIO. Otherwise, clears the pointer and drops the reference.
 *
 * Returns 0 on success, or -ENXIO if no eventfd was registered.
 */
int io_eventfd_unregister(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd) {
		ctx->has_evfd = false;
		rcu_assign_pointer(ctx->io_ev_fd, NULL);
		io_eventfd_put(ev_fd);
		return 0;
	}

	return -ENXIO;
}
