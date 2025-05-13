# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter
io_kiocb         | notif.c                   | work, flags, io_task, refcount_t                                  | cmd_to_io_kiocb           | notif.c                          | local variable                    
|                 |                           |                                                                  | container_of              | cancel.c                         | function parameter                
io_notif_data    | net.c                     | struct io_kiocb, struct ubuf_info, refcount_t                     | io_notif_to_data          | net.c                            | local variable                    
io_tw_state      | notif.c                   | struct io_kiocb, state                                           | io_notif_tw_complete      | notif.c                          | function parameter                
struct sk_buff   | notif.c                   | skb_data, skb_len                                                 | io_link_skb               | notif.c                          | function parameter                
io_uring_sqe     | opdef.c                   | command, size, flags                                             | io_openat_prep            | opdef.c                          | function parameter                
struct io_ring_ctx | io_uring.c               | context data, refcount, locks                                     | __io_openat_prep          | openclose.c                      | return value, function parameter  
struct file      | openclose.c               | file descriptors, flags, refcount                                 | fd_install               | io_uring.c                       | return value, function parameter  
struct io_ring_ctx | io_uring.c               | context, number of buffers                                        | io_buffer_select          | kbuf.c                           | return value, local variable      
struct io_buffer_list | kbuf.c                 | memory region, buffer data, refcount                              | io_buffer_get_list        | kbuf.c                           | local variable                    
struct io_buffer | kbuf.c                    | buffer data, flags, memory                                       | io_add_buffers            | kbuf.c                           | function parameter, local variable
refcount_t       | eventfd.c                 | refcount for eventfd, atomic counters                             | refcount_dec_and_test     | eventfd.c                        | local variable                    
struct io_eventfd | io_uring/eventfd.c        | eventfd context, eventfd file descriptor, refcount, rcu_head     | io_eventfd_free           | io_uring/eventfd.c               | function parameter, local variable
|                 |                           |                                                                  | io_eventfd_put            | io_uring/eventfd.c               | function parameter                
|                 |                           |                                                                  | io_eventfd_do_signal      | io_uring/eventfd.c               | local variable                    
|                 |                           |                                                                  | __io_eventfd_signal       | io_uring/eventfd.c               | function parameter                
|                 |                           |                                                                  | io_eventfd_grab           | io_uring/eventfd.c               | return value, local variable      
|                 |                           |                                                                  | io_eventfd_signal         | io_uring/eventfd.c               | local variable                    
|                 |                           |                                                                  | io_eventfd_flush_signal   | io_uring/eventfd.c               | local variable                    
|                 |                           |                                                                  | io_eventfd_register       | io_uring/eventfd.c               | local variable                    
|                 |                           |                                                                  | io_eventfd_unregister     | io_uring/eventfd.c               | function parameter                
io_kbuf_commit         | kbuf.c                    | req, bl, len, flags                                                | io_kbuf_commit            | kbuf.c                           | function parameter                
io_kbuf_recycle_legacy | kbuf.c                    | req, issue_flags                                                   | io_kbuf_recycle_legacy    | kbuf.c                           | function parameter                
io_kiocb_to_cmd        | advise.c                  | req, struct io_madvise                                             | io_kiocb_to_cmd           | advise.c                         | function parameter                
io_pbuf_get_region     | kbuf.c                    | ctx, region                                                      | io_pbuf_get_region        | kbuf.c                           | function parameter                
io_provide_buffers     | kbuf.c                    | req, issue_flags                                                   | io_provide_buffers        | kbuf.c                           | function parameter                
io_provide_buffers_prep| kbuf.c                    | req, sqe                                                          | io_provide_buffers_prep   | kbuf.c                           | function parameter                
io_provided_buffer_select| kbuf.c                  | req, len                                                          | io_provided_buffer_select | kbuf.c                           | function parameter                
io_provided_buffers_select| kbuf.c                 | req, len                                                          | io_provided_buffers_select| kbuf.c                           | function parameter                
io_put_bl              | kbuf.c                    | ctx, bl                                                           | io_put_bl                 | kbuf.c                           | function parameter                
__io_put_kbuf          | kbuf.c                    | req, len, issue_flags                                              | __io_put_kbuf             | kbuf.c                           | function parameter                
__io_put_kbuf_list     | kbuf.c                    | req, len, io_buffers_comp                                          | __io_put_kbuf_list        | kbuf.c                           | function parameter                
io_refill_buffer_cache | kbuf.c                    | ctx                                                               | io_refill_buffer_cache    | kbuf.c                           | function parameter                
io_region_get_ptr      | io_uring.c                | ctx, rings                                                         | io_region_get_ptr         | io_uring.c                       | function parameter                
io_register_pbuf_ring | kbuf.c                    | ctx, arg                                                           | io_register_pbuf_ring     | kbuf.c                           | function parameter                
io_register_pbuf_status| kbuf.c                    | ctx, arg                                                           | io_register_pbuf_status   | kbuf.c                           | function parameter                
__io_remove_buffers   | kbuf.c                    | ctx                                                               | __io_remove_buffers       | kbuf.c                           | function parameter                
io_remove_buffers     | kbuf.c                    | req, issue_flags                                                   | io_remove_buffers         | kbuf.c                           | function parameter                
io_remove_buffers_prep| kbuf.c                    | req, sqe                                                          | io_remove_buffers_prep    | kbuf.c                           | function parameter                
io_req_set_res        | advise.c                  | req, ret, 0                                                       | io_req_set_res            | advise.c                         | function parameter                
io_ring_buffer_select | kbuf.c                    | req, len                                                          | io_ring_buffer_select     | kbuf.c                           | function parameter                
io_ring_buffers_peek  | kbuf.c                    | req, arg                                                          | io_ring_buffers_peek      | kbuf.c                           | function parameter                
io_ring_head_to_buf   | kbuf.c                    | br, head, mask                                                    | io_ring_head_to_buf       | kbuf.c                           | function parameter                
io_ring_submit_lock   | cancel.c                  | ctx, issue_flags                                                   | io_ring_submit_lock       | cancel.c                         | function parameter                
io_ring_submit_unlock | cancel.c                  | ctx, issue_flags                                                   | io_ring_submit_unlock     | cancel.c                         | function parameter                
io_unregister_pbuf_ring| kbuf.c                   | ctx, arg                                                           | io_unregister_pbuf_ring   | kbuf.c                           | function parameter                
is_power_of_2         | kbuf.c                    | reg                                                               | is_power_of_2             | kbuf.c                           | function parameter                
kfree                 | alloc_cache.h             | *iov                                                              | kfree                     | alloc_cache.h                    | function parameter                
kmalloc_array         | kbuf.c                    | nr_avail, size                                                   | kmalloc_array             | kbuf.c                           | function parameter                
kmem_cache_alloc      | io_uring.c                | req_cachep, gfp                                                   | kmem_cache_alloc          | io_uring.c                       | function parameter                
kmem_cache_alloc_bulk | io_uring.c                | req_cachep, gfp, reqs                                             | kmem_cache_alloc_bulk     | io_uring.c                       | function parameter                
kmem_cache_free       | io_uring.c                | req_cachep, req                                                   | kmem_cache_free           | io_uring.c                       | function parameter                
kzalloc               | io-wq.c                   | worker                                                           | kzalloc                   | io-wq.c                          | function parameter                
likely                | io-wq.c                   | unbounded work                                                     | likely                    | io-wq.c                          | function parameter                
list_add              | kbuf.c                    | buf, bl                                                           | list_add                  | kbuf.c                           | function parameter                
list_add_tail         | io_uring.c                | ocqe, ctx                                                        | list_add_tail             | io_uring.c                       | function parameter                
list_del              | io_uring.c                | ocqe                                                              | list_del                  | io_uring.c                       | function parameter                
list_empty            | io-wq.c                   | wq->wait.entry                                                    | list_empty                | io-wq.c                          | function parameter                
list_empty_careful    | io-uring.c                | req, seq, defer_list                                               | list_empty_careful        | io-uring.c                       | function parameter                
list_entry            | kbuf.c                    | item, io_buffer                                                    | list_entry                | kbuf.c                           | function parameter                
list_first_entry      | io-uring.c                | ctx->defer_list                                                   | list_first_entry          | io-uring.c                       | function parameter                
list_for_each_safe    | kbuf.c                    | item, tmp, ctx->io_buffers_cache                                   | list_for_each_safe        | kbuf.c                           | function parameter                
list_move             | kbuf.c                    | nxt, ctx->io_buffers_cache                                        | list_move                 | kbuf.c                           | function parameter                
list_move_tail        | kbuf.c                    | buf, bl                                                           | list_move_tail            | kbuf.c                           | function parameter                
list_splice_init      | kbuf.c                    | ctx->io_buffers_comp, ctx->io_buffers_cache                       | list_splice_init          | kbuf.c                           | function parameter                
lockdep_assert_held   | futex.c                   | ctx->uring_lock                                                   | lockdep_assert_held       | futex.c                          | function parameter                
MAX_BIDS_PER_BGID     | kbuf.c                    | (1 << 16)                                                         | MAX_BIDS_PER_BGID         | kbuf.c                           | macro                             
memset                | alloc_cache.c             | obj, cache->init_clear                                            | memset                   | alloc_cache.c                    | function parameter                
min_not_zero          | kbuf.c                    | needed                                                            | min_not_zero              | kbuf.c                           | function parameter                
min_t                 | kbuf.c                    | tail, head, UIO_MAXIOV                                            | min_t                     | kbuf.c                           | function parameter                
PAGE_ALIGN            | io_uring.c                | size                                                              | PAGE_ALIGN                | io_uring.c                       | function parameter                
READ_ONCE            | advise.c                  | sqe->addr                                                         | READ_ONCE                | advise.c                         | function parameter                
req_set_fail          | advise.c                  | req                                                               | req_set_fail              | advise.c                         | function parameter                
scoped_guard          | kbuf.c                    | mutex, ctx->mmap_lock                                             | scoped_guard              | kbuf.c                           | function parameter                
sizeof                | alloc_cache.c             | cache->entries                                                    | sizeof                   | alloc_cache.c                    | function parameter                
smp_load_acquire      | io_uring.c                | tail                                                               | smp_load_acquire          | io_uring.c                       | function parameter                
spin_lock             | cancel.c                  | ctx->completion_lock                                               | spin_lock                 | cancel.c                         | function parameter                
spin_unlock           | cancel.c                  | ctx->completion_lock                                               | spin_unlock               | cancel.c                         | function parameter                
u64_to_user_ptr       | epoll.c                   | sqe->addr                                                         | u64_to_user_ptr           | epoll.c                          | function parameter                
unlikely              | cancel.c                  | req->flags & REQ_F_BUFFER_SELECT                                  | unlikely                  | cancel.c                         | function parameter                
WARN_ON_ONCE          | advise.c                  | issue_flags & IO_URING_F_NONBLOCK                                 | WARN_ON_ONCE              | advise.c                         | function parameter                
while                 | alloc_cache.c             | entry                                                            | while                     | alloc_cache.c                    | function parameter                
xa_erase              | kbuf.c                    | ctx->io_bl_xa, bl->bgid                                            | xa_erase                  | kbuf.c                           | function parameter                
xa_err                | kbuf.c                    | xa_store, ctx->io_bl_xa                                            | xa_err                    | kbuf.c                           | function parameter                
xa_find               | kbuf.c                    | ctx->io_bl_xa, index, ULONG_MAX                                    | xa_find                   | kbuf.c                           | function parameter                
xa_load               | io_uring.c                | ctx->personalities, personality                                   | xa_load                   | io_uring.c                       | function parameter                
xa_store              | kbuf.c                    | ctx->io_bl_xa, bgid, bl                                           | xa_store                  | kbuf.c                           | function parameter
uiov                    | compat_ptr(msg->msg_iov)                                         | struct msghdr, iov                                              | uiov_get_iov            | net.c                           | local variable                    
copy_from_user          | cancel.c                   | sc, arg, sizeof(sc)                                              | copy_from_user          | cancel.c                        | function parameter                
__copy_msghdr          | net.c                      | iomsg->msg, msg, NULL                                             | __copy_msghdr           | net.c                           | function parameter                
copy_to_user           | io_uring.c                 | params, p, sizeof(*p)                                            | copy_to_user            | io_uring.c                      | function parameter                
defined                | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | defined                 | advise.c                        | macro                            
do_accept              | net.c                      | req->file, &arg, accept->addr, accept->addr_len                   | do_accept               | net.c                           | function parameter                
fd_install             | io_uring.c                 | fd, file                                                         | fd_install              | io_uring.c                      | function parameter                
__get_compat_msghdr    | net.c                      | iomsg->msg, cmsg, NULL                                            | __get_compat_msghdr     | net.c                           | function parameter                
__get_unused_fd_flags  | net.c                      | accept->flags, accept->nofile                                     | __get_unused_fd_flags   | net.c                           | function parameter                
__get_user             | net.c                      | clen, uiov->iov_len                                               | __get_user              | net.c                           | function parameter                
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro                            
__import_iovec         | net.c                      | ddir, uiov, msg->msg_iovlen                                       | __import_iovec          | net.c                           | function parameter                
import_ubuf            | net.c                      | ITER_SOURCE, sr->buf, sr->len                                      | import_ubuf             | net.c                           | function parameter                
io_accept              | net.c                      | struct io_accept                                                  | io_accept               | net.c                           | struct definition                
io_accept_prep         | net.c                      | req, sqe                                                         | io_accept_prep          | net.c                           | function definition                
io_alloc_cache_kasan   | alloc_cache.h              | iov, nr                                                           | io_alloc_cache_kasan    | alloc_cache.h                   | function definition                
io_alloc_cache_put     | alloc_cache.h              | cache, io_alloc_cache                                              | io_alloc_cache_put      | alloc_cache.h                   | function definition                
io_alloc_notif         | net.c                      | zc->notif, io_alloc_notif(ctx)                                    | io_alloc_notif          | net.c                           | function definition                
io_bind                | net.c                      | struct io_bind                                                    | io_bind                 | net.c                           | struct definition                
io_bind_prep           | net.c                      | req, sqe                                                         | io_bind_prep            | net.c                           | function definition                
io_buffer_select       | kbuf.c                     | req, len                                                         | io_buffer_select        | kbuf.c                          | function definition                
io_buffers_peek        | kbuf.c                     | req, arg                                                         | io_buffers_peek         | kbuf.c                          | function definition                
io_buffers_select      | kbuf.c                     | req, arg                                                         | io_buffers_select       | kbuf.c                          | function definition                
io_bundle_nbufs        | net.c                      | kmsg, ret                                                         | io_bundle_nbufs         | net.c                           | function definition                
io_compat_msg_copy_hdr | net.c                      | req, kmsg                                                        | io_compat_msg_copy_hdr  | net.c                           | function definition                
io_connect             | net.c                      | struct io_connect                                                 | io_connect              | net.c                           | struct definition                
io_connect_prep        | net.c                      | req, sqe                                                         | io_connect_prep         | net.c                           | function definition                
io_do_buffer_select    | kbuf.h                     | req                                                              | io_do_buffer_select     | kbuf.h                          | inline function definition        
io_fixed_fd_install    | filetable.c                | error value, fd                                                    | io_fixed_fd_install     | filetable.c                     | function definition                
io_import_fixed        | net.c                      | kmsg->msg.msg_iter                                                | io_import_fixed         | net.c                           | function definition                
io_kbuf_recycle        | io_uring.c                 | req, 0                                                            | io_kbuf_recycle         | io_uring.c                      | function definition                
io_kiocb_to_cmd        | advise.c                   | req, struct io_madvise                                             | io_kiocb_to_cmd         | advise.c                        | function definition                
io_listen              | net.c                      | struct io_listen                                                  | io_listen               | net.c                           | struct definition                
io_listen_prep         | net.c                      | req, sqe                                                         | io_listen_prep          | net.c                           | function definition                
io_msg_alloc_async     | net.c                      | req                                                              | io_msg_alloc_async      | net.c                           | function definition                
io_msg_copy_hdr        | net.c                      | req, iomsg                                                       | io_msg_copy_hdr         | net.c                           | function definition                
io_mshot_prep_retry    | net.c                      | req                                                              | io_mshot_prep_retry     | net.c                           | inline function definition        
io_netmsg_cache_free   | io_uring.c                 | ctx->netmsg_cache, io_netmsg_cache_free                           | io_netmsg_cache_free    | io_uring.c                      | function definition                
io_netmsg_iovec_free   | net.c                      | kmsg                                                             | io_netmsg_iovec_free    | net.c                           | function definition                
io_netmsg_recycle      | net.c                      | req, issue_flags                                                  | io_netmsg_recycle       | net.c                           | function definition                
io_net_retry           | net.c                      | sock, flags                                                       | io_net_retry            | net.c                           | function definition                
io_net_vec_assign      | net.c                      | req, kmsg                                                         | io_net_vec_assign       | net.c                           | function definition                
io_notif_account_mem   | net.c                      | sr->notif, sr->len                                                 | io_notif_account_mem    | net.c                           | function definition                
io_notif_flush         | net.c                      | iFile: ./fdinfo.c                                                 | io_notif_flush          | net.c                           | function definition                
common_tracking_show_fdinfo | fdinfo.c               | ctx->ring_ctx                                                     | common_tracking_show_fdinfo | fdinfo.c                    | function definition                
for                    | Makefile                   | io_uring                                                           | for                     | Makefile                        | loop structure                    
from_kgid_munged      | fdinfo.c                   | cred->gid                                                          | from_kgid_munged        | fdinfo.c                        | function definition                
from_kuid_munged      | fdinfo.c                   | cred->uid                                                          | from_kuid_munged        | fdinfo.c                        | function definition                
getrusage              | fdinfo.c                   | sq->thread, RUSAGE_SELF                                            | getrusage               | fdinfo.c                        | function definition                
hlist_for_each_entry   | fdinfo.c                   | req, hb->list, hash_node                                           | hlist_for_each_entry    | fdinfo.c                        | function definition                
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro                            
io_slot_file          | cancel.c                   | cd->file                                                          | io_slot_file            | cancel.c                        | function definition                
io_uring_get_opcode   | fdinfo.c                   | sq_idx, io_uring_get_opcode(sqe->opcode), sqe->fd                  | io_uring_get_opcode     | fdinfo.c                        | function definition                
io_uring_show_cred    | fdinfo.c                   | m, id                                                             | io_uring_show_cred      | fdinfo.c                        | function definition                
io_uring_show_fdinfo  | fdinfo.c                   | m, file                                                           | io_uring_show_fdinfo    | fdinfo.c                        | function definition                
list_for_each_entry   | cancel.c                   | node, ctx->tctx_list, ctx_node                                     | list_for_each_entry     | cancel.c                        | function definition                
min                    | fdinfo.c                   | sq_tail - sq_head, ctx->sq_entries                                 | min                     | fdinfo.c                        | function definition                
mode                   | epoll.c                    | issue_flags, non-blocking mode                                    | mode                    | epoll.c                         | function definition                
mutex_trylock         | fdinfo.c                   | ctx->uring_lock                                                    | mutex_trylock           | fdinfo.c                        | function definition                
mutex_unlock          | cancel.c                   | ctx->uring_lock                                                    | mutex_unlock            | cancel.c                        | function definition                
napi_show_fdinfo      | fdinfo.c                   | ctx->ring_ctx                                                     | napi_show_fdinfo        | fdinfo.c                        | function definition                
READ_ONCE             | advise.c                   | sqe->addr                                                          | READ_ONCE               | advise.c                        | function definition                
seq_file_path         | fdinfo.c                   | m, f, " \t\n\\"                                                    | seq_file_path           | fdinfo.c                        | function definition                
seq_printf            | fdinfo.c                   | m, "%5d\n", id                                                     | seq_printf              | fdinfo.c                        | function definition                
seq_putc              | fdinfo.c                   | m, '\n'                                                           | seq_putc                | fdinfo.c                        | function definition                
seq_put_decimal_ull   | fdinfo.c                   | m, "\tUid:\t", from_kuid_munged(uns, cred->uid)                    | seq_put_decimal_ull     | fdinfo.c                        | function definition                
seq_put_hex_ll        | fdinfo.c                   | m, NULL, cap.val, 16                                               | seq_put_hex_ll          | fdinfo.c                        | function definition                
seq_puts              | fdinfo.c                   | m, "\n\tGroups:\t"                                                 | seq_puts                | fdinfo.c                        | function definition                
seq_user_ns           | fdinfo.c                   | uns = seq_user_ns(m)                                               | seq_user_ns             | fdinfo.c                        | function definition                
sizeof                | alloc_cache.c              | cache->entries                                                     | sizeof                  | alloc_cache
spin_unlock            | cancel.c                   | &ctx->completion_lock                                            | spin_unlock             | cancel.c                        | function call                   
switch                 | advise.c                   | fa->advice                                                       | switch                  | advise.c                        | conditional branch             
task_work_pending      | fdinfo.c                   | req->tctx->task                                                   | task_work_pending       | fdinfo.c                        | function call                   
xa_empty               | fdinfo.c                   | !xa_empty(&ctx->personalities)                                    | xa_empty                | fdinfo.c                        | function call                   
xa_for_each            | fdinfo.c                   | &ctx->personalities, index, cred                                  | xa_for_each             | fdinfo.c                        | function call                   
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro                          
io_file_get_fixed      | cancel.c                   | req, cancel->fd                                                   | io_file_get_fixed       | cancel.c                        | function call                   
io_file_get_normal     | cancel.c                   | req, cancel->fd                                                   | io_file_get_normal      | cancel.c                        | function call                   
io_kiocb_to_cmd        | advise.c                   | req, struct io_madvise                                            | io_kiocb_to_cmd         | advise.c                        | function call                   
io_nop                 | nop.c                      | struct io_nop                                                     | io_nop                  | nop.c                           | struct definition              
io_nop_prep            | nop.c                      | req, sqe                                                          | io_nop_prep             | nop.c                           | function definition             
io_req_assign_buf_node | net.c                      | sr->notif, node                                                   | io_req_assign_buf_node  | net.c                           | function call                   
io_req_set_res         | advise.c                   | req, ret, 0                                                       | io_req_set_res          | advise.c                        | function call                   
io_ring_submit_lock    | cancel.c                   | ctx, issue_flags                                                  | io_ring_submit_lock     | cancel.c                        | function call                   
io_ring_submit_unlock  | cancel.c                   | ctx, issue_flags                                                  | io_ring_submit_unlock   | cancel.c                        | function call                   
io_rsrc_node_lookup    | cancel.c                   | &ctx->file_table.data, fd                                          | io_rsrc_node_lookup     | cancel.c                        | function call            
NOP_FLAGS              | nop.c                      | IORING_NOP_INJECT_RESULT, IORING_NOP_FIXED_FILE                   | NOP_FLAGS               | nop.c                           | macro                          
READ_ONCE              | advise.c                   | sqe->addr                                                         | READ_ONCE               | advise.c                        | function call                   
req_set_fail           | advise.c                   | req                                                               | req_set_fail            | advise.c                        | function call                   
ACCEPT_FLAGS             | net.c                 | IORING_ACCEPT_MULTISHOT, IORING_ACCEPT_DONTWAIT, ...             | ACCEPT_FLAGS             | net.c                 | macro
access_ok               | kbuf.c               | u64_to_user_ptr(p->addr), size                                   | access_ok               | kbuf.c               | function call
again                   | eventfd.c            | ev_fd exists, io_eventfd_unregister                              | again                   | eventfd.c            | comment
BUILD_BUG_ON            | io-wq.c              | IO_WQ_ACCT_BOUND, IO_WQ_BOUND                                    | BUILD_BUG_ON            | io-wq.c              | macro
bvec_iter_advance_single| net.c                | from->bvec, &bi, v.bv_len                                        | bvec_iter_advance_single| net.c                | function call
check_add_overflow      | filetable.c          | range.off, range.len, &end                                       | check_add_overflow      | filetable.c          | function call
compat_ptr              | net.c                | o_notif_flush(zc->notif)                                         | compat_ptr              | net.c                | macro or helper
io_notif_to_data        | net.c                | notif                                                            | io_notif_to_data        | net.c                | function call
io_put_kbuf             | io_uring.c           | req, res, IO_URING_F_UNLOCKED                                    | io_put_kbuf             | io_uring.c           | function call
io_put_kbufs            | kbuf.h               | req, len                                                         | io_put_kbufs            | kbuf.h               | inline function    
io_recv                    | net.c        | * Finishes io_recv and io_recvmsg.                   | io_recv                    | net.c             | function comment
io_recv_buf_select        | net.c        | req, kmsg                                           | io_recv_buf_select        | net.c             | function definition
io_recv_finish            | net.c        | req, ret                                            | io_recv_finish            | net.c             | function definition
io_recvmsg                | net.c        | * Finishes io_recv and io_recvmsg.                  | io_recvmsg                | net.c             | function comment
io_recvmsg_copy_hdr       | net.c        | req                                                 | io_recvmsg_copy_hdr       | net.c             | function definition
io_recvmsg_mshot_prep     | net.c        | req                                                 | io_recvmsg_mshot_prep     | net.c             | function definition
io_recvmsg_multishot      | net.c        | sock, io                                            | io_recvmsg_multishot      | net.c             | function definition
io_recvmsg_prep           | net.c        | req, sqe                                            | io_recvmsg_prep           | net.c             | function definition
io_recvmsg_prep_multishot | net.c        | kmsg                                               | io_recvmsg_prep_multishot | net.c             | function definition
io_recvmsg_prep_setup     | net.c        | req                                                 | io_recvmsg_prep_setup     | net.c             | function definition
io_req_assign_buf_node    | net.c        | sr->notif, node                                     | io_req_assign_buf_node    | net.c             | function call
io_req_msg_cleanup        | net.c        | req                                                 | io_req_msg_cleanup        | net.c             | function definition
io_req_post_cqe           | io_uring.c   | req, res, cflags                                    | io_req_post_cqe           | io_uring.c        | function definition
io_req_set_res            | advise.c     | req, ret, 0                                         | io_req_set_res            | advise.c          | function call
io_ring_submit_lock       | cancel.c     | ctx, issue_flags                                    | io_ring_submit_lock       | cancel.c          | function call
io_ring_submit_unlock     | cancel.c     | ctx, issue_flags                                    | io_ring_submit_unlock     | cancel.c          | function call
io_rsrc_node_lookup       | cancel.c     | &ctx->file_table.data, fd                           | io_rsrc_node_lookup       | cancel.c          | function call
io_send                   | net.c        | req, issue_flags                                    | io_send                   | net.c             | function definition
io_send_finish            | net.c        | req, ret                                            | io_send_finish            | net.c             | function definition
io_sendmsg                | net.c        | req, issue_flags                                    | io_sendmsg                | net.c             | function definition
io_sendmsg_copy_hdr       | net.c        | req                                                 | io_sendmsg_copy_hdr       | net.c             | function definition
io_sendmsg_prep           | net.c        | req, sqe                                            | io_sendmsg_prep           | net.c             | function definition
io_sendmsg_recvmsg_cleanup| net.c        | req                                                 | io_sendmsg_recvmsg_cleanup| net.c             | function definition
io_sendmsg_setup          | net.c        | req, sqe                                            | io_sendmsg_setup          | net.c             | function definition
io_sendmsg_zc             | net.c        | req, issue_flags                                    | io_sendmsg_zc             | net.c             | function definition
io_sendrecv_fail          | net.c        | req                                                 | io_sendrecv_fail          | net.c             | function definition
io_send_select_buffer     | net.c        | req, issue_flags                                    | io_send_select_buffer     | net.c             | function definition
io_send_setup             | net.c        | req, sqe                                            | io_send_setup             | net.c             | function definition
io_send_zc                | net.c        | req, issue_flags                                    | io_send_zc                | net.c             | function definition   
io_send_zc_cleanup        | net.c        | req                                                  | io_send_zc_cleanup        | net.c             | function definition
io_send_zc_import         | net.c        | req, issue_flags                                     | io_send_zc_import         | net.c             | function definition
io_send_zc_prep           | net.c        | req, sqe                                             | io_send_zc_prep           | net.c             | function definition
io_sg_from_iter           | net.c        | skb                                                  | io_sg_from_iter           | net.c             | function definition
io_sg_from_iter_iovec     | net.c        | skb                                                  | io_sg_from_iter_iovec     | net.c             | function definition
io_shutdown               | net.c        | struct io_shutdown                                   | io_shutdown               | net.c             | struct definition
io_shutdown_prep          | net.c        | req, sqe                                             | io_shutdown_prep          | net.c             | function definition
io_socket                 | net.c        | struct io_socket                                     | io_socket                 | net.c             | struct definition
io_socket_prep            | net.c        | req, sqe                                             | io_socket_prep            | net.c             | function definition
io_uring_alloc_async_data | io_uring.h   | cache                                                | io_uring_alloc_async_data | io_uring.h        | function definition
iov_iter_count            | net.c        | &kmsg->msg.msg_iter                                  | iov_iter_count            | net.c             | function call
iov_iter_init             | net.c        | &kmsg->msg.msg_iter, ITER_SOURCE                     | iov_iter_init             | net.c             | function call
iov_iter_ubuf             | net.c        | &kmsg->msg.msg_iter, ITER_DEST, buf, len            | iov_iter_ubuf             | net.c             | function call
IO_ZC_FLAGS_COMMON        | net.c        | IORING_RECVSEND_POLL_FIRST, IORING_RECVSEND_FIXED_BUF | IO_ZC_FLAGS_COMMON        | net.c             | macro
IO_ZC_FLAGS_VALID         | net.c        | IO_ZC_FLAGS_COMMON, IORING_SEND_ZC_REPORT_USAGE     | IO_ZC_FLAGS_VALID         | net.c             | macro
IS_ERR                    | eventfd.c    | ev_fd->cq_ev_fd                                      | IS_ERR                    | eventfd.c         | macro
iter_iov                  | net.c        | &kmsg->msg.msg_iter                                  | iter_iov                  | net.c             | function call
iter_is_ubuf              | net.c        | &kmsg->msg.msg_iter                                  | iter_is_ubuf              | net.c             | function call
kfree                     | alloc_cache.h| *iov                                                 | kfree                     | alloc_cache.h     | function call
min                       | fdinfo.c     | sq_tail - sq_head, ctx->sq_entries                   | min                       | fdinfo.c          | macro
min_not_zero              | kbuf.c       | needed, PEEK_MAX_IMPORT                              | min_not_zero              | kbuf.c            | macro
min_t                     | kbuf.c       | tail - head, UIO_MAXIOV                              | min_t                     | kbuf.c            | macro
move_addr_to_kernel       | net.c        | addr, addr_len, &kmsg->addr                          | move_addr_to_kernel       | net.c             | function call
mp_bvec_iter_bvec         | net.c        | from->bvec, bi                                       | mp_bvec_iter_bvec         | net.c             | function call
offsetof                 | io_uring.c   | struct io_async_msghdr, clear                        | offsetof                 | io_uring.c        | macro
PAGE_ALIGN               | io_uring.c   | size                                                 | PAGE_ALIGN               | io_uring.c        | macro
PTR_ERR                  | eventfd.c    | ev_fd->cq_ev_fd                                      | PTR_ERR                  | eventfd.c         | macro
put_unused_fd            | net.c        | fd                                                   | put_unused_fd            | net.c             | function call
READ_ONCE                | advise.c     | sqe->addr                                            | READ_ONCE                | advise.c          | function call
RECVMSG_FLAGS            | net.c        | IORING_RECVSEND_POLL_FIRST, IORING_RECV_MULTISHOT, ... | RECVMSG_FLAGS            | net.c             | macro
req_has_async_data       | io_uring.h   | req                                                  | req_has_async_data       | io_uring.h        | function definition
req_set_fail             | advise.c     | req                                                  | req_set_fail             | advise.c          | function call
rlimit                   | net.c        | RLIMIT_NOFILE                                        | rlimit                   | net.c             | function call
s                        | cancel.c     | slow path comment                                    | s                        | cancel.c          | comment
SENDMSG_FLAGS            | net.c        | IORING_RECVSEND_POLL_FIRST, IORING_RECVSEND_BUNDLE   | SENDMSG_FLAGS            | net.c             | macro
sizeof                   | alloc_cache.c| void *                                               | sizeof                   | alloc_cache.c     | macro
__skb_fill_page_desc_noacc| net.c       | shinfo, frag++, v.bv_page                            | __skb_fill_page_desc_noacc| net.c             | function call
skb_shinfo               | net.c        | skb                                                  | skb_shinfo               | net.c             | function call
skb_zcopy_downgrade_managed| net.c      | skb                                                  | skb_zcopy_downgrade_managed| net.c           | function call
skb_zcopy_managed        | net.c        | skb                                                  | skb_zcopy_managed        | net.c             | function call
sock_error               | net.c        | sock_error()                                         | sock_error               | net.c             | function call
sock_from_file           | napi.h       | req->file                                            | sock_from_file           | napi.h            | function call
sock_recvmsg             | net.c        | sock, &kmsg->msg, flags                              | sock_recvmsg             | net.c             | function call
sock_sendmsg             | net.c        | sock, &kmsg->msg                                     | sock_sendmsg             | net.c             | function call
__sys_bind_socket        | net.c        | sock, &io->addr, bind->addr_len                      | __sys_bind_socket        | net.c             | function call
__sys_connect_file       | net.c        | req->file, &io->addr, connect->addr_len              | __sys_connect_file       | net.c             | function call
__sys_listen_socket      | net.c        | sock, listen->backlog                                | __sys_listen_socket      | net.c             | function call
__sys_recvmsg_sock       | net.c        | sock, &kmsg->msg, sr->umsg                           | __sys_recvmsg_sock       | net.c             | function call
sys_sendmsg              | net.c        | comment: sys_sendmsg() overwrites it                 | sys_sendmsg              | net.c             | comment
__sys_sendmsg_sock       | net.c        | sock, &kmsg->msg, flags                              | __sys_sendmsg_sock       | net.c             | function call
__sys_shutdown_sock       | net.c        | sock, shutdown->how                                    | __sys_shutdown_sock       | net.c             | function call
__sys_socket_file         | net.c        | sock->domain, sock->type, sock->protocol               | __sys_socket_file         | net.c             | function call
test_bit                  | filetable.h  | bit, table->bitmap                                     | test_bit                  | filetable.h       | macro
u64_to_user_ptr           | epoll.c      | READ_ONCE(sqe->addr)                                   | u64_to_user_ptr           | epoll.c           | function call
unlikely                  | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                      | unlikely                  | cancel.c          | macro
unsafe_get_user           | io_uring.c   | arg.sigmask, &uarg->sigmask, uaccess_end               | unsafe_get_user           | io_uring.c        | function call
user_access_begin         | io_uring.c   | uarg, sizeof(*uarg)                                    | user_access_begin         | io_uring.c        | function call
user_access_end           | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | user_access_end           | advise.c          | function call
while                     | alloc_cache.c| io_alloc_cache_get(cache) != NULL                      | while                     | alloc_cache.c     | loop
zerocopy_fill_skb_from_iter| net.c        | skb, from, length                                      | zerocopy_fill_skb_from_iter| net.c            | function call
add_wait_queue            | poll.c       | head, &poll->wait                                      | add_wait_queue            | poll.c            | function call
atomic_fetch_inc          | poll.c       | &req->poll_refs                                        | atomic_fetch_inc          | poll.c            | function call
atomic_or                 | io-wq.c      | IO_WQ_WORK_CANCEL, &work->flags                        | atomic_or                 | io-wq.c           | function call
atomic_read               | io-wq.c      | &work->flags                                           | atomic_read               | io-wq.c           | function call
atomic_set                | eventfd.c    | &ev_fd->ops, 0                                         | atomic_set                | eventfd.c         | function call
atomic_sub_return         | poll.c       | v, &req->poll_refs                                     | atomic_sub_return         | poll.c            | function call
BIT                       | eventfd.c    | BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops             | BIT                       | eventfd.c         | macro
container_of              | cancel.c     | work, struct io_kiocb, work                            | container_of              | cancel.c          | macro
__do_wait                 | waitid.c     | &iwa->wo                                               | __do_wait                 | waitid.c          | function call
GENMASK                   | poll.c       | IO_POLL_REF_MASK (29, 0)                               | GENMASK                   | poll.c            | macro
hlist_add_head            | io_uring.c   | user_access_end()                                      | hlist_add_head            | io_uring.c        | function call
WARN_ON_ONCE              | afutex.c     | hlist_add_head(&req->hash_node, &ctx->futex_list)      | WARN_ON_ONCE              | afutex.c          | macro
hlist_del_init            | futex.c      | &req->hash_node                                        | hlist_del_init            | futex.c           | function call
hlist_for_each_entry_safe | futex.c      | req, tmp, &ctx->futex_list, hash_node                 | hlist_for_each_entry_safe | futex.c           | function call
if                        | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                        | advise.c          | conditional
init_waitqueue_func_entry | io_uring.c   | &iowq.wq, io_wake_function                            | init_waitqueue_func_entry | io_uring.c        | function call
io_kiocb_to_cmd           | advise.c     | req, struct io_madvise                                 | io_kiocb_to_cmd           | advise.c          | function call
io_match_task_safe        | futex.c      | req, tctx, cancel_all                                  | io_match_task_safe        | futex.c           | function call
io_req_queue_tw_complete  | io_uring.h   | req, res                                               | io_req_queue_tw_complete  | io_uring.h        | function definition
io_req_set_res            | advise.c     | req, ret, 0                                            | io_req_set_res            | advise.c          | function call
io_req_task_complete      | futex.c      | req, ts                                                | io_req_task_complete      | futex.c           | function call
io_req_task_work_add      | futex.c      | req                                                    | io_req_task_work_add      | futex.c           | function call
io_ring_submit_lock       | cancel.c     | ctx, issue_flags                                        | io_ring_submit_lock       | cancel.c          | function call
io_ring_submit_unlock     | cancel.c     | ctx, issue_flags                                        | io_ring_submit_unlock     | cancel.c          | function call
io_tw_lock                | futex.c      | ctx, ts                                                 | io_tw_lock                | futex.c           | function call
io_uring_alloc_async_data | io_uring.h   | cache                                                  | io_uring_alloc_async_data | io_uring.h        | function definition
io_waitid                 | opdef.c      | issue = io_waitid                                       | io_waitid                 | opdef.c           | function call
__io_waitid_cancel        | waitid.c     | ctx, req                                               | __io_waitid_cancel        | waitid.c          | function definition
io_waitid_cancel          | cancel.c     | ctx, cd, issue_flags                                    | io_waitid_cancel          | cancel.c          | function call
io_waitid_cb              | waitid.c     | req, ts                                                 | io_waitid_cb              | waitid.c          | function definition
io_waitid_compat_copy_si  | waitid.c     | iw, signo                                              | io_waitid_compat_copy_si  | waitid.c          | function definition
io_waitid_complete        | waitid.c     | req, ret                                                | io_waitid_complete        | waitid.c          | function definition
io_waitid_copy_si         | waitid.c     | req, signo                                              | io_waitid_copy_si         | waitid.c          | function definition
io_waitid_drop_issue_ref  | waitid.c     | req                                                    | io_waitid_drop_issue_ref  | waitid.c          | function definition
io_waitid_finish          | waitid.c     | req, ret                                                | io_waitid_finish          | waitid.c          | function definition
io_waitid_free            | waitid.c     | req                                                    | io_waitid_free            | waitid.c          | function definition
io_waitid_prep            | opdef.c      | prep = io_waitid_prep                                   | io_waitid_prep            | opdef.c           | function call
io_waitid_remove_all      | io_uring.c   | ctx, tctx, cancel_all                                  | io_waitid_remove_all      | io_uring.c        | function call
io_waitid_wait            | waitid.c     | wait, mode                                              | io_waitid_wait            | waitid.c          | function definition
kernel_waitid_prepare      | waitid.c     | &iwa->wo, iw->which, iw->upid, &iw->info               | kernel_waitid_prepare      | waitid.c          | function call
kfree                      | alloc_cache.h| *iov                                                    | kfree                      | alloc_cache.h     | function call
list_del_init              | io-wq.c      | &wq->wait.entry                                          | list_del_init              | io-wq.c           | function call
lockdep_assert_held        | futex.c      | &ctx->uring_lock                                         | lockdep_assert_held        | futex.c           | function call
pid_child_should_wake     | waitid.c     | wo, p                                                   | pid_child_should_wake     | waitid.c          | function call
put_pid                    | waitid.c     | iwa->wo.wo_pid                                           | put_pid                    | waitid.c          | function call
READ_ONCE                  | advise.c     | sqe->addr                                               | READ_ONCE                  | advise.c          | macro
remove_wait_queue          | waitid.c     | iw->head, &iwa->wo.child_wait                           | remove_wait_queue          | waitid.c          | function call
req_set_fail               | advise.c     | req                                                     | req_set_fail               | advise.c          | function call
sizeof                     | alloc_cache.c| cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                     | alloc_cache.c     | operator
spin_lock_irq              | io-wq.c      | &wq->hash->wait.lock                                     | spin_lock_irq              | io-wq.c           | function call
spin_unlock_irq            | io-wq.c      | &wq->hash->wait.lock                                     | spin_unlock_irq            | io-wq.c           | function call
u64_to_user_ptr            | epoll.c      | READ_ONCE(sqe->addr)                                     | u64_to_user_ptr            | epoll.c           | function call
unlikely                   | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                        | unlikely                   | cancel.c          | macro
unsafe_put_user            | waitid.c     | signo, &infop->si_signo, Efault                         | unsafe_put_user            | waitid.c          | function call
user_write_access_begin    | waitid.c     | infop, sizeof(*infop)                                    | user_write_access_begin    | waitid.c          | function call
user_write_access_end      | waitid.c     |                                                         | user_write_access_end      | waitid.c          | function call
WARN_ON_ONCE               | advise.c     | issue_flags & IO_URING_F_NONBLOCK                        | WARN_ON_ONCE               | advise.c          | macro
atomic_fetch_or            | eventfd.c    | BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops               | atomic_fetch_or            | eventfd.c         | function call
atomic_set                 | eventfd.c    | &ev_fd->ops, 0                                           | atomic_set                 | eventfd.c         | function call
BIT                        | eventfd.c    | BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops               | BIT                        | eventfd.c         | macro
call_rcu                   | eventfd.c    | &ev_fd->rcu, io_eventfd_free                            | call_rcu                   | eventfd.c         | function call
call_rcu_hurry             | eventfd.c    | &ev_fd->rcu, io_eventfd_do_signal                       | call_rcu_hurry             | eventfd.c         | function call
container_of               | cancel.c     | work, struct io_kiocb, work                              | container_of               | cancel.c          | macro
copy_from_user             | cancel.c     | &sc, arg, sizeof(sc)                                     | copy_from_user             | cancel.c          | function call
eventfd_ctx_fdget          | eventfd.c    | fd                                                      | eventfd_ctx_fdget          | eventfd.c         | function call
eventfd_ctx_put            | eventfd.c    | ev_fd->cq_ev_fd                                          | eventfd_ctx_put            | eventfd.c         | function call
eventfd_signal_allowed     | eventfd.c    |                                                         | eventfd_signal_allowed     | eventfd.c         | function call
eventfd_signal_mask        | eventfd.c    | ev_fd->cq_ev_fd, EPOLL_URING_WAKE                       | eventfd_signal_mask        | eventfd.c         | function call
if                         | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                      | if                         | advise.c          | conditional
io_eventfd_do_signal       | eventfd.c    | rcu                                                     | io_eventfd_do_signal       | eventfd.c         | function definition
io_eventfd_flush_signal    | eventfd.c    | ctx                                                     | io_eventfd_flush_signal    | eventfd.c         | function call
io_eventfd_free            | eventfd.c    | rcu                                                     | io_eventfd_free            | eventfd.c         | function definition
io_eventfd_grab            | eventfd.c    | ctx                                                     | io_eventfd_grab            | eventfd.c         | function definition
io_eventfd_put             | eventfd.c    | ev_fd                                                   | io_eventfd_put             | eventfd.c         | function definition
io_eventfd_register        | eventfd.c    | ctx, arg                                                 | io_eventfd_register        | eventfd.c         | function call
io_eventfd_release         | eventfd.c    | ev_fd, bool put_ref                                      | io_eventfd_release         | eventfd.c         | function definition
__io_eventfd_signal        | eventfd.c    | ev_fd                                                    | __io_eventfd_signal        | eventfd.c         | function definition
io_eventfd_signal          | eventfd.c    | ctx                                                     | io_eventfd_signal          | eventfd.c         | function call
io_eventfd_trigger         | eventfd.c    | ev_fd                                                    | io_eventfd_trigger         | eventfd.c         | function definition
io_eventfd_unregister      | eventfd.c    | ev_fd                                                     | io_eventfd_unregister      | eventfd.c         | function call
io_wq_current_is_worker    | cancel.c     | tctx != current->io_uring                               | io_wq_current_is_worker    | cancel.c          | function call
IS_ERR                     | eventfd.c    | ev_fd->cq_ev_fd                                          | IS_ERR                     | eventfd.c         | macro
kfree                      | alloc_cache.h| *iov                                                     | kfree                      | alloc_cache.h     | function call
kmalloc                    | alloc_cache.c| cache->elem_size, gfp                                    | kmalloc                    | alloc_cache.c     | function call
lockdep_is_held            | eventfd.c    | &ctx->uring_lock                                          | lockdep_is_held            | eventfd.c         | function call
PTR_ERR                    | eventfd.c    | ev_fd->cq_ev_fd                                          | PTR_ERR                    | eventfd.c         | function call
rcu_assign_pointer         | eventfd.c    | ctx->io_ev_fd, ev_fd                                      | rcu_assign_pointer         | eventfd.c         | function call
rcu_dereference            | eventfd.c    | ctx->io_ev_fd                                            | rcu_dereference            | eventfd.c         | function call
rcu_dereference_protected  | eventfd.c    | ctx->io_ev_fd, ...                                      | rcu_dereference_protected  | eventfd.c         | function call
rcu_read_lock              | eventfd.c    |                                                         | rcu_read_lock              | eventfd.c         | function call
rcu_read_unlock            | eventfd.c    |                                                         | rcu_read_unlock            | eventfd.c         | function call
READ_ONCE                  | advise.c     | sqe->addr                                               | READ_ONCE                  | advise.c          | macro
refcount_dec_and_test      | eventfd.c    | &ev_fd->refs                                             | refcount_dec_and_test      | eventfd.c         | function call
refcount_inc_not_zero      | eventfd.c    | &ev_fd->refs                                             | refcount_inc_not_zero      | eventfd.c         | function call
refcount_set               | eventfd.c    | &ev_fd->refs, 1                                          | refcount_set               | eventfd.c         | function call
sizeof                     | alloc_cache.c| cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                     | alloc_cache.c     | operator
spin_lock                  | cancel.c     | &ctx->completion_lock                                    | spin_lock                  | cancel.c          | function call
spin_unlock                | cancel.c     | &ctx->completion_lock                                    | spin_unlock                | cancel.c          | function call
bitmap_free                | filetable.c  | table->bitmap                                            | bitmap_free                | filetable.c       | function call
bitmap_zalloc              | filetable.c  | nr_files, GFP_KERNEL_ACCOUNT                             | bitmap_zalloc              | filetable.c       | function call
check_add_overflow         | filetable.c  | range.off, range.len, &end                               | check_add_overflow         | filetable.c       | function call
copy_from_user             | cancel.c     | &sc, arg, sizeof(sc)                                     | copy_from_user             | cancel.c          | function call
find_next_zero_bit         | filetable.c  | table->bitmap, nr, table->alloc_hint                     | find_next_zero_bit         | filetable.c       | function call
fput                       | cancel.c     | file                                                    | fput                       | cancel.c          | function call
if                         | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                      | if                         | advise.c          | conditional
io_alloc_file_tables       | filetable.c  | ctx, table                                               | io_alloc_file_tables       | filetable.c       | function definition
io_file_bitmap_clear       | filetable.c  | &ctx->file_table, offset                                 | io_file_bitmap_clear       | filetable.c       | function call
io_file_bitmap_get         | filetable.c  | ctx                                                     | io_file_bitmap_get         | filetable.c       | function call
io_file_bitmap_set         | filetable.c  | &ctx->file_table, slot_index                             | io_file_bitmap_set         | filetable.c       | function call
io_file_table_set_alloc_range | filetable.c | ctx, range.off, range.len                                | io_file_table_set_alloc_range | filetable.c    | function call
__io_fixed_fd_install      | filetable.c  | ctx, file                                                | __io_fixed_fd_install      | filetable.c       | function definition
io_fixed_fd_install        | filetable.c  | error value                                             | io_fixed_fd_install        | filetable.c       | function call
io_fixed_fd_remove         | filetable.c  | ctx, offset                                              | io_fixed_fd_remove         | filetable.c       | function definition
io_fixed_file_set          | filetable.c  | node, file                                               | io_fixed_file_set          | filetable.c       | function call
io_free_file_tables        | filetable.c  | ctx, table                                               | io_free_file_tables        | filetable.c       | function definition
io_install_fixed_file      | filetable.c  | ctx, file                                                | io_install_fixed_file      | filetable.c       | function call
io_is_uring_fops           | filetable.c  | file                                                    | io_is_uring_fops           | filetable.c       | function call
io_register_file_alloc_range | filetable.c | ctx, ...                                                 | io_register_file_alloc_range | filetable.c    | function call
io_reset_rsrc_node         | filetable.c  | ctx, &ctx->file_table.data, slot_index                   | io_reset_rsrc_node         | filetable.c       | function call
io_ring_submit_lock        | cancel.c     | ctx, issue_flags                                          | io_ring_submit_lock        | cancel.c          | function call
io_ring_submit_unlock      | cancel.c     | ctx, issue_flags                                          | io_ring_submit_unlock      | cancel.c          | function call
io_rsrc_data_alloc         | filetable.c  | &table->data, nr_files                                    | io_rsrc_data_alloc         | filetable.c       | function call
io_rsrc_data_free          | filetable.c  | ctx, &table->data                                         | io_rsrc_data_free          | filetable.c       | function call
io_rsrc_node_alloc         | filetable.c  | IORING_RSRC_FILE                                          | io_rsrc_node_alloc         | filetable.c       | function call
io_rsrc_node_lookup        | cancel.c     | &ctx->file_table.data, fd                                 | io_rsrc_node_lookup        | cancel.c          | function call
__must_hold                | cancel.c     | &ctx->uring_lock                                          | __must_hold                | cancel.c          | function call
sizeof                     | alloc_cache.c| cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                     | alloc_cache.c     | operator
unlikely                   | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                        | unlikely                   | cancel.c          | macro
while                      | alloc_cache.c| entry = io_alloc_cache_get(cache)                        | while                      | alloc_cache.c     | loop
do_statx                    | statx.c      | sx->dfd, sx->filename, sx->flags, sx->mask, sx->buffer | do_statx                    | statx.c           | function call
getname_uflags               | fs.c         | oldf, lnk->flags                                         | getname_uflags               | fs.c              | function call
if                           | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                      | if                           | advise.c          | conditional
io_kiocb_to_cmd              | advise.c     | req, struct io_madvise                                   | io_kiocb_to_cmd              | advise.c          | function call
io_req_set_res               | advise.c     | req, ret, 0                                              | io_req_set_res               | advise.c          | function call
io_statx                     | opdef.c      | .issue = io_statx                                        | io_statx                     | opdef.c           | function call
io_statx_cleanup             | opdef.c      | .cleanup = io_statx_cleanup                              | io_statx_cleanup             | opdef.c           | function call
io_statx_prep                | opdef.c      | .prep = io_statx_prep                                    | io_statx_prep                | opdef.c           | function call
IS_ERR                       | eventfd.c    | ev_fd->cq_ev_fd                                          | IS_ERR                       | eventfd.c         | macro
PTR_ERR                      | eventfd.c    | ev_fd->cq_ev_fd                                          | PTR_ERR                      | eventfd.c         | function call
putname                      | fs.c         | ren->oldpath                                             | putname                      | fs.c              | function call
READ_ONCE                    | advise.c     | sqe->addr                                                | READ_ONCE                    | advise.c          | macro
u64_to_user_ptr              | epoll.c      | sqe->addr                                                | u64_to_user_ptr              | epoll.c           | function call
WARN_ON_ONCE                 | advise.c     | issue_flags & IO_URING_F_NONBLOCK                        | WARN_ON_ONCE                 | advise.c          | macro
do_ftruncate                  | truncate.c    | req->file, ft->len, 1                                  | do_ftruncate                  | truncate.c        | function call
if                             | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                             | advise.c          | conditional
io_ftruncate                   | opdef.c      | .issue = io_ftruncate                                 | io_ftruncate                   | opdef.c           | function call
io_ftruncate_prep              | opdef.c      | .prep = io_ftruncate_prep                             | io_ftruncate_prep              | opdef.c           | function call
io_kiocb_to_cmd                | advise.c     | req, struct io_madvise                                | io_kiocb_to_cmd                | advise.c          | function call
io_req_set_res                 | advise.c     | req, ret, 0                                           | io_req_set_res                 | advise.c          | function call
READ_ONCE                      | advise.c     | sqe->addr                                             | READ_ONCE                      | advise.c          | macro
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                     | WARN_ON_ONCE                   | advise.c          | macro
CLASS                          | msg_ring.c   | fd, f, sqe->fd                                        | CLASS                          | msg_ring.c        | macro
cmd_to_io_kiocb                | msg_ring.c   | msg                                                   | cmd_to_io_kiocb                | msg_ring.c        | function call
container_of                   | cancel.c     | work, struct io_kiocb, work                           | container_of                   | cancel.c          | macro
fd_empty                       | msg_ring.c   | f                                                     | fd_empty                       | msg_ring.c        | function call
fd_file                        | msg_ring.c   | f                                                     | fd_file                        | msg_ring.c        | function call
fput                           | cancel.c     | file                                                  | fput                           | cancel.c          | function call
get_file                       | msg_ring.c   | msg->src_file                                          | get_file                       | msg_ring.c        | function call
if                             | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                             | advise.c          | conditional
init_task_work                 | io-wq.c      | &worker->create_work, func                            | init_task_work                 | io-wq.c           | function call
io_add_aux_cqe                 | io_uring.c   | ctx, user_data, res, cflags                           | io_add_aux_cqe                 | io_uring.c        | function call
io_alloc_cache_get             | alloc_cache.c| cache                                                 | io_alloc_cache_get             | alloc_cache.c     | function call
io_alloc_cache_put             | alloc_cache.h| cache                                                 | io_alloc_cache_put             | alloc_cache.h     | function call
io_double_lock_ctx             | msg_ring.c   | octx                                                  | io_double_lock_ctx             | msg_ring.c        | function call
io_double_unlock_ctx           | msg_ring.c   | octx                                                  | io_double_unlock_ctx           | msg_ring.c        | function call
__io_fixed_fd_install          | filetable.c  | ctx, file                                              | __io_fixed_fd_install          | filetable.c       | function call
io_is_uring_fops               | filetable.c  | file                                                  | io_is_uring_fops               | filetable.c       | function call
io_kiocb_to_cmd                | advise.c     | req, struct io_madvise                                | io_kiocb_to_cmd                | advise.c          | function call
io_msg_data_remote             | msg_ring.c   | target_ctx                                             | io_msg_data_remote             | msg_ring.c        | function call
io_msg_fd_remote               | msg_ring.c   | req                                                   | io_msg_fd_remote               | msg_ring.c        | function call
io_msg_get_kiocb               | msg_ring.c   | ctx                                                   | io_msg_get_kiocb               | msg_ring.c        | function call
io_msg_grab_file               | msg_ring.c   | req, issue_flags                                        | io_msg_grab_file               | msg_ring.c        | function call
io_msg_install_complete        | msg_ring.c   | req, issue_flags                                        | io_msg_install_complete        | msg_ring.c        | function call
io_msg_need_remote             | msg_ring.c   | target_ctx                                             | io_msg_need_remote             | msg_ring.c        | function call
io_msg_remote_post             | msg_ring.c   | ctx, req                                               | io_msg_remote_post             | msg_ring.c        | function call
io_msg_ring                    | msg_ring.c   | req, issue_flags                                        | io_msg_ring                    | msg_ring.c        | function call
io_msg_ring_cleanup            | msg_ring.c   | req                                                   | io_msg_ring_cleanup            | msg_ring.c        | function call
__io_msg_ring_data             | msg_ring.c   | target_ctx                                             | __io_msg_ring_data             | msg_ring.c        | function call
io_msg_ring_data               | msg_ring.c   | req, issue_flags                                        | io_msg_ring_data               | msg_ring.c        | function call
__io_msg_ring_prep             | msg_ring.c   | msg, sqe                                               | __io_msg_ring_prep             | msg_ring.c        | function call
io_msg_ring_prep               | msg_ring.c   | req, sqe                                               | io_msg_ring_prep               | msg_ring.c        | function call
io_msg_send_fd                 | msg_ring.c   | req, issue_flags                                        | io_msg_send_fd                 | msg_ring.c        | function call
io_msg_tw_complete             | msg_ring.c   | req, ts                                                 | io_msg_tw_complete             | msg_ring.c        | function call
io_msg_tw_fd_complete          | msg_ring.c   | head                                                  | io_msg_tw_fd_complete          | msg_ring.c        | function call
io_post_aux_cqe                | io_uring.c   | ctx, user_data, res, cflags                           | io_post_aux_cqe                | io_uring.c        | function call
io_req_queue_tw_complete       | io_uring.h   | req, res                                               | io_req_queue_tw_complete       | io_uring.h        | function call
io_req_set_res                 | advise.c     | req, ret, 0                                           | io_req_set_res                 | advise.c          | function call
io_req_task_work_add_remote    | io_uring.c   | req, ctx                                               | io_req_task_work_add_remote    | io_uring.c        | function call
IORING_MSG_RING_MASK           | msg_ring.c   | IORING_MSG_RING_CQE_SKIP, IORING_MSG_RING_MASK        | IORING_MSG_RING_MASK           | msg_ring.c        | macro
io_ring_submit_lock            | cancel.c     | ctx, issue_flags                                        | io_ring_submit_lock            | cancel.c          | function call
io_ring_submit_unlock          | cancel.c     | ctx, issue_flags                                        | io_ring_submit_unlock          | cancel.c          | function call
io_rsrc_node_lookup            | cancel.c     | ctx->file_table.data, fd                                 | io_rsrc_node_lookup            | cancel.c          | function call
io_slot_file                   | cancel.c     | node                                                   | io_slot_file                   | cancel.c          | function call
io_uring_sync_msg_ring         | msg_ring.c   | sqe                                                   | io_uring_sync_msg_ring         | msg_ring.c        | function call
kmem_cache_alloc               | io_uring.c   | req_cachep, gfp                                         | kmem_cache_alloc               | io_uring.c        | function call
kmem_cache_free                | io_uring.c   | req_cachep, req                                         | kmem_cache_free                | io_uring.c        | function call
mutex_lock                     | cancel.c     | ctx->uring_lock                                         | mutex_lock                     | cancel.c          | function call
mutex_trylock                  | fdinfo.c     | ctx->uring_lock, has_lock                               | mutex_trylock                  | fdinfo.c          | function call
mutex_unlock                   | cancel.c     | ctx->uring_lock                                         | mutex_unlock                   | cancel.c          | function call
percpu_ref_get                 | io_uring.c   | ctx->refs                                               | percpu_ref_get                 | io_uring.c        | function call
percpu_ref_put                 | io_uring.c   | ctx->refs                                               | percpu_ref_put                 | io_uring.c        | function call
READ_ONCE                      | advise.c     | sqe->addr                                             | READ_ONCE                      | advise.c          | macro
req_set_fail                   | advise.c     | req                                                   | req_set_fail                   | advise.c          | function call
spin_trylock                   | msg_ring.c   | ctx->msg_lock                                           | spin_trylock                   | msg_ring.c        | function call
spin_unlock                    | cancel.c     | ctx->completion_lock                                    | spin_unlock                    | cancel.c          | function call
switch                         | advise.c     | fa->advice                                             | switch                         | advise.c          | function call
task_work_add                  | io-wq.c      | wq->task, &worker->create_work, TWA_SIGNAL              | task_work_add                  | io-wq.c           | function call
unlikely                       | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                       | unlikely                       | cancel.c          | macro
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                       | WARN_ON_ONCE                   | advise.c          | macro
ARRAY_SIZE                     | cancel.c     | sc.pad                                                | ARRAY_SIZE                     | cancel.c          | macro
BUG_ON                          | io_uring.c   | !tctx                                                 | BUG_ON                          | io_uring.c        | macro
BUILD_BUG_ON                    | io-wq.c      | (int) IO_WQ_ACCT_BOUND != (int) IO_WQ_BOUND             | BUILD_BUG_ON                    | io-wq.c           | macro
defined                         | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | defined                         | advise.c          | macro
for                             | Makefile     | Makefile for io_uring                                  | for                             | Makefile          | loop
if                              | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                              | advise.c          | conditional
io_eopnotsupp_prep              | opdef.c      | kiocb                                                 | io_eopnotsupp_prep              | opdef.c           | function call
io_no_issue                     | opdef.c      | req, issue_flags                                       | io_no_issue                     | opdef.c           | function call
io_uring_get_opcode             | fdinfo.c     | sq_idx, sqe->opcode, sqe->fd                           | io_uring_get_opcode             | fdinfo.c          | function call
io_uring_op_supported           | opdef.c      | opcode                                                | io_uring_op_supported           | opdef.c           | function call
io_uring_optable_init           | io_uring.c   |                                                     | io_uring_optable_init           | io_uring.c        | function call
prep                            | io_uring.c   | linked timeouts should have two refs once prep'ed      | prep                            | io_uring.c        | comment
sizeof                          | alloc_cache.c| max_nr, sizeof(void *), GFP_KERNEL                     | sizeof                          | alloc_cache.c     | keyword
WARN_ON_ONCE                    | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | WARN_ON_ONCE                    | advise.c          | macro
do_splice                     | splice.c     | in, poff_in, out, poff_out, sp->len, flags             | do_splice                     | splice.c         | function call
do_tee                         | splice.c     | in, out, sp->len, flags                                 | do_tee                         | splice.c         | function call
fput                           | cancel.c     | file                                                   | fput                           | cancel.c         | function call
if                             | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                             | advise.c         | conditional
io_file_get_normal             | cancel.c     | req, cancel->fd                                         | io_file_get_normal             | cancel.c         | function call
io_kiocb_to_cmd               | advise.c     | req, struct io_madvise                                  | io_kiocb_to_cmd               | advise.c         | function call
io_put_rsrc_node               | rsrc.c       | ctx, data->nodes[data->nr]                              | io_put_rsrc_node               | rsrc.c           | function call
io_req_set_res                 | advise.c     | req, ret, 0                                             | io_req_set_res                 | advise.c         | function call
io_ring_submit_lock           | cancel.c     | ctx, issue_flags                                        | io_ring_submit_lock           | cancel.c         | function call
io_ring_submit_unlock         | cancel.c     | ctx, issue_flags                                        | io_ring_submit_unlock         | cancel.c         | function call
io_rsrc_node_lookup           | cancel.c     | &ctx->file_table.data, fd                               | io_rsrc_node_lookup           | cancel.c         | function call
io_slot_file                  | cancel.c     | node                                                   | io_slot_file                  | cancel.c         | function call
io_splice                      | opdef.c      | .issue = io_splice                                      | io_splice                      | opdef.c          | function call
io_splice_cleanup              | opdef.c      | .cleanup = io_splice_cleanup                             | io_splice_cleanup              | opdef.c          | function call
io_splice_get_file             | splice.c     | req                                                    | io_splice_get_file             | splice.c         | function call
__io_splice_prep               | splice.c     | req                                                    | __io_splice_prep               | splice.c         | function call
io_splice_prep                 | opdef.c      | .prep = io_splice_prep                                  | io_splice_prep                 | opdef.c          | function call
io_tee                         | opdef.c      | .issue = io_tee                                         | io_tee                         | opdef.c          | function call
io_tee_prep                    | opdef.c      | .prep = io_tee_prep                                     | io_tee_prep                    | opdef.c          | function call
READ_ONCE                      | advise.c     | sqe->addr                                              | READ_ONCE                      | advise.c         | macro
req_set_fail                   | advise.c     | req                                                    | req_set_fail                   | advise.c         | function call
unlikely                       | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                       | unlikely                       | cancel.c         | keyword
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | WARN_ON_ONCE                   | advise.c         | macro
ARRAY_SIZE                     | cancel.c     | sc.pad                                                 | ARRAY_SIZE                     | cancel.c         | macro
atomic_inc_return              | cancel.c     | req->ctx->cancel_seq                                    | atomic_inc_return              | cancel.c         | function call
CANCEL_FLAGS                   | cancel.c     | IORING_ASYNC_CANCEL_ALL, IORING_ASYNC_CANCEL_FD         | CANCEL_FLAGS                   | cancel.c         | macro
container_of                   | cancel.c     | work, struct io_kiocb, work                             | container_of                   | cancel.c         | function call
copy_from_user                 | cancel.c     | &sc, arg, sizeof(sc)                                    | copy_from_user                 | cancel.c         | function call
DEFINE_WAIT                     | cancel.c     | wait                                                   | DEFINE_WAIT                     | cancel.c         | macro
fget                            | cancel.c     | sc.fd                                                   | fget                            | cancel.c         | function call
finish_wait                    | cancel.c     | &ctx->cq_wait, &wait                                   | finish_wait                    | cancel.c         | function call
__io_async_cancel              | cancel.c     | cd                                                     | __io_async_cancel              | cancel.c         | function call
io_async_cancel                | cancel.c     | req, issue_flags                                        | io_async_cancel                | cancel.c         | function call
io_async_cancel_one            | cancel.c     | tctx, cd                                                | io_async_cancel_one            | cancel.c         | function call
io_async_cancel_prep           | cancel.c     | req, sqe                                                | io_async_cancel_prep           | cancel.c         | function call
io_cancel_cb                   | cancel.c     | work, data                                              | io_cancel_cb                   | cancel.c         | function call
io_cancel_match_sequence       | cancel.c     | req, cd->seq                                            | io_cancel_match_sequence       | cancel.c         | function call
io_cancel_req_match            | cancel.c     | req, cd                                                 | io_cancel_req_match            | cancel.c         | function call
io_file_get_fixed              | cancel.c     | req, cancel->fd,                                        | io_file_get_fixed              | cancel.c         | function call
io_futex_cancel                | cancel.c     | ctx, cd, issue_flags                                    | io_futex_cancel                | cancel.c         | function call
io_poll_cancel                 | cancel.c     | ctx, cd, issue_flags                                    | io_poll_cancel                 | cancel.c         | function call
io_req_set_res                 | advise.c     | req, ret, 0                                             | io_req_set_res                 | advise.c         | function call
io_ring_submit_lock           | cancel.c     | ctx, issue_flags                                        | io_ring_submit_lock           | cancel.c         | function call
io_ring_submit_unlock         | cancel.c     | ctx, issue_flags                                        | io_ring_submit_unlock         | cancel.c         | function call
io_rsrc_node_lookup           | cancel.c     | &ctx->file_table.data, fd                               | io_rsrc_node_lookup           | cancel.c         | function call
io_run_task_work_sig          | cancel.c     | ctx                                                   | io_run_task_work_sig          | cancel.c         | function call
io_slot_file                  | cancel.c     | node                                                   | io_slot_file                  | cancel.c         | function call
__io_sync_cancel               | cancel.c     | tctx                                                   | __io_sync_cancel               | cancel.c         | function call
io_sync_cancel                 | cancel.c     | ctx, arg                                                | io_sync_cancel                 | cancel.c         | function call
io_timeout_cancel              | cancel.c     | ctx, cd                                                 | io_timeout_cancel              | cancel.c         | function call
io_try_cancel                  | cancel.c     | tctx, cd                                                | io_try_cancel                  | cancel.c         | function call
io_waitid_cancel               | cancel.c     | ctx, cd, issue_flags                                    | io_waitid_cancel               | cancel.c         | function call
io_wq_cancel_cb                | cancel.c     | tctx->io_wq, io_cancel_cb, cd, all                      | io_wq_cancel_cb                | cancel.c         | function call
io_wq_current_is_worker        | cancel.c     | tctx != current->io_uring                              | io_wq_current_is_worker        | cancel.c         | function call
ktime_add_ns                   | cancel.c     | timespec64_to_ktime(ts), ktime_get_ns()                | ktime_add_ns                   | cancel.c         | function call
ktime_get_ns                   | cancel.c     |                                                     | ktime_get_ns                   | cancel.c         | function call
list_for_each_entry            | cancel.c     | node, &ctx->tctx_list, ctx_node                        | list_for_each_entry            | cancel.c         | macro
__must_hold                    | cancel.c     | &ctx->uring_lock                                       | __must_hold                    | cancel.c         | macro
mutex_lock                     | cancel.c     | &ctx->uring_lock                                       | mutex_lock                     | cancel.c         | function call
mutex_unlock                   | cancel.c     | &ctx->uring_lock                                       | mutex_unlock                   | cancel.c         | function call
prepare_to_wait                | cancel.c     | &ctx->cq_wait, &wait, TASK_INTERRUPTIBLE                | prepare_to_wait                | cancel.c         | function call
READ_ONCE                      | advise.c     | sqe->addr                                              | READ_ONCE                      | advise.c         | macro
req_set_fail                   | advise.c     | req                                                    | req_set_fail                   | advise.c         | function call
schedule_hrtimeout             | cancel.c     | &timeout, HRTIMER_MODE_ABS                             | schedule_hrtimeout             | cancel.c         | function call
sizeof                         | alloc_cache.c| max_nr, sizeof(void *), GFP_KERNEL                     | sizeof                         | alloc_cache.c    | keyword
spin_lock                      | cancel.c     | &ctx->completion_lock                                  | spin_lock                      | cancel.c         | function call
spin_unlock                    | cancel.c     | &ctx->completion_lock                                  | spin_unlock                    | cancel.c         | function call
switch                          | advise.c     | fa->advice                                             | switch                          | advise.c         | keyword
timespec64_to_ktime            | cancel.c     | ts, ktime_get_ns()                                     | timespec64_to_ktime            | cancel.c         | function call
unlikely                       | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                       | unlikely                       | cancel.c         | keyword
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | WARN_ON_ONCE                   | advise.c         | macro
while                           | alloc_cache.c| io_alloc_cache_get(cache)                              | while                           | alloc_cache.c    | loop
atomic_read            | io-wq.c                   | return io_get_acct(wq, !(atomic_read(&work->flags) & IO_WQ_WORK_UNBOUND))   | atomic_read             | io-wq.c                        | function call                   
atomic_set             | eventfd.c                 | atomic_set(&ev_fd->ops, 0)                                              | atomic_set              | eventfd.c                      | function call                   
cmd_to_io_kiocb        | msg_ring.c                | struct io_kiocb *req = cmd_to_io_kiocb(msg)                               | cmd_to_io_kiocb         | msg_ring.c                     | function call                   
container_of           | cancel.c                  | struct io_kiocb *req = container_of(work, struct io_kiocb, work)           | container_of            | cancel.c                       | macro                          
data_race              | sqpoll.c                  | WARN_ON_ONCE(data_race(sqd->thread) == current)                           | data_race               | sqpoll.c                       | function call                   
ERR_PTR                | io-wq.c                   | return ERR_PTR(-EINVAL)                                                  | ERR_PTR                 | io-wq.c                        | function call                   
get_timespec64         | io-uring.c                | if (get_timespec64(&ext_arg->ts, u64_to_user_ptr(arg.ts)))                | get_timespec64          | io-uring.c                     | function call                   
hrtimer_init           | timeout.c                 | hrtimer_init(&io->timer, io_timeout_get_clock(io), mode)                   | hrtimer_init            | timeout.c                      | function call                   
hrtimer_start          | timeout.c                 | hrtimer_start(&data->timer, timespec64_to_ktime(data->ts), data->mode)    | hrtimer_start           | timeout.c                      | function call                   
hrtimer_try_to_cancel  | timeout.c                 | if (hrtimer_try_to_cancel(&io->timer) != -1)                              | hrtimer_try_to_cancel   | timeout.c                      | function call                   
hweight32              | timeout.c                 | if (hweight32(tr->flags & IORING_TIMEOUT_CLOCK_MASK) > 1)                 | hweight32               | timeout.c                      | function call                   
if                     | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                 | if                      | advise.c                       | macro                          
INIT_LIST_HEAD         | io-wq.c                   | INIT_LIST_HEAD(&wq->wait.entry)                                           | INIT_LIST_HEAD          | io-wq.c                        | macro                          
io_cancel_req_match    | cancel.c                  | bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd)  | io_cancel_req_match     | cancel.c                       | function definition             
__io_disarm_linked_timeout | timeout.c              | struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req)          | __io_disarm_linked_timeout | timeout.c                    | function definition             
io_disarm_linked_timeout | timeout.c               | link = io_disarm_linked_timeout(req)                                      | io_disarm_linked_timeout | timeout.c                    | function call                   
io_disarm_next         | io-uring.c                | /* requests with any of those set should undergo io_disarm_next() */       | io_disarm_next          | io-uring.c                     | function call                   
io_fail_links          | timeout.c                 | static void io_fail_links(struct io_kiocb *req)                            | io_fail_links           | timeout.c                      | function definition             
io_flush_killed_timeouts | timeout.c               | static __cold bool io_flush_killed_timeouts(struct list_head *list, int err) | io_flush_killed_timeouts | timeout.c                    | function definition             
io_flush_timeouts      | io-uring.c                | io_flush_timeouts(ctx)                                                    | io_flush_timeouts       | io-uring.c                     | function call                   
io_for_each_link       | io-uring.c                | io_for_each_link(req, head)                                               | io_for_each_link        | io-uring.c                     | function call                   
io_free_req            | io-uring.c                | __cold void io_free_req(struct io_kiocb *req)                              | io_free_req             | io-uring.c                     | function call                   
io_is_timeout_noseq    | timeout.c                 | static inline bool io_is_timeout_noseq(struct io_kiocb *req)               | io_is_timeout_noseq     | timeout.c                      | function call                   
io_kill_timeout        | timeout.c                 | static void io_kill_timeout(struct io_kiocb *req, struct list_head *list)   | io_kill_timeout         | timeout.c                      | function call                   
io_kill_timeouts       | io-uring.c                | ret |= io_kill_timeouts(ctx, tctx, cancel_all);                           | io_kill_timeouts        | io-uring.c                     | function call                   
io_kiocb_to_cmd        | advise.c                  | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise)            | io_kiocb_to_cmd         | advise.c                       | function call                   
io_linked_timeout_update | timeout.c               | static int io_linked_timeout_update(struct io_ring_ctx *ctx, __u64 user_data) | io_linked_timeout_update | timeout.c                    | function definition             
io_link_timeout_fn     | timeout.c                 | static enum hrtimer_restart io_link_timeout_fn(struct hrtimer *timer)       | io_link_timeout_fn      | timeout.c                      | function definition             
io_link_timeout_prep   | opdef.c                   | .prep = io_link_timeout_prep                                               | io_link_timeout_prep    | opdef.c                        | function definition             
io_match_task          | io-uring.c                | * As io_match_task() but protected against racing with linked timeouts.     | io_match_task           | io-uring.c                     | function call                   
io_put_req             | timeout.c                 | static inline void io_put_req(struct io_kiocb *req)                        | io_put_req              | timeout.c                      | function definition             
io_queue_linked_timeout | io-uring.c               | io_queue_linked_timeout(__io_prep_linked_timeout(req))                     | io_queue_linked_timeout  | io-uring.c                     | function call                   
io_queue_next          | io-uring.c                | void io_queue_next(struct io_kiocb *req)                                   | io_queue_next           | io-uring.c                     | function call                   
io_remove_next_linked  | timeout.c                 | static inline void io_remove_next_linked(struct io_kiocb *req)             | io_remove_next_linked   | timeout.c                      | function definition             
io_req_post_cqe        | io-uring.c                | bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags)           | io_req_post_cqe         | io-uring.c                     | function call                   
io_req_queue_tw_complete | io-uring.h              | static inline void io_req_queue_tw_complete(struct io_kiocb *req, s32 res) | io_req_queue_tw_complete | io-uring.h                     | function definition             
io_req_set_res         | advise.c                  | io_req_set_res(req, ret, 0)                                               | io_req_set_res          | advise.c                       | function call                   
io_req_task_complete   | futex.c                   | io_req_task_complete(req, ts)                                             | io_req_task_complete    | futex.c                        | function call                   
io_req_task_link_timeout | timeout.c               | static void io_req_task_link_timeout(struct io_kiocb *req, struct io_tw_state *ts) | io_req_task_link_timeout | timeout.c                    | function definition             
io_req_task_queue_fail | io-uring.c                | io_req_task_queue_fail(req, -ECANCELED)                                   | io_req_task_queue_fail  | io-uring.c                     | function call                   
io_req_task_work_add   | futex.c                   | io_req_task_work_add(req)                                                 | io_req_task_work_add    | futex.c                        | function call                   
io_req_tw_fail_links   | timeout.c                 | static void io_req_tw_fail_links(struct io_kiocb *link, struct io_tw_state *ts) | io_req_tw_fail_links    | timeout.c                    | function definition             
io_should_terminate_tw | io-uring.c                | if (unlikely(io_should_terminate_tw()))                                    | io_should_terminate_tw  | io-uring.c                     | function call                   
io_timeout             | opdef.c                   | .issue = io_timeout                                                        | io_timeout              | opdef.c                        | function call                   
io_timeout_cancel      | cancel.c                  | ret = io_timeout_cancel(ctx, cd)                                          | io_timeout_cancel       | cancel.c                       | function call                   
io_timeout_complete    | timeout.c                 | static void io_timeout_complete(struct io_kiocb *req, struct io_tw_state *ts) | io_timeout_complete     | timeout.c                      | function definition             
io_timeout_extract     | timeout.c                 | static struct io_kiocb *io_timeout_extract(struct io_ring_ctx *ctx)         | io_timeout_extract      | timeout.c                      | function definition             
io_timeout_finish      | timeout.c                 | static inline bool io_timeout_finish(struct io_timeout *timeout)            | io_timeout_finish       | timeout.c                      | function call                   
io_timeout_fn          | timeout.c                 | static enum hrtimer_restart io_timeout_fn(struct hrtimer *timer)            | io_timeout_fn           | timeout.c                      | function definition             
io_timeout_get_clock   | timeout.c                 | static clockid_t io_timeout_get_clock(struct io_timeout_data *data)        | io_timeout_get_clock    | timeout.c                      | function definition             
__io_timeout_prep      | timeout.c                 | static int __io_timeout_prep(struct io_kiocb *req)                         | __io_timeout_prep       | timeout.c                      | function definition             
io_timeout_prep        | opdef.c                   | .prep = io_timeout_prep                                                    | io_timeout_prep         | opdef.c                        | function definition             
io_timeout_remove      | opdef.c                   | .issue = io_timeout_remove                                                 | io_timeout_remove       | opdef.c                        | function definition             
io_timeout_remove_prep | opdef.c                   | .prep = io_timeout_remove_prep                                            | io_timeout_remove_prep  | opdef.c                        | function definition             
io_timeout_update      | timeout.c                 | static int io_timeout_update(struct io_ring_ctx *ctx, __u64 user_data)      | io_timeout_update       | timeout.c                      | function call                   
io_translate_timeout_mode | timeout.c               | static inline enum hrtimer_mode io_translate_timeout_mode(unsigned int flags) | io_translate_timeout_mode | timeout.c                    | function definition             
io_try_cancel          | cancel.c                  | int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd)    | io_try_cancel           | cancel.c                       | function definition             
io_tw_lock             | futex.c                   | io_tw_lock(ctx, ts)                                                      | io_tw_lock              | futex.c                        | function call                   
io_uring_alloc_async_data | io-uring.h              | static inline void *io_uring_alloc_async_data(struct io_alloc_cache *cache) | io_uring_alloc_async_data | io-uring.h                    | function definition             
IS_ERR                 | eventfd.c                 | if (IS_ERR(ev_fd->cq_ev_fd))                                             | IS_ERR                  | eventfd.c                      | function call                   
list_add               | kbuf.c                    | list_add(&buf->list, &bl->buf_list)                                        | list_add                | kbuf.c                         | function call                   
list_add_tail          | io-uring.c                | list_add_tail(&ocqe->list, &ctx->cq_overflow_list)                        | list_add_tail           | io-uring.c                     | function call                   
list_del               | io-uring.c                | list_del(&ocqe->list)                                                     | list_del                | io-uring.c                     | function call                   
list_del_init          | io-wq.c                   | list_del_init(&wq->wait.entry)                                            | list_del_init           | io-wq.c                        | function call                   
list_empty             | io-wq.c                   | if (list_empty(&wq->wait.entry))                                          | list_empty              | io-wq.c                        | function call                   
list_entry             | kbuf.c                    | buf = list_entry(item, struct io_buffer, list)                             | list_entry              | kbuf.c                         | function call                   
list_first_entry       | io-uring.c                | struct io_defer_entry *de = list_first_entry(&ctx->defer_list)            | list_first_entry        | io-uring.c                     | function call                   
list_for_each_entry    | cancel.c                  | list_for_each_entry(node, &ctx->tctx_list, ctx_node)                      | list_for_each_entry     | cancel.c                       | function call                   
list_for_each_entry_safe | napi.c                  | * list_for_each_entry_safe() is not required as long as:                   | list_for_each_entry_safe | napi.c                        | function call                   
list_for_each_prev     | timeout.c                 | list_for_each_prev(entry, &ctx->timeout_list)                              | list_for_each_prev      | timeout.c                      | function call                   
LIST_HEAD              | io-uring.c                | LIST_HEAD(list)                                                           | LIST_HEAD               | io-uring.c                     | macro                          
list_move_tail         | kbuf.c                    | list_move_tail(&buf->list, &bl->buf_list)                                  | list_move_tail          | kbuf.c                         | function call                   
__must_hold            | cancel.c                  | __must_hold(&ctx->uring_lock)                                             | __must_hold             | cancel.c                       | macro                          
PTR_ERR                | eventfd.c                 | int ret = PTR_ERR(ev_fd->cq_ev_fd)                                        | PTR_ERR                 | eventfd.c                      | function call                   
raw_spin_lock_irq      | io-uring.c                | raw_spin_lock_irq(&ctx->timeout_lock)                                     | raw_spin_lock_irq       | io-uring.c                     | function call                   
raw_spin_lock_irqsave  | timeout.c                 | raw_spin_lock_irqsave(&ctx->timeout_lock, flags)                         | raw_spin_lock_irqsave   | timeout.c                      | function call                   
raw_spin_unlock_irq    | io-uring.c                | raw_spin_unlock_irq(&ctx->timeout_lock)                                   | raw_spin_unlock_irq     | io-uring.c                     | function call                   
raw_spin_unlock_irqrestore | timeout.c              | raw_spin_unlock_irqrestore(&ctx->timeout_lock, flags)                    | raw_spin_unlock_irqrestore | timeout.c                    | function call                   
READ_ONCE             | advise.c                  | ma->addr = READ_ONCE(sqe->addr)                                           | READ_ONCE              | advise.c                       | function call                   
req_has_async_data     | io-uring.h                | static inline bool req_has_async_data(struct io_kiocb *req)               | req_has_async_data      | io-uring.h                     | function definition             
req_ref_inc_not_zero   | refs.h                    | static inline bool req_ref_inc_not_zero(struct io_kiocb *req)             | req_ref_inc_not_zero    | refs.h                         | function definition             
return                  | advise.c         | return -EINVAL;                                                                   | return                    | advise.c               | keyword / control statement  
spin_lock               | cancel.c         | spin_lock(&ctx->completion_lock);                                                 | spin_lock                 | cancel.c               | function call                
spin_unlock             | cancel.c         | spin_unlock(&ctx->completion_lock);                                               | spin_unlock               | cancel.c               | function call                
switch                  | advise.c         | switch (fa->advice) {                                                              | switch                    | advise.c               | keyword / control statement  
timespec64_to_ktime     | cancel.c         | timeout = ktime_add_ns(timespec64_to_ktime(ts), ktime_get_ns());                 | timespec64_to_ktime       | cancel.c               | function call                
trace_io_uring_fail_link| timeout.c        | trace_io_uring_fail_link(req, link);                                              | trace_io_uring_fail_link  | timeout.c              | function call                
u64_to_user_ptr         | epoll.c          | ev = u64_to_user_ptr(READ_ONCE(sqe->addr));                                       | u64_to_user_ptr           | epoll.c                | function call                
unlikely                | cancel.c         | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                                   | unlikely                  | cancel.c               | macro / branch prediction    
WARN_ON_ONCE            | advise.c         | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                                  | WARN_ON_ONCE              | advise.c               | macro / debugging macro      
while                   | alloc_cache.c    | while ((entry = io_alloc_cache_get(cache)) != NULL)                               | while                     | alloc_cache.c          | keyword / control statement  
io_rw_init_file        | rw.c                       | struct io_kiocb *req, fmode_t mode, int rw_type                  | io_rw_init_file         | rw.c                           | function definition            
io_rw_recycle          | rw.c                       | struct io_kiocb *req, unsigned int issue_flags                   | io_rw_recycle           | rw.c                           | function definition            
io_rw_should_reissue   | rw.c                       | struct io_kiocb *req                                             | io_rw_should_reissue    | rw.c                           | function definition            
io_rw_should_retry     | rw.c                       | struct io_kiocb *req                                             | io_rw_should_retry      | rw.c                           | function definition            
io_schedule            | rw.c                       | io_schedule();                                                   | io_schedule             | rw.c                           | function call                  
__io_submit_flush_completions | io_uring.c          | struct io_ring_ctx *ctx                                          | __io_submit_flush_completions | io_uring.c              | function definition            
io_uring_alloc_async_data | io_uring.h              | struct io_alloc_cache *cache, ...                                | io_uring_alloc_async_data | io_uring.h                  | function definition (inline)   
io_uring_classic_poll  | rw.c                       | struct io_kiocb *req, struct io_comp_batch *iob, ...             | io_uring_classic_poll    | rw.c                           | function definition            
io_uring_hybrid_poll   | rw.c                       | struct io_kiocb *req, ...                                        | io_uring_hybrid_poll     | rw.c                           | function definition            
iov_iter_advance       | rsrc.c                     | iov_iter_advance()                                               | iov_iter_advance        | rsrc.c                         | function call                  
iov_iter_count         | net.c                      | !iov_iter_count(&kmsg->msg.msg_iter)                             | iov_iter_count          | net.c                          | function call                  
iov_iter_is_bvec       | rw.c                       | !iov_iter_is_bvec(iter)                                          | iov_iter_is_bvec        | rw.c                           | function call                  
iov_iter_restore       | rw.c                       | iov_iter_restore(&io->meta.iter, &io->meta_state.iter_meta)      | iov_iter_restore        | rw.c                           | function call                  
iov_iter_save_state    | rw.c                       | iov_iter_save_state(&io->iter, &io->iter_state)                  | iov_iter_save_state     | rw.c                           | function call                  
io_wq_current_is_worker | cancel.c                  | !io_wq_current_is_worker() && tctx != current->io_uring          | io_wq_current_is_worker | cancel.c                      | function call                  
io_write               | opdef.c                    | .issue = io_write                                                | io_write                | opdef.c                        | function pointer               
iter_iov_addr          | rw.c                       | addr = iter_iov_addr(iter)                                       | iter_iov_addr           | rw.c                           | function call                  
iter_iov_len           | rw.c                       | len = iter_iov_len(iter)                                         | iter_iov_len            | rw.c                           | function call                  
iter_is_ubuf           | net.c                      | iter_is_ubuf(&kmsg->msg.msg_iter)                                | iter_is_ubuf            | net.c                          | function call                  
kfree                  | alloc_cache.h              | kfree(*iov);                                                     | kfree                   | alloc_cache.h                  | function call                  
ki_complete            | rw.c                       | ->ki_complete()                                                  | ki_complete             | rw.c                           | function pointer               
kiocb_done             | rw.c                       | struct io_kiocb *req, ssize_t ret                                | kiocb_done              | rw.c                           | function definition            
kiocb_end_write        | rw.c                       | kiocb_end_write(&rw->kiocb)                                      | kiocb_end_write         | rw.c                           | function call                  
kiocb_set_rw_flags     | rw.c                       | kiocb_set_rw_flags(kiocb, rw->flags, rw_type)                    | kiocb_set_rw_flags      | rw.c                           | function call                  
kiocb_start_write      | rw.c                       | kiocb_start_write(kiocb)                                         | kiocb_start_write       | rw.c                           | function call                  
ktime_get_ns           | cancel.c                   | ktime_get_ns()                                                   | ktime_get_ns            | cancel.c                       | function call                  
ktime_set              | rw.c                       | ktime_set(0, sleep_time)                                         | ktime_set               | rw.c                           | function call                  
likely                 | io-wq.c                    | Most likely an attempt ...                                       | likely                  | io-wq.c                        | macro                          
list_del_init          | io-wq.c                    | list_del_init(&wq->wait.entry)                                   | list_del_init           | io-wq.c                        | function call                  
lockdep_assert_held    | futex.c                    | lockdep_assert_held(&ctx->uring_lock)                            | lockdep_assert_held     | futex.c                        | macro                          
loop_rw_iter           | rw.c                       | int ddir, struct io_rw *rw, struct iov_iter *iter               | loop_rw_iter            | rw.c                           | function definition            
need_complete_io       | rw.c                       | struct io_kiocb *req                                             | need_complete_io        | rw.c                           | function definition            
percpu_ref_is_dying    | io_uring.h                 | !percpu_ref_is_dying(&ctx->refs)                                 | percpu_ref_is_dying     | io_uring.h                     | function call                  
read                   | eventfd.c                  | returns with an ev_fd reference                                  | read                    | eventfd.c                      | comment/function reference     
read_iter              | rw.c                       | ->read_iter()                                                    | read_iter               | rw.c                           | function pointer (comment)     
READ_ONCE              | advise.c                   | READ_ONCE(sqe->addr)                                             | READ_ONCE               | advise.c                       | function call                  
req_has_async_data     | io_uring.h                 | bool req_has_async_data(struct io_kiocb *req)                    | req_has_async_data      | io_uring.h                     | function definition (inline)   
req_set_fail           | advise.c                   | req_set_fail(req)                                                | req_set_fail            | advise.c                       | function call                  
return                 | advise.c                   | return -EINVAL;                                                  | return                  | advise.c                       | keyword                        
rq_list_empty          | rw.c                       | !rq_list_empty(&iob.req_list)                                    | rq_list_empty           | rw.c                           | function call                  
rw_verify_area         | rw.c                       | rw_verify_area(READ, req->file, ...)                             | rw_verify_area          | rw.c                           | function call                  
sb_start_write_trylock | rw.c                       | sb_start_write_trylock(inode->i_sb)                              | sb_start_write_trylock  | rw.c                           | function call                  
__sb_writers_release   | rw.c                       | __sb_writers_release(inode->i_sb, SB_FREEZE_WRITE)               | __sb_writers_release    | rw.c                           | function call                  
__set_current_state    | futex.c                    | __set_current_state(TASK_RUNNING)                                | __set_current_state     | futex.c                        | macro/function                 
set_current_state      | io-wq.c                    | set_current_state(TASK_INTERRUPTIBLE)                            | set_current_state       | io-wq.c                        | function call                  
S_ISBLK                | io_uring.c                 | !S_ISBLK(file_inode(req->file)->i_mode)                          | S_ISBLK                 | io_uring.c                     | macro                          
S_ISREG                | io_uring.c                 | S_ISREG(file_inode(file)->i_mode)                                | S_ISREG                 | io_uring.c                     | macro                          
sizeof                 | alloc_cache.c              | sizeof(void *)                                                   | sizeof                 | alloc_cache.c                  | keyword                        
smp_load_acquire       | io_uring.c                 | smp_load_acquire to read the tail                                | smp_load_acquire        | io_uring.c                     | macro                          
smp_store_release      | io_uring.c                 | smp_store_release to                                             | smp_store_release       | io_uring.c                     | macro                          
successful             | futex.c                    | successful setup, then the task ...                              | successful              | futex.c                        | comment context                
switch                 | advise.c                   | switch (fa->advice)                                              | switch                  | advise.c                       | conditional branch             
trace_io_uring_short_write | rw.c                   | trace_io_uring_short_write(req->ctx, ...)                        | trace_io_uring_short_write | rw.c                       | function call                  
u64_to_user_ptr        | epoll.c                    | u64_to_user_ptr(READ_ONCE(sqe->addr))                            | u64_to_user_ptr         | epoll.c                        | function call                  
unlikely               | cancel.c                   | unlikely(req->flags & REQ_F_BUFFER_SELECT)                       | unlikely                | cancel.c                       | macro                          
until                  | cancel.c                   | Keep looking until ...                                           | until                   | cancel.c                       | comment context                
uring_cmd_iopoll       | rw.c                       | file->f_op->uring_cmd_iopoll(...)                                | uring_cmd_iopoll        | rw.c                           | function call (callback)       
vfs_poll               | poll.c                     | Redo vfs_poll()                                                  | vfs_poll                | poll.c                         | function call                  
wake_page_match        | rw.c                       | !wake_page_match(wpq, key)                                       | wake_page_match         | rw.c                           | function call                  
WARN_ON_ONCE           | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK)                  | WARN_ON_ONCE            | advise.c                       | macro                          
while                  | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)              | while                   | alloc_cache.c                  | keyword                        
wq_list_cut            | io-wq.c                    | wq_list_cut(&acct->work_list, ...)                               | wq_list_cut             | io-wq.c                        | function call                  
wq_list_empty          | io-wq.c                    | !wq_list_empty(&acct->work_list)                                 | wq_list_empty           | io-wq.c                        | function call                  
wq_list_for_each       | io-wq.c                    | wq_list_for_each(node, prev, ...)                                | wq_list_for_each        | io-wq.c                        | macro                          
wq_list_for_each_resume | rw.c                      | wq_list_for_each_resume(pos, prev)                               | wq_list_for_each_resume | rw.c                           | macro                          
write                  | io_uring.c                 | note on the read/write ordering ...                              | write                   | io_uring.c                     | comment context                
write_iter             | rw.c                       | ->write_iter()                                                   | write_iter              | rw.c                           | function pointer (comment)     
io_file_get_flags       | filetable.h               | struct file *file                                                | io_file_get_flags       | filetable.h                    | function declaration           
io_file_supports_nowait | rw.c                      | struct io_kiocb *req, __poll_t mask                              | io_file_supports_nowait | rw.c                           | function definition            
io_fixup_rw_res         | rw.c                      | struct io_kiocb *req, long res                                   | io_fixup_rw_res         | rw.c                           | inline function                
io_hybrid_iopoll_delay  | rw.c                      | struct io_ring_ctx *ctx, struct io_kiocb *req                    | io_hybrid_iopoll_delay  | rw.c                           | function definition            
io_import_fixed         | net.c                     | io_import_fixed(ITER_SOURCE, ...)                                | io_import_fixed         | net.c                          | function call                  
__io_import_iovec       | rw.c                      | __io_import_iovec(int ddir, req, ...)                            | __io_import_iovec       | rw.c                           | function definition            
io_import_iovec         | rw.c                      | io_import_iovec(int rw, req, ...)                                | io_import_iovec         | rw.c                           | inline function                
io_iopoll_complete      | rw.c                      | checking ->iopoll_completed                                      | io_iopoll_complete      | rw.c                           | function call (comment ref)    
io_iov_buffer_select_prep | rw.c                    | struct io_kiocb *req                                             | io_iov_buffer_select_prep | rw.c                        | function definition            
io_iov_compat_buffer_select_prep | rw.c            | struct io_rw *rw                                                 | io_iov_compat_buffer_select_prep | rw.c                | function definition            
io_iter_do_read         | rw.c                      | struct io_rw *rw, struct iov_iter *iter                          | io_iter_do_read         | rw.c                           | inline function                
io_kbuf_recycle         | io_uring.c                | io_kbuf_recycle(req, 0)                                          | io_kbuf_recycle         | io_uring.c                     | function call                  
io_kiocb_ppos           | rw.c                      | struct kiocb *kiocb                                              | io_kiocb_ppos           | rw.c                           | inline function                
io_kiocb_start_write    | rw.c                      | struct io_kiocb *req, struct kiocb *kiocb                        | io_kiocb_start_write    | rw.c                           | function definition            
io_kiocb_to_cmd         | advise.c                  | req, struct io_madvise                                           | io_kiocb_to_cmd         | advise.c                       | function call                  
io_kiocb_update_pos     | rw.c                      | struct io_kiocb *req                                             | io_kiocb_update_pos     | rw.c                           | inline function                
io_meta_restore         | rw.c                      | struct io_async_rw *io, struct kiocb *kiocb                      | io_meta_restore         | rw.c                           | inline function                
io_meta_save_state      | rw.c                      | struct io_async_rw *io                                           | io_meta_save_state      | rw.c                           | inline function                
iopoll                  | io_uring.c                | ctx->flags & IORING_SETUP_IOPOLL                                 | iopoll                  | io_uring.c                     | condition flag (bitfield)      
io_poll_multishot_retry | poll.h                    | struct io_kiocb *req                                             | io_poll_multishot_retry | poll.h                         | inline function                
io_prep_read            | opdef.c                   | .prep = io_prep_read                                             | io_prep_read            | opdef.c                        | function reference in struct   
io_prep_read_fixed      | opdef.c                   | .prep = io_prep_read_fixed                                       | io_prep_read_fixed      | opdef.c                        | function reference in struct   
io_prep_readv           | opdef.c                   | .prep = io_prep_readv                                            | io_prep_readv           | opdef.c                        | function reference in struct   
io_prep_rw              | rw.c                      | io_prep_rw(struct io_kiocb *req, ...)                            | io_prep_rw              | rw.c                           | function definition            
io_prep_rw_fixed        | rw.c                      | io_prep_rw_fixed(req, sqe)                                       | io_prep_rw_fixed        | rw.c                           | function definition            
io_prep_rw_pi           | rw.c                      | io_prep_rw_pi(req, rw, ddir)                                     | io_prep_rw_pi           | rw.c                           | function definition            
io_prep_rw_setup        | rw.c                      | io_prep_rw_setup(req, ddir, do_import)                           | io_prep_rw_setup        | rw.c                           | function definition            
io_prep_rwv             | rw.c                      | io_prep_rwv(req, sqe)                                            | io_prep_rwv             | rw.c                           | function definition            
io_prep_write           | opdef.c                   | .prep = io_prep_write                                            | io_prep_write           | opdef.c                        | function reference in struct   
io_prep_write_fixed     | opdef.c                   | .prep = io_prep_write_fixed                                      | io_prep_write_fixed     | opdef.c                        | function reference in struct   
io_prep_writev          | opdef.c                   | .prep = io_prep_writev                                           | io_prep_writev          | opdef.c                        | function reference in struct   
ioprio_check_cap        | rw.c                      | ioprio_check_cap(ioprio)                                         | ioprio_check_cap        | rw.c                           | function call                  
io_put_kbuf             | io_uring.c                | io_req_set_res(req, res, io_put_kbuf(...))                       | io_put_kbuf             | io_uring.c                     | function call                  
__io_read               | rw.c                      | __io_read(req, issue_flags)                                      | __io_read               | rw.c                           | function definition            
io_read                 | opdef.c                   | .issue = io_read                                                 | io_read                 | opdef.c                        | function reference in struct   
io_read_mshot           | opdef.c                   | .issue = io_read_mshot                                           | io_read_mshot           | opdef.c                        | function reference in struct   
io_read_mshot_prep      | opdef.c                   | .prep = io_read_mshot_prep                                       | io_read_mshot_prep      | opdef.c                        | function reference in struct   
io_readv_writev_cleanup | opdef.c                   | .cleanup = io_readv_writev_cleanup                               | io_readv_writev_cleanup | opdef.c                        | function reference in struct   
io_req_assign_buf_node  | net.c                     | io_req_assign_buf_node(sr->notif, node)                          | io_req_assign_buf_node  | net.c                          | function call                  
io_req_end_write        | rw.c                      | io_req_end_write(req)                                            | io_req_end_write        | rw.c                           | function definition            
io_req_io_end          | rw.c                         | struct io_kiocb *req                                | io_req_io_end           | rw.c                           | function definition            
io_req_post_cqe        | io_uring.c                   | struct io_kiocb *req, s32 res, u32 cflags           | io_req_post_cqe         | io_uring.c                     | function definition            
io_req_rw_cleanup      | rw.c                         | struct io_kiocb *req, unsigned int issue_flags      | io_req_rw_cleanup       | rw.c                           | function definition            
io_req_rw_complete     | io_uring.c                   | io_poll_task_func, io_req_rw_complete               | io_req_rw_complete      | io_uring.c                     | function reference             
io_req_set_res         | advise.c                     | req, ret, 0                                          | io_req_set_res          | advise.c                       | function call                  
io_req_task_complete   | futex.c                      | req, ts                                             | io_req_task_complete    | futex.c                        | function call                  
io_req_task_queue      | io_uring.c                   | de->req                                             | io_req_task_queue       | io_uring.c                     | function call                  
__io_req_task_work_add | io_uring.c                   | void __io_req_task_work_add(...)                    | __io_req_task_work_add  | io_uring.c                     | function definition            
do_linkat              | fs.c                         | do_linkat(lnk->old_dfd, ...)                        | do_linkat               | fs.c                           | function call                  
do_mkdirat             | fs.c                         | do_mkdirat(mkd->dfd, ...)                           | do_mkdirat              | fs.c                           | function call                  
do_renameat2           | fs.c                         | do_renameat2(ren->old_dfd, ...)                     | do_renameat2            | fs.c                           | function call                  
do_rmdir               | fs.c                         | do_rmdir(un->dfd, ...)                              | do_rmdir                | fs.c                           | function call                  
do_symlinkat           | fs.c                         | do_symlinkat(sl->oldpath, ...)                      | do_symlinkat            | fs.c                           | function call                  
do_unlinkat            | fs.c                         | do_unlinkat(un->dfd, ...)                           | do_unlinkat             | fs.c                           | function call                  
access_ok              | kbuf.c                       | access_ok(u64_to_user_ptr(...), size)              | access_ok               | kbuf.c                         | function call                  
blkdev_write_iter      | rw.c                         | blkdev_write_iter()                                 | blkdev_write_iter       | rw.c                           | function reference             
cmd_to_io_kiocb        | msg_ring.c                   | cmd_to_io_kiocb(msg)                                | cmd_to_io_kiocb         | msg_ring.c                     | function call                  
complete               | io-wq.c                      | complete(&worker->ref_done)                         | complete                | io-wq.c                        | function call                  
container_of           | cancel.c                     | container_of(work, struct io_kiocb, work)           | container_of            | cancel.c                       | macro                          
copy_from_user         | cancel.c                     | copy_from_user(&sc, arg, sizeof(sc))                | copy_from_user          | cancel.c                       | function call                  
DEFINE_IO_COMP_BATCH   | rw.c                         | DEFINE_IO_COMP_BATCH(iob)                           | DEFINE_IO_COMP_BATCH    | rw.c                           | macro                          
destroy_hrtimer_on_stack | io_uring.c                | destroy_hrtimer_on_stack(&iowq->t)                  | destroy_hrtimer_on_stack | io_uring.c                   | function call                  
dio_complete           | rw.c                         | rw->kiocb.dio_complete = NULL                       | dio_complete            | rw.c                           | field assignment               
file_inode             | io_uring.c                   | file_inode(req->file)                               | file_inode              | io_uring.c                     | function call                  
__folio_lock_async     | rw.c                         | __folio_lock_async()                                | __folio_lock_async      | rw.c                           | function reference             
fsnotify_access        | rw.c                         | fsnotify_access(req->file)                          | fsnotify_access         | rw.c                           | function call                  
fsnotify_modify        | rw.c                         | fsnotify_modify(req->file)                          | fsnotify_modify         | rw.c                           | function call                  
get_current_ioprio     | rw.c                         | get_current_ioprio()                                | get_current_ioprio      | rw.c                           | function call                  
__get_user             | net.c                        | __get_user(clen, &uiov->iov_len)                    | __get_user              | net.c                          | function call                  
hrtimer_cancel         | io_uring.c                   | hrtimer_cancel(&iowq->t)                            | hrtimer_cancel          | io_uring.c                     | function call                  
hrtimer_set_expires    | io_uring.c                   | hrtimer_set_expires(timer, ...)                     | hrtimer_set_expires     | io_uring.c                     | function call                  
hrtimer_setup_sleeper_on_stack | rw.c               | hrtimer_setup_sleeper_on_stack(...)                 | hrtimer_setup_sleeper_on_stack | rw.c                    | function call                  
hrtimer_sleeper_start_expires | rw.c                | hrtimer_sleeper_start_expires(...)                  | hrtimer_sleeper_start_expires | rw.c                    | function call                  
if                     | advise.c                     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                  | if                      | advise.c                       | macro                          
__import_iovec         | net.c                        | __import_iovec(...)                                 | __import_iovec          | net.c                          | function call                  
import_ubuf            | net.c                        | import_ubuf(...)                                    | import_ubuf             | net.c                          | function call                  
INIT_LIST_HEAD         | io-wq.c                      | INIT_LIST_HEAD(&wq->wait.entry)                     | INIT_LIST_HEAD          | io-wq.c                        | macro                          
io_alloc_cache_kasan   | alloc_cache.h                | io_alloc_cache_kasan(...)                           | io_alloc_cache_kasan    | alloc_cache.h                  | function definition            
io_alloc_cache_put     | alloc_cache.h                | io_alloc_cache_put(...)                             | io_alloc_cache_put      | alloc_cache.h                  | function definition            
io_async_buf_func      | rw.c                         | io_async_buf_func(...)                              | io_async_buf_func       | rw.c                           | function definition            
io_buffer_select       | kbuf.c                       | io_buffer_select(req, len)                          | io_buffer_select        | kbuf.c                         | function call                  
io_complete_rw         | rw.c                         | io_complete_rw(kiocb, res)                          | io_complete_rw          | rw.c                           | function definition            
__io_complete_rw_common | rw.c                        | __io_complete_rw_common(req, res)                   | __io_complete_rw_common | rw.c                           | function definition            
io_complete_rw_iopoll  | rw.c                         | io_complete_rw_iopoll(...)                          | io_complete_rw_iopoll   | rw.c                           | function definition            
io_do_buffer_select    | kbuf.h                       | io_do_buffer_select(req)                            | io_do_buffer_select     | kbuf.h                         | function definition            
io_do_iopoll           | io_uring.c                   | io_do_iopoll(ctx, true)                             | io_do_iopoll            | io_uring.c                     | function call                  
io_file_can_poll       | io_uring.c                   | io_file_can_poll(req, ...)                          | io_file_can_poll        | io_uring.c                     | function call                  
io_rsrc_node_lookup    | cancel.c                     | io_rsrc_node_lookup(&ctx->file_table.data, fd)     | io_rsrc_node_lookup     | cancel.c                       | function call                  
io_rw_alloc_async      | rw.c                         | io_rw_alloc_async(req)                              | io_rw_alloc_async       | rw.c                           | function definition            
io_rw_cache_free       | io_uring.c                   | io_alloc_cache_free(...)                            | io_rw_cache_free        | io_uring.c                     | function reference             
io_rw_done             | rw.c                         | io_rw_done(req, ret)                                | io_rw_done              | rw.c                           | function definition            
io_rw_fail             | opdef.c                      | .fail = ...                                         | io_rw_fail              | opdef.c                        | field initializer              
getname                | fs.c                         | getname(oldf)                                       | getname                 | fs.c                           | function call                  
getname_uflags         | fs.c                         | getname_uflags(oldf, flags)                         | getname_uflags          | fs.c                           | function call                  
io_kiocb_to_cmd        | advise.c                     | io_kiocb_to_cmd(req, struct io_madvise)            | io_kiocb_to_cmd         | advise.c                       | function call                  
io_linkat              | fs.c                         | io_linkat(req, flags)                               | io_linkat               | fs.c                           | function definition            
io_linkat_prep         | fs.c                         | io_linkat_prep(req, sqe)                            | io_linkat_prep          | fs.c                           | function definition            
io_link_cleanup        | fs.c                         | io_link_cleanup(req)                                | io_link_cleanup         | fs.c                           | function definition            
io_mkdirat             | fs.c                         | io_mkdirat(req, flags)                              | io_mkdirat              | fs.c                           | function definition            
io_mkdirat_cleanup     | fs.c                         | io_mkdirat_cleanup(req)                             | io_mkdirat_cleanup      | fs.c                           | function definition            
io_mkdirat_prep        | fs.c                         | io_mkdirat_prep(req, sqe)                           | io_mkdirat_prep         | fs.c                           | function definition            
io_renameat            | fs.c                         | io_renameat(req, flags)                             | io_renameat             | fs.c                           | function definition            
io_renameat_cleanup    | fs.c                         | io_renameat_cleanup(req)                            | io_renameat_cleanup     | fs.c                           | function definition            
io_renameat_prep       | fs.c                         | io_renameat_prep(req, sqe)                          | io_renameat_prep        | fs.c                           | function definition            
io_symlinkat           | fs.c                         | io_symlinkat(req, flags)                            | io_symlinkat            | fs.c                           | function definition            
io_symlinkat_prep      | fs.c                         | io_symlinkat_prep(req, sqe)                         | io_symlinkat_prep       | fs.c                           | function definition            
io_unlinkat            | fs.c                         | io_unlinkat(req, flags)                             | io_unlinkat             | fs.c                           | function definition            
io_unlinkat_cleanup    | fs.c                         | io_unlinkat_cleanup(req)                            | io_unlinkat_cleanup     | fs.c                           | function definition            
io_unlinkat_prep       | fs.c                         | io_unlinkat_prep(req, sqe)                          | io_unlinkat_prep        | fs.c                           | function definition            
IS_ERR                 | eventfd.c                    | IS_ERR(ev_fd->cq_ev_fd)                             | IS_ERR                  | eventfd.c                      | macro                          
PTR_ERR                | eventfd.c                    | PTR_ERR(ev_fd->cq_ev_fd)                            | PTR_ERR                 | eventfd.c                      | macro                          
putname                | fs.c                         | putname(ren->oldpath)                               | putname                 | fs.c                           | function call                  
READ_ONCE              | advise.c                     | READ_ONCE(sqe->addr)                                | READ_ONCE               | advise.c                       | macro                          
u64_to_user_ptr        | epoll.c                      | u64_to_user_ptr(...)                                | u64_to_user_ptr         | epoll.c                        | macro                          
unlikely               | cancel.c                     | unlikely(req->flags & REQ_F_BUFFER_SELECT)         | unlikely                | cancel.c                       | macro                          
WARN_ON_ONCE           | advise.c                     | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK)    | WARN_ON_ONCE            | advise.c                       | macro                          
_acquires              | io-wq.c                    | __acquires(&acct->lock)                                         | _acquires              | io-wq.c                         | macro                           
alloc_cpumask_var      | io-wq.c                    | alloc_cpumask_var(&wq->cpu_mask, GFP_KERNEL)                    | alloc_cpumask_var      | io-wq.c                         | function call                   
atomic_andnot          | io_uring.c                 | atomic_andnot(IORING_SQ_CQ_OVERFLOW, &ctx->rings->sq_flags)     | atomic_andnot          | io_uring.c                      | function call                   
atomic_dec_return      | sqpoll.c                   | atomic_dec_return(&sqd->park_pending)                           | atomic_dec_return      | sqpoll.c                        | function call                   
atomic_inc             | io-wq.c                    | atomic_inc(&acct->nr_running)                                   | atomic_inc             | io-wq.c                         | function call                   
atomic_or              | io-wq.c                    | atomic_or(IO_WQ_WORK_CANCEL, &work->flags)                      | atomic_or              | io-wq.c                         | function call                   
atomic_read            | io-wq.c                    | atomic_read(&work->flags)                                       | atomic_read            | io-wq.c                         | function call                   
atomic_set             | eventfd.c                  | atomic_set(&ev_fd->ops, 0)                                      | atomic_set             | eventfd.c                       | function call                   
audit_uring_entry      | io_uring.c                 | audit_uring_entry(req->opcode)                                  | audit_uring_entry      | io_uring.c                      | function call                   
audit_uring_exit       | io_uring.c                 | audit_uring_exit(!ret, ret)                                     | audit_uring_exit       | io_uring.c                      | function call                   
CLASS                  | msg_ring.c                 | CLASS(fd, f)(sqe->fd)                                           | CLASS                  | msg_ring.c                      | macro                           
clear_bit              | io-wq.c                    | clear_bit(IO_WORKER_F_FREE, &worker->flags)                     | clear_bit              | io-wq.c                         | function call                   
complete               | io-wq.c                    | complete(&worker->ref_done)                                     | complete               | io-wq.c                         | function call                   
cond_resched           | io-wq.c                    | cond_resched()                                                  | cond_resched           | io-wq.c                         | function call                   
cpumask_of             | sqpoll.c                   | cpumask_of(sqd->sq_cpu)                                         | cpumask_of             | sqpoll.c                        | function call                   
cpumask_test_cpu       | io-wq.c                    | cpumask_test_cpu(raw_smp_processor_id(), ...)                   | cpumask_test_cpu       | io-wq.c                         | function call                   
cpu_online             | sqpoll.c                   | cpu_online(cpu)                                                 | cpu_online             | sqpoll.c                        | function call                   
cpuset_cpus_allowed    | io-wq.c                    | cpuset_cpus_allowed(data->task, wq->cpu_mask)                   | cpuset_cpus_allowed    | io-wq.c                         | function call                   
create_io_thread       | io-wq.c                    | create_io_thread(io_wq_worker, worker, NUMA_NO_NODE)            | create_io_thread       | io-wq.c                         | function call                   
current_cred           | io_uring.c                 | current_cred()                                                  | current_cred           | io_uring.c                      | function call                   
data_race              | sqpoll.c                   | data_race(sqd->thread)                                          | data_race              | sqpoll.c                        | macro                           
DEFINE_WAIT            | cancel.c                   | DEFINE_WAIT(wait)                                               | DEFINE_WAIT            | cancel.c                        | macro                           
do_exit                | io-wq.c                    | do_exit(0)                                                      | do_exit                | io-wq.c                         | function call                   
ERR_PTR                | io-wq.c                    | ERR_PTR(-EINVAL)                                                | ERR_PTR                | io-wq.c                         | macro                           
fd_empty               | msg_ring.c                 | fd_empty(f)                                                     | fd_empty               | msg_ring.c                      | function call                   
fd_file                | msg_ring.c                 | fd_file(f)                                                      | fd_file                | msg_ring.c                      | function call                   
finish_wait            | cancel.c                   | finish_wait(&ctx->cq_wait, &wait)                               | finish_wait            | cancel.c                        | function call                   
free_cpumask_var       | io-wq.c                    | free_cpumask_var(wq->cpu_mask)                                  | free_cpumask_var       | io-wq.c                         | function call                   
get_current_cred       | io_uring.c                 | get_current_cred()                                              | get_current_cred       | io_uring.c                      | function call                   
getrusage              | fdinfo.c                   | getrusage(sq->thread, RUSAGE_SELF, &sq_usage)                   | getrusage              | fdinfo.c                        | function call                   
get_signal             | io-wq.c                    | get_signal(&ksig)                                               | get_signal             | io-wq.c                         | function call                   
get_task_struct        | io-wq.c                    | get_task_struct(data->task)                                     | get_task_struct        | io-wq.c                         | function call                   
if                     | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)      | if                     | advise.c                        | macro                           
init_completion        | io-wq.c                    | init_completion(&worker->ref_done)                              | init_completion        | io-wq.c                         | function call                   
INIT_LIST_HEAD         | io-wq.c                    | INIT_LIST_HEAD(&wq->wait.entry)                                 | INIT_LIST_HEAD         | io-wq.c                         | macro                           
init_waitqueue_head    | io_uring.c                 | init_waitqueue_head(&ctx->sqo_sq_wait)                          | init_waitqueue_head    | io_uring.c                      | function call                   
io_attach_sq_data      | sqpoll.c                   | io_attach_sq_data(struct io_uring_params *p)                    | io_attach_sq_data      | sqpoll.c                        | function definition             
io_do_iopoll           | io_uring.c                 | io_do_iopoll(ctx, true)                                         | io_do_iopoll           | io_uring.c                      | function call                   
io_get_sq_data         | sqpoll.c                   | io_get_sq_data(struct io_uring_params *p, ...)                  | io_get_sq_data         | sqpoll.c                        | function definition             
io_handle_tw_list      | io_uring.c                 | io_handle_tw_list(struct llist_node *node, ...)                 | io_handle_tw_list      | io_uring.c                      | function definition             
io_is_uring_fops       | filetable.c                | io_is_uring_fops(file)                                          | io_is_uring_fops       | filetable.c                     | function call                   
io_napi                | napi.h                     | io_napi(struct io_ring_ctx *ctx)                                | io_napi                | napi.h                          | inline function                
io_napi_sqpoll_busy_poll| napi.c                   | io_napi_sqpoll_busy_poll()                                      | io_napi_sqpoll_busy_poll| napi.c                         | function definition             
io_put_sq_data                  | register.c               | io_put_sq_data(sqd);                                      | io_put_sq_data               | register.c                 | function call          
io_ring_exit_work              | io_uring.c               | static __cold void io_ring_exit_work(...)                 | io_ring_exit_work            | io_uring.c                 | function definition    
io_run_task_work               | io-wq.c                  | io_run_task_work();                                       | io_run_task_work             | io-wq.c                    | function call          
io_sqd_events_pending          | sqpoll.c                 | static inline bool io_sqd_events_pending(...)             | io_sqd_events_pending        | sqpoll.c                   | inline function        
io_sqd_handle_event            | sqpoll.c                 | static bool io_sqd_handle_event(...)                      | io_sqd_handle_event          | sqpoll.c                   | function definition    
io_sqd_update_thread_idle      | sqpoll.c                 | static __cold void io_sqd_update_thread_idle(...)         | io_sqd_update_thread_idle    | sqpoll.c                   | function definition    
io_sq_offload_create           | io_uring.c               | io_sq_offload_create(ctx, p);                             | io_sq_offload_create         | io_uring.c                 | function call          
io_sqpoll_wait_sq              | io_uring.c               | io_sqpoll_wait_sq(ctx);                                   | io_sqpoll_wait_sq            | io_uring.c                 | function call          
io_sqpoll_wq_cpu_affinity      | register.c               | io_sqpoll_wq_cpu_affinity(ctx, new_mask);                 | io_sqpoll_wq_cpu_affinity    | register.c                 | function call          
io_sqring_entries              | io_uring.c               | unsigned int entries = io_sqring_entries(ctx);            | io_sqring_entries            | io_uring.c                 | function call          
io_sqring_full                 | io_uring.c               | if (!io_sqring_full(ctx))                                 | io_sqring_full               | io_uring.c                 | function call          
__io_sq_thread                 | sqpoll.c                 | static int __io_sq_thread(...)                            | __io_sq_thread               | sqpoll.c                   | function definition    
io_sq_thread                   | io_uring.c               | rely on io_sq_thread to do polling                        | io_sq_thread                 | io_uring.c                 | comment / reference    
io_sq_thread_finish            | io_uring.c               | io_sq_thread_finish(ctx);                                 | io_sq_thread_finish          | io_uring.c                 | function call          
io_sq_thread_park              | io_uring.c               | io_sq_thread_park(sqd);                                   | io_sq_thread_park            | io_uring.c                 | function call          
io_sq_thread_stop              | sqpoll.c                 | void io_sq_thread_stop(...)                               | io_sq_thread_stop            | sqpoll.c                   | function definition    
io_sq_thread_unpark            | io_uring.c               | io_sq_thread_unpark(sqd);                                 | io_sq_thread_unpark          | io_uring.c                 | function call          
io_sq_tw                       | sqpoll.c                 | static unsigned int io_sq_tw(...)                         | io_sq_tw                     | sqpoll.c                   | function definition    
io_sq_tw_pending               | sqpoll.c                 | static bool io_sq_tw_pending(...)                         | io_sq_tw_pending             | sqpoll.c                   | function definition    
io_sq_update_worktime          | sqpoll.c                 | static void io_sq_update_worktime(...)                    | io_sq_update_worktime        | sqpoll.c                   | function definition    
io_submit_sqes                 | io_uring.c               | int io_submit_sqes(...)                                   | io_submit_sqes               | io_uring.c                 | function definition    
io_uring_alloc_task_context    | io_uring.h               | int io_uring_alloc_task_context(...)                      | io_uring_alloc_task_context  | io_uring.h                 | function declaration    
io_uring_cancel_generic        | io_uring.c               | __cold void io_uring_cancel_generic(...)                  | io_uring_cancel_generic      | io_uring.c                 | function definition    
io_uring_register              | register.c               | io_uring_register() syscall                               | io_uring_register            | register.c                 | comment / syscall      
io_wq_cpu_affinity             | io-wq.c                  | int io_wq_cpu_affinity(...)                               | io_wq_cpu_affinity           | io-wq.c                    | function definition    
IS_ERR                         | eventfd.c                | if (IS_ERR(ev_fd->cq_ev_fd))                              | IS_ERR                       | eventfd.c                  | macro                  
kfree                          | alloc_cache.h            | kfree(*iov);                                              | kfree                        | alloc_cache.h              | function call          
kzalloc                        | io-wq.c                  | kzalloc(sizeof(*worker), GFP_KERNEL);                     | kzalloc                      | io-wq.c                    | function call          
likely                         | io-wq.c                  | Most likely an attempt ...                                | likely                       | io-wq.c                    | macro                  
list_add                       | kbuf.c                   | list_add(&buf->list, &bl->buf_list);                      | list_add                     | kbuf.c                     | function call          
list_del_init                  | io-wq.c                  | list_del_init(&wq->wait.entry);                           | list_del_init                | io-wq.c                    | function call          
list_for_each_entry            | cancel.c                 | list_for_each_entry(node, &ctx->tctx_list, ctx_node)      | list_for_each_entry          | cancel.c                   | macro                  
list_is_singular               | napi.c                   | if (list_is_singular(&ctx->napi_list))                    | list_is_singular             | napi.c                     | function call          
llist_empty                    | io_uring.c               | if (!llist_empty(&ctx->work_llist))                       | llist_empty                  | io_uring.c                 | function call          
max                            | io-wq.c                  | below the max number of workers                           | max                          | io-wq.c                    | macro                  
msecs_to_jiffies               | io-wq.c                  | msecs_to_jiffies(worker->init_retries * 5)                | msecs_to_jiffies             | io-wq.c                    | function call          
mutex_init                     | io_uring.c               | mutex_init(&ctx->uring_lock);                             | mutex_init                   | io_uring.c                 | function call          
mutex_lock                     | cancel.c                 | mutex_lock(&ctx->uring_lock);                             | mutex_lock                   | cancel.c                   | function call          
mutex_unlock                   | cancel.c                 | mutex_unlock(&ctx->uring_lock);                           | mutex_unlock                 | cancel.c                   | function call          
need_resched                   | io_uring.c               | if (need_resched())                                       | need_resched                 | io_uring.c                 | function call          
override_creds                 | io_uring.c               | creds = override_creds(req->creds);                       | override_creds               | io_uring.c                 | function call          
percpu_ref_is_dying            | io_uring.h               | if (!percpu_ref_is_dying(&ctx->refs))                     | percpu_ref_is_dying          | io_uring.h                 | function call          
prepare_to_wait                | cancel.c                 | prepare_to_wait(&ctx->cq_wait, &wait, ...)                | prepare_to_wait              | cancel.c                   | function call          
PTR_ERR                        | eventfd.c                | int ret = PTR_ERR(ev_fd->cq_ev_fd);                       | PTR_ERR                      | eventfd.c                  | macro                  
put_task_struct                | io-wq.c                  | put_task_struct(wq->task);                                | put_task_struct              | io-wq.c                    | function call          
raw_smp_processor_id           | io-wq.c                  | raw_smp_processor_id()                                    | raw_smp_processor_id         | io-wq.c                    | function call          
READ_ONCE                      | advise.c                 | ma->addr = READ_ONCE(sqe->addr);                          | READ_ONCE                    | advise.c                   | macro                  
refcount_dec_and_test          | eventfd.c                | refcount_dec_and_test(&ev_fd->refs)                       | refcount_dec_and_test        | eventfd.c                  | function call          
refcount_inc                   | io-wq.c                  | refcount_inc(&data->hash->refs);                          | refcount_inc                 | io-wq.c                    | function call          
refcount_set                   | eventfd.c                | refcount_set(&ev_fd->refs, 1);                            | refcount_set                 | eventfd.c                  | function call          
__releases             | io-wq.c                    | &acct->lock                                                       | __releases              | io-wq.c                         | macro annotation              
revert_creds           | io_uring.c                 | revert_creds(creds);                                              | revert_creds            | io_uring.c                     | function call                 
schedule               | io_uring.c                 | schedule();                                                       | schedule                | io_uring.c                     | function call                 
security_uring_sqpoll  | sqpoll.c                   | ret = security_uring_sqpoll();                                    | security_uring_sqpoll   | sqpoll.c                       | function call                 
set_bit                | io-wq.c                    | set_bit(IO_WORKER_F_FREE, &worker->flags);                        | set_bit                 | io-wq.c                        | function call                 
set_cpus_allowed_ptr   | io-wq.c                    | set_cpus_allowed_ptr(tsk, wq->cpu_mask);                           | set_cpus_allowed_ptr    | io-wq.c                        | function call                 
set_task_comm          | io-wq.c                    | set_task_comm(current, buf);                                      | set_task_comm           | io-wq.c                        | function call                 
signal_pending         | io-wq.c                    | if (signal_pending(current)) {                                    | signal_pending          | io-wq.c                        | function call                 
sizeof                 | alloc_cache.c              | kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);               | sizeof                  | alloc_cache.c                 | keyword                       
smp_mb__after_atomic   | sqpoll.c                   | smp_mb__after_atomic();                                           | smp_mb__after_atomic    | sqpoll.c                      | function call                 
snprintf               | io-wq.c                    | snprintf(buf, sizeof(buf), "iou-wrk-%d", wq->task->pid);          | snprintf                | io-wq.c                        | function call                 
task_work_pending      | fdinfo.c                   | task_work_pending(req->tctx->task));                              | task_work_pending       | fdinfo.c                      | function call                 
task_work_run          | io_uring.h                 | task_work_run();                                                  | task_work_run           | io_uring.h                    | function call                 
tctx_task_work_run     | io_uring.c                 | struct llist_node *tctx_task_work_run(...)                        | tctx_task_work_run      | io_uring.c                    | function definition           
test_bit               | filetable.h                | WARN_ON_ONCE(!test_bit(bit, table->bitmap));                      | test_bit                | filetable.h                   | function call                 
time_after             | io_uring.c                 | if (WARN_ON_ONCE(time_after(jiffies, timeout))) {                 | time_after              | io_uring.c                    | macro (time comparison)       
unlikely               | cancel.c                   | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                   | unlikely                | cancel.c                      | macro (branch prediction)     
wait_event             | sqpoll.c                   | wait_event(sqd->wait, !atomic_read(&sqd->park_pending));          | wait_event              | sqpoll.c                      | macro                         
wait_for_completion    | io-wq.c                    | wait_for_completion(&worker->ref_done);                           | wait_for_completion     | io-wq.c                        | function call                 
wake_up                | io-wq.c                    | wake_up(&wq->hash->wait);                                         | wake_up                 | io-wq.c                        | function call                 
wake_up_new_task       | io-wq.c                    | wake_up_new_task(tsk);                                            | wake_up_new_task        | io-wq.c                        | function call                 
wake_up_process        | io-wq.c                    | wake_up_process(worker->task);                                    | wake_up_process         | io-wq.c                        | function call                 
WARN_ON_ONCE           | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                  | WARN_ON_ONCE            | advise.c                      | macro                         
while                  | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)               | while                   | alloc_cache.c                 | keyword                       
wq_has_sleeper         | io-wq.c                    | if (wq_has_sleeper(&wq->hash->wait))                               | wq_has_sleeper          | io-wq.c                        | function call                 
wq_list_empty          | io-wq.c                    | !wq_list_empty(&acct->work_list);                                 | wq_list_empty           | io-wq.c                        | function call                 
bool                    | advise.c                   | io_fadvise_force_async(struct io_fadvise *fa)                     | bool                    | advise.c                        | function definition             
busy_loop_current_time | napi.c                     | /* napi approximating usecs, reverse busy_loop_current_time */    | busy_loop_current_time | napi.c                          | comment                         
copy_from_user          | cancel.c                   | copy_from_user(&sc, arg, sizeof(sc))                              | copy_from_user          | cancel.c                        | function call                   
copy_to_user            | io_uring.c                 | copy_to_user(params, p, sizeof(*p))                               | copy_to_user            | io_uring.c                      | function call                   
dynamic_tracking_do_busy_loop | napi.c              | dynamic_tracking_do_busy_loop(struct io_ring_ctx *ctx, ...)      | dynamic_tracking_do_busy_loop | napi.c                    | function definition             
guard                   | io_uring.c                 | guard(rcu)();                                                     | guard                   | io_uring.c                      | function call                   
HASH_BITS               | napi.c                     | HASH_BITS(ctx->napi_ht)                                           | HASH_BITS               | napi.c                          | macro                           
hash_del_rcu            | napi.c                     | hash_del_rcu(&e->node)                                            | hash_del_rcu            | napi.c                          | function call                   
hash_min                | napi.c                     | hash_min(napi_id, HASH_BITS(...))                                | hash_min                | napi.c                          | function call                   
hlist_add_tail_rcu      | napi.c                     | hlist_add_tail_rcu(&e->node, hash_list)                           | hlist_add_tail_rcu      | napi.c                          | function call                   
hlist_for_each_entry_rcu| napi.c                     | hlist_for_each_entry_rcu(e, hash_list, node)                      | hlist_for_each_entry_rcu | napi.c                        | macro                           
if                      | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                      | advise.c                        | macro (preprocessor)            
INIT_LIST_HEAD          | io-wq.c                    | INIT_LIST_HEAD(&wq->wait.entry)                                   | INIT_LIST_HEAD          | io-wq.c                         | macro                           
INIT_LIST_HEAD_RCU      | napi.c                     | INIT_LIST_HEAD_RCU(&ctx->napi_list)                               | INIT_LIST_HEAD_RCU      | napi.c                          | macro                           
io_get_time             | io_uring.c                 | start_time = io_get_time(ctx)                                     | io_get_time             | io_uring.c                      | function call                   
io_has_work             | io_uring.c                 | io_has_work(iowq->ctx)                                            | io_has_work             | io_uring.c                      | function call                   
__io_napi_add_id        | napi.c                     | int __io_napi_add_id(...)                                         | __io_napi_add_id        | napi.c                          | function definition             
io_napi_blocking_busy_loop | napi.c                  | io_napi_blocking_busy_loop(ctx, ...)                              | io_napi_blocking_busy_loop | napi.c                     | function definition             
__io_napi_busy_loop     | napi.c                     | __io_napi_busy_loop()                                             | __io_napi_busy_loop     | napi.c                          | comment                         
io_napi_busy_loop_should_end | napi.c               | io_napi_busy_loop_should_end(...)                                 | io_napi_busy_loop_should_end | napi.c                    | function definition             
io_napi_busy_loop_timeout | napi.c                  | io_napi_busy_loop_timeout(...)                                    | io_napi_busy_loop_timeout | napi.c                     | function definition             
__io_napi_del_id        | napi.c                     | int __io_napi_del_id(...)                                         | __io_napi_del_id        | napi.c                          | function definition             
__io_napi_do_busy_loop  | napi.c                     | __io_napi_do_busy_loop(ctx, ...)                                  | __io_napi_do_busy_loop  | napi.c                          | function definition             
io_napi_free            | io_uring.c                 | io_napi_free(ctx)                                                 | io_napi_free            | io_uring.c                      | function call                   
io_napi_hash_find       | napi.c                     | io_napi_hash_find(...)                                            | io_napi_hash_find       | napi.c                          | function definition             
io_napi_init            | io_uring.c                 | io_napi_init(ctx)                                                 | io_napi_init            | io_uring.c                      | function call                   
io_napi_register        | napi.c                     | io_napi_register()                                                | io_napi_register        | napi.c                          | comment                         
io_napi_register_napi   | napi.c                     | int io_napi_register_napi(...)                                    | io_napi_register_napi   | napi.c                          | function definition             
__io_napi_remove_stale  | napi.c                     | __io_napi_remove_stale(ctx)                                       | __io_napi_remove_stale  | napi.c                          | function definition             
io_napi_remove_stale    | napi.c                     | io_napi_remove_stale(ctx, is_stale)                               | io_napi_remove_stale    | napi.c                          | function definition             
io_napi_sqpoll_busy_poll| napi.c                     | io_napi_sqpoll_busy_poll()                                        | io_napi_sqpoll_busy_poll| napi.c                          | comment                         
io_napi_unregister      | napi.c                     | io_napi_unregister()                                              | io_napi_unregister      | napi.c                          | comment                         
io_register_napi        | napi.c                     | int io_register_napi(...)                                         | io_register_napi        | napi.c                          | function definition             
io_should_wake          | io_uring.c                 | io_should_wake(iowq)                                              | io_should_wake          | io_uring.c                      | function call                   
io_unregister_napi      | napi.c                     | int io_unregister_napi(...)                                       | io_unregister_napi      | napi.c                          | function definition             
kfree                   | alloc_cache.h              | kfree(*iov)                                                       | kfree                   | alloc_cache.h                   | function call                   
kfree_rcu               | io-wq.c                    | kfree_rcu(worker, rcu)                                            | kfree_rcu               | io-wq.c                         | function call                   
kmalloc                 | alloc_cache.c              | kmalloc(cache->elem_size, gfp)                                    | kmalloc                 | alloc_cache.c                   | function call                   
ktime_add               | io_uring.c                 | ktime_add(iowq.timeout, start_time)                               | ktime_add               | io_uring.c                      | function call                   
ktime_after             | napi.c                     | return ktime_after(now, end_time)                                 | ktime_after             | napi.c                          | function call                   
ktime_sub               | napi.c                     | ktime_t dt = ktime_sub(...)                                       | ktime_sub               | napi.c                          | function call                   
ktime_to_us             | napi.c                     | ktime_to_us(ctx->napi_busy_poll_dt)                               | ktime_to_us             | napi.c                          | function call                   
list_add_tail_rcu       | io-wq.c                    | list_add_tail_rcu(...)                                            | list_add_tail_rcu       | io-wq.c                         | function call                   
list_del_rcu            | io-wq.c                    | list_del_rcu(...)                                                 | list_del_rcu            | io-wq.c                         | function call                   
list_empty_careful      | io_uring.c                 | list_empty_careful(...)                                           | list_empty_careful      | io_uring.c                      | function call                   
list_for_each_entry     | cancel.c                   | list_for_each_entry(node, ...)                                    | list_for_each_entry     | cancel.c                        | macro                           
list_for_each_entry_rcu | io-wq.c                    | list_for_each_entry_rcu(worker, ...)                              | list_for_each_entry_rcu | io-wq.c                         | macro                           
list_for_each_entry_safe| napi.c                     | list_for_each_entry_safe() is not required ...                    | list_for_each_entry_safe| napi.c                          | comment                         
list_is_singular        | napi.c                     | list_is_singular(&ctx->napi_list)                                 | list_is_singular        | napi.c                          | function call                   
min_t                   | kbuf.c                     | nr_avail = min_t(__u16, ...)                                      | min_t                   | kbuf.c                          | macro                           
napi_busy_loop_rcu      | napi.c                     | napi_busy_loop_rcu(e->napi_id, ...)                               | napi_busy_loop_rcu      | napi.c                          | function call                   
NAPI_TIMEOUT            | napi.c                     | #define NAPI_TIMEOUT (60 * SEC_CONVERSION)                        | NAPI_TIMEOUT            | napi.c                          | macro definition                
net_to_ktime            | napi.c                     | net_to_ktime(unsigned long t)                                     | net_to_ktime            | napi.c                          | function definition             
ns_to_ktime             | napi.c                     | return ns_to_ktime(t << 10)                                       | ns_to_ktime             | napi.c                          | function call                   
READ_ONCE               | advise.c                   | ma->addr = READ_ONCE(sqe->addr)                                   | READ_ONCE               | advise.c                        | function call                   
scoped_guard            | kbuf.c                     | scoped_guard(mutex, &ctx->mmap_lock)                              | scoped_guard            | kbuf.c                          | macro/function                 
signal_pending          | io-wq.c                    | signal_pending(current)                                           | signal_pending          | io-wq.c                         | function call                   
sizeof                  | alloc_cache.c              | sizeof(void *)                                                    | sizeof                  | alloc_cache.c                   | keyword                        
spin_lock               | cancel.c                   | spin_lock(&ctx->completion_lock)                                  | spin_lock               | cancel.c                        | function call                   
spin_lock_init          | io_uring.c                 | spin_lock_init(&ctx->msg_lock)                                    | spin_lock_init          | io_uring.c                      | function call                   
spin_unlock             | cancel.c                   | spin_unlock(&ctx->completion_lock)                                | spin_unlock             | cancel.c                        | function call                   
static_tracking_do_busy_loop | napi.c               | static_tracking_do_busy_loop(...)                                 | static_tracking_do_busy_loop | napi.c                    | function definition             
switch                  | advise.c                   | switch (fa->advice)                                               | switch                  | advise.c                        | conditional branch             
time_after              | io_uring.c                 | time_after(jiffies, timeout)                                      | time_after              | io_uring.c                      | macro                           
unlikely                | cancel.c                   | unlikely(req->flags & REQ_F_BUFFER_SELECT)                        | unlikely                | cancel.c                        | macro                           
while                   | alloc_cache.c              | while ((entry = io_alloc_cache_get(...))                          | while                   | alloc_cache.c                   | keyword                        
WRITE_ONCE              | io_uring.c                 | WRITE_ONCE(...)                                                   | WRITE_ONCE              | io_uring.c                      | macro                           
add_wait_queue           | poll.c           | head, &poll->wait                          | add_wait_queue           | poll.c           | function call
add_wait_queue_exclusive | poll.c           | head, &poll->wait                          | add_wait_queue_exclusive | poll.c           | function call
aio_poll_complete_work   | poll.c           | aio_poll_complete_work()                   | aio_poll_complete_work   | poll.c           | function reference
atomic_andnot            | io_uring.c       | IORING_SQ_CQ_OVERFLOW, &ctx->rings->sq_flags | atomic_andnot          | io_uring.c       | function call
atomic_cmpxchg           | poll.c           | &req->poll_refs, 1, 0                      | atomic_cmpxchg           | poll.c           | function call
atomic_fetch_inc         | poll.c           | &req->poll_refs                            | atomic_fetch_inc         | poll.c           | function call
atomic_fetch_or          | eventfd.c        | BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops | atomic_fetch_or          | eventfd.c        | function call
atomic_or                | io-wq.c          | IO_WQ_WORK_CANCEL, &work->flags            | atomic_or                | io-wq.c          | function call
atomic_read              | io-wq.c          | &work->flags                                | atomic_read              | io-wq.c          | function call
atomic_set               | eventfd.c        | &ev_fd->ops, 0                              | atomic_set               | eventfd.c        | function call
atomic_sub_return        | poll.c           | v, &req->poll_refs                         | atomic_sub_return        | poll.c           | function call
BIT                      | eventfd.c        | IO_EVENTFD_OP_SIGNAL_BIT                   | BIT                      | eventfd.c        | macro
container_of             | cancel.c         | work, struct io_kiocb, work                | container_of             | cancel.c         | macro
demangle_poll            | poll.c           | events                                     | demangle_poll            | poll.c           | function call
GENMASK                  | poll.c           | 29, 0                                      | GENMASK                  | poll.c           | macro
hash_del                 | poll.c           | &req->hash_node                            | hash_del                 | poll.c           | function call
hash_long                | poll.c           | req->cqe.user_data, table->hash_bits       | hash_long                | poll.c           | function call
hlist_add_head           | futex.c          | &req->hash_node, &ctx->futex_list          | hlist_add_head           | futex.c          | function call
hlist_del_init           | futex.c          | &req->hash_node                            | hlist_del_init           | futex.c          | function call
hlist_for_each_entry     | fdinfo.c         | &hb->list, hash_node                       | hlist_for_each_entry     | fdinfo.c         | function call
hlist_for_each_entry_safe| futex.c          | &ctx->futex_list, hash_node                | hlist_for_each_entry_safe| futex.c          | function call
INIT_HLIST_NODE          | poll.c           | &req->hash_node                            | INIT_HLIST_NODE          | poll.c           | macro
init_waitqueue_func_entry| io_uring.c       | &iowq.wq, io_wake_function                 | init_waitqueue_func_entry| io_uring.c       | function call
io_arm_poll_handler      | poll.c           | struct io_kiocb *req, ...                  | __io_arm_poll_handler    | poll.c           | function definition
io_arm_poll_handler      | io_uring.c       | req, issue_flags                           | io_arm_poll_handler      | io_uring.c       | function call
IO_ASYNC_POLL_COMMON     | poll.c           | EPOLLONESHOT | EPOLLPRI                    | IO_ASYNC_POLL_COMMON     | poll.c           | macro
io_async_queue_proc      | poll.c           | struct file *file, struct wait_queue_head *head | io_async_queue_proc  | poll.c           | function definition
io_cache_alloc           | alloc_cache.h    | struct io_alloc_cache *cache, gfp_t gfp   | io_cache_alloc           | alloc_cache.h    | inline function
io_cancel_match_sequence | cancel.c         | req, cd->seq                               | io_cancel_match_sequence | cancel.c         | function call
io_cancel_req_match      | cancel.c         | req, cd                                    | io_cancel_req_match      | cancel.c         | function definition
io_file_can_poll         | io_uring.c       | req                                        | io_file_can_poll         | io_uring.c       | function call
io_init_poll_iocb        | poll.c           | struct io_poll *poll, __poll_t events      | io_init_poll_iocb        | poll.c           | function definition
io_kbuf_recycle          | io_uring.c       | req, 0                                     | io_kbuf_recycle          | io_uring.c       | function call
io_kiocb_to_cmd          | advise.c         | req, struct io_madvise                     | io_kiocb_to_cmd          | advise.c         | macro / cast
io_match_task_safe       | futex.c          | req, tctx, cancel_all                      | io_match_task_safe       | futex.c          | function call
io_napi_add              | napi.h           | -                                          | io_napi_add              | napi.h           | function declaration (commented)
io_poll_add              | opdef.c          | assigned to .issue                         | io_poll_add              | opdef.c          | function reference
io_poll_add_hash         | poll.c           | req, issue_flags                           | io_poll_add_hash         | poll.c           | function definition
io_poll_add_prep         | opdef.c          | assigned to .prep                          | io_poll_add_prep         | opdef.c          | function reference
__io_poll_cancel         | poll.c           | ctx, cd                                    | __io_poll_cancel         | poll.c           | function definition
io_poll_cancel           | cancel.c         | ctx, cd, issue_flags                       | io_poll_cancel           | cancel.c         | function call
io_poll_cancel_req       | poll.c           | req                                        | io_poll_cancel_req       | poll.c           | function definition
io_poll_can_finish_inline| poll.c           | req                                        | io_poll_can_finish_inline| poll.c           | function definition
io_poll_check_events     | poll.c           | req, ts                                    | io_poll_check_events     | poll.c           | function definition
io_poll_disarm           | poll.c           | req                                        | io_poll_disarm           | poll.c           | function definition
io_poll_double_prepare   | poll.c           | req                                        | io_poll_double_prepare   | poll.c           | function definition
__io_poll_execute        | poll.c           | req, mask                                  | __io_poll_execute        | poll.c           | function definition
io_poll_execute          | poll.c           | req, res                                   | io_poll_execute          | poll.c           | inline function
io_poll_file_find        | poll.c           | ctx, ...                                   | io_poll_file_find        | poll.c           | function definition
io_poll_find             | poll.c           | ctx, poll_only, ...                        | io_poll_find             | poll.c           | function definition
io_pollfree_wake         | poll.c           | req, poll                                  | io_pollfree_wake         | poll.c           | function definition
io_poll_get_double          | poll.c        | req                                      | io_poll_get_double         | poll.c        | function definition
io_poll_get_ownership       | poll.c        | req                                      | io_poll_get_ownership      | poll.c        | inline function
io_poll_get_ownership_slowpath| poll.c     | req                                      | io_poll_get_ownership_slowpath | poll.c     | function definition
io_poll_get_single          | poll.c        | req                                      | io_poll_get_single         | poll.c        | function definition
io_poll_issue               | io_uring.c    | req, ts                                  | io_poll_issue              | io_uring.c    | function definition
io_poll_mark_cancelled      | poll.c        | req                                      | io_poll_mark_cancelled     | poll.c        | function definition
io_poll_parse_events        | poll.c        | sqe                                      | io_poll_parse_events       | poll.c        | function definition
io_poll_queue_proc          | poll.c        | file, head                               | io_poll_queue_proc         | poll.c        | function definition
io_poll_remove              | opdef.c       | assigned to .issue                       | io_poll_remove             | opdef.c       | function reference
io_poll_remove_all          | io_uring.c    | ctx, tctx, cancel_all                    | io_poll_remove_all         | io_uring.c    | function call
io_poll_remove_entries      | poll.c        | req                                      | io_poll_remove_entries     | poll.c        | function definition
io_poll_remove_entry        | poll.c        | poll                                     | io_poll_remove_entry       | poll.c        | inline function
io_poll_remove_prep         | opdef.c       | assigned to .prep                        | io_poll_remove_prep        | opdef.c       | function reference
io_poll_req_insert          | poll.c        | req                                      | io_poll_req_insert         | poll.c        | function definition
io_poll_task_func           | io_uring.c    | function reference                       | io_poll_task_func          | io_uring.c    | function reference
IO_POLL_UNMASK              | poll.c        | (EPOLLERR|EPOLLHUP|EPOLLNVAL|EPOLLRDHUP) | IO_POLL_UNMASK             | poll.c        | macro
io_poll_wake                | poll.c        | wait, mode, sync                         | io_poll_wake               | poll.c        | function definition
__io_queue_proc             | poll.c        | poll, pt                                 | __io_queue_proc            | poll.c        | function definition
io_req_alloc_apoll          | poll.c        | req, ...                                 | io_req_alloc_apoll         | poll.c        | function definition
io_req_defer_failed         | io_uring.c    | req, res                                 | io_req_defer_failed        | io_uring.c    | function definition
io_req_post_cqe             | io_uring.c    | req, res, cflags                         | io_req_post_cqe            | io_uring.c    | function definition
io_req_set_res              | advise.c      | req, ret, 0                              | io_req_set_res             | advise.c      | function call
io_req_task_complete        | futex.c       | req, ts                                  | io_req_task_complete       | futex.c       | function call
io_req_task_submit          | io_uring.c    | req, ts                                  | io_req_task_submit         | io_uring.c    | function definition
__io_req_task_work_add      | io_uring.c    | req, flags                               | __io_req_task_work_add     | io_uring.c    | function definition
io_req_task_work_add        | futex.c       | req                                      | io_req_task_work_add       | futex.c       | function call
io_ring_submit_lock         | cancel.c      | ctx, issue_flags                         | io_ring_submit_lock        | cancel.c      | function call
io_ring_submit_unlock       | cancel.c      | ctx, issue_flags                         | io_ring_submit_unlock      | cancel.c      | function call
io_should_terminate_tw      | io_uring.c    | -                                        | io_should_terminate_tw     | io_uring.c    | function call (unlikely)
io_tw_lock                  | futex.c       | ctx, ts                                  | io_tw_lock                 | futex.c       | function call
key_to_poll                 | poll.c        | key                                      | key_to_poll                | poll.c        | function call
kfree                       | alloc_cache.h | *iov                                     | kfree                      | alloc_cache.h | macro/function call
kmalloc                     | alloc_cache.c | cache->elem_size, gfp                    | kmalloc                    | alloc_cache.c | function call
list_del_init               | io-wq.c       | &wq->wait.entry                          | list_del_init              | io-wq.c       | macro/function call
lockdep_assert_held         | futex.c       | &ctx->uring_lock                         | lockdep_assert_held        | futex.c       | macro/assert
mangle_poll                 | poll.c        | req->cqe.res & ...                       | mangle_poll                | poll.c        | function call
poll_refs                   | poll.c        | -                                        | poll_refs                  | poll.c        | variable (comment)
rcu_read_lock               | eventfd.c     | -                                        | rcu_read_lock              | eventfd.c     | function call
rcu_read_unlock             | eventfd.c     | -                                        | rcu_read_unlock            | eventfd.c     | function call
READ_ONCE                   | advise.c      | sqe->addr                                | READ_ONCE                  | advise.c      | macro
req_set_fail                | advise.c      | req                                      | req_set_fail               | advise.c      | function call
return                      | advise.c      | return -EINVAL                           | return                     | advise.c      | keyword
sizeof                      | alloc_cache.c | sizeof(void *)                           | sizeof                     | alloc_cache.c | keyword/operator
smp_load_acquire            | io_uring.c    | -                                        | smp_load_acquire           | io_uring.c    | macro
smp_store_release           | io_uring.c    | -                                        | smp_store_release          | io_uring.c    | macro
spin_lock_irq               | io-wq.c       | &wq->hash->wait.lock                     | spin_lock_irq              | io-wq.c       | function call
spin_unlock_irq             | io-wq.c       | &wq->hash->wait.lock                     | spin_unlock_irq            | io-wq.c       | function call
swahw32                     | poll.c        | events                                   | swahw32                    | poll.c        | function call
trace_io_uring_poll_arm     | poll.c        | req, mask, apoll->poll.events            | trace_io_uring_poll_arm    | poll.c        | trace function
trace_io_uring_task_add     | poll.c        | req, mask                                | trace_io_uring_task_add    | poll.c        | trace function
unlikely                    | cancel.c      | unlikely(...)                            | unlikely                   | cancel.c      | macro
vfs_poll                    | poll.c        | -                                        | vfs_poll                   | poll.c        | function call (comment)
wait                        | cancel.c      | DEFINE_WAIT(wait)                        | wait                       | cancel.c      | macro / wait queue
wake_up_pollfree            | poll.c        | -                                        | wake_up_pollfree           | poll.c        | function call (comment)
WARN_ON_ONCE                | advise.c      | issue_flags                              | WARN_ON_ONCE               | advise.c      | macro
while                       | alloc_cache.c | while ((entry = ...))                    | while                      | alloc_cache.c | keyword
wqe_is_double               | poll.c        | wqe                                      | wqe_is_double              | poll.c        | inline function
wqe_to_req                  | poll.c        | wqe                                      | wqe_to_req                 | poll.c        | inline function
__acquires              | io-wq.c                   | __acquires(&acct->lock)                                        | __acquires              | io-wq.c                        | function call                   
__add_wait_queue        | io-wq.c                   | __add_wait_queue(&wq->hash->wait, &wq->wait)                   | __add_wait_queue        | io-wq.c                        | function call                   
alloc_cpumask_var       | io-wq.c                   | if (!alloc_cpumask_var(&wq->cpu_mask, GFP_KERNEL))             | alloc_cpumask_var       | io-wq.c                        | function call                   
atomic_dec              | io-wq.c                   | atomic_dec(&acct->nr_running)                                  | atomic_dec              | io-wq.c                        | function call                   
atomic_dec_and_test     | io-wq.c                   | if (atomic_dec_and_test(&wq->worker_refs))                     | atomic_dec_and_test     | io-wq.c                        | function call                   
atomic_inc              | io-wq.c                   | atomic_inc(&acct->nr_running)                                  | atomic_inc              | io-wq.c                        | function call                   
atomic_or               | io-wq.c                   | atomic_or(IO_WQ_WORK_CANCEL, &work->flags)                      | atomic_or               | io-wq.c                        | function call                   
atomic_read             | io-wq.c                   | return io_get_acct(wq, !(atomic_read(&work->flags) & IO_WQ_WORK_UNBOUND)) | atomic_read             | io-wq.c                        | function call                   
atomic_set              | eventfd.c                 | atomic_set(&ev_fd->ops, 0)                                      | atomic_set              | eventfd.c                      | function call                   
BIT                     | eventfd.c                 | if (!atomic_fetch_or(BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops)) | BIT                    | eventfd.c                      | macro                          
bool                    | advise.c                  | static bool io_fadvise_force_async(struct io_fadvise *fa)       | bool                   | advise.c                       | type definition                
BUILD_BUG_ON            | io-wq.c                   | BUILD_BUG_ON((int) IO_WQ_ACCT_BOUND   != (int) IO_WQ_BOUND)    | BUILD_BUG_ON            | io-wq.c                        | macro                          
clear_bit               | io-wq.c                   | clear_bit(IO_WORKER_F_FREE, &worker->flags)                    | clear_bit               | io-wq.c                        | function call                   
clear_bit_unlock       | io-wq.c                   | clear_bit_unlock(0, &worker->create_state)                     | clear_bit_unlock       | io-wq.c                        | function call                   
complete                | io-wq.c                   | complete(&worker->ref_done)                                     | complete                | io-wq.c                        | function call                   
cond_resched            | io-wq.c                   | cond_resched()                                                  | cond_resched            | io-wq.c                        | function call                   
container_of            | cancel.c                  | struct io_kiocb *req = container_of(work, struct io_kiocb, work) | container_of            | cancel.c                       | macro                          
Copyright               | io-wq.c                   | * Copyright (C) 2019 Jens Axboe                                 | Copyright               | io-wq.c                        | comment                        
cpuhp_setup_state_multi | io-wq.c                   | ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, "io-wq/online", | cpuhp_setup_state_multi | io-wq.c                        | function call                   
cpuhp_state_add_instance_nocalls | io-wq.c             | ret = cpuhp_state_add_instance_nocalls(io_wq_online, &wq->cpuhp_node) | cpuhp_state_add_instance_nocalls | io-wq.c              | function call                   
cpuhp_state_remove_instance_nocalls | io-wq.c         | cpuhp_state_remove_instance_nocalls(io_wq_online, &wq->cpuhp_node) | cpuhp_state_remove_instance_nocalls | io-wq.c           | function call                   
cpumask_clear_cpu       | io-wq.c                   | cpumask_clear_cpu(od->cpu, worker->wq->cpu_mask)                | cpumask_clear_cpu       | io-wq.c                        | function call                   
cpumask_copy            | io-wq.c                   | cpumask_copy(tctx->io_wq->cpu_mask, mask)                       | cpumask_copy            | io-wq.c                        | function call                   
cpumask_set_cpu         | io-wq.c                   | cpumask_set_cpu(od->cpu, worker->wq->cpu_mask)                  | cpumask_set_cpu         | io-wq.c                        | function call                   
cpumask_subset          | io-wq.c                   | if (cpumask_subset(mask, allowed_mask))                          | cpumask_subset          | io-wq.c                        | function call                   
cpumask_test_cpu        | io-wq.c                   | exit_mask = !cpumask_test_cpu(raw_smp_processor_id(),           | cpumask_test_cpu        | io-wq.c                        | function call                   
cpuset_cpus_allowed     | io-wq.c                   | cpuset_cpus_allowed(data->task, wq->cpu_mask);                  | cpuset_cpus_allowed     | io-wq.c                        | function call                   
create_io_thread        | io-wq.c                   | tsk = create_io_thread(io_wq_worker, worker, NUMA_NO_NODE)     | create_io_thread        | io-wq.c                        | function call                   
create_io_worker        | io-wq.c                   | static bool create_io_worker(struct io_wq *wq, int index)      | create_io_worker        | io-wq.c                        | function call                   
create_worker_cb        | io-wq.c                   | static void create_worker_cb(struct callback_head *cb)         | create_worker_cb        | io-wq.c                        | function definition             
create_worker_cont      | io-wq.c                   | static void create_worker_cont(struct callback_head *cb)       | create_worker_cont      | io-wq.c                        | function definition             
do_exit                 | io-wq.c                   | do_exit(0)                                                      | do_exit                 | io-wq.c                        | function call                   
do_work                 | io-wq.c                   | io_wq_work_fn *do_work;                                         | do_work                 | io-wq.c                        | function call                   
ERR_PTR                 | io-wq.c                   | return ERR_PTR(-EINVAL)                                         | ERR_PTR                 | io-wq.c                        | function call                   
fatal_signal_pending    | io-wq.c                   | if (fatal_signal_pending(current))                               | fatal_signal_pending    | io-wq.c                        | function call                   
fn                      | io-wq.c                   | work_cancel_fn *fn;                                             | fn                      | io-wq.c                        | variable                       
for                     | Makefile                  | # Makefile for io_uring                                         | for                     | Makefile                       | loop                         
free                    | alloc_cache.c             | void (*free)(const void *)                                       | free                    | alloc_cache.c                 | function pointer               
free_cpumask_var        | io-wq.c                   | free_cpumask_var(wq->cpu_mask)                                  | free_cpumask_var        | io-wq.c                        | function call                   
free_work               | io-wq.c                   | free_work_fn *free_work;                                        | free_work               | io-wq.c                        | function pointer               
func                    | futex.c                   | req->io_task_work.func = io_futex_complete;                    | func                    | futex.c                        | variable                       
get_signal              | io-wq.c                   | if (!get_signal(&ksig))                                         | get_signal              | io-wq.c                        | function call                   
get_task_struct         | io-wq.c                   | wq->task = get_task_struct(data->task);                         | get_task_struct         | io-wq.c                        | function call                   
hash_ptr                | io-wq.c                   | bit = hash_ptr(val, IO_WQ_HASH_ORDER);                          | hash_ptr                | io-wq.c                        | function call                   
hlist_entry_safe        | io-wq.c                   | struct io_wq *wq = hlist_entry_safe(node, struct io_wq, cpuhp_node) | hlist_entry_safe        | io-wq.c                        | function call                   
hlist_nulls_add_head_rcu| io-wq.c                   | hlist_nulls_add_head_rcu(&worker->nulls_node, &wq->free_list)   | hlist_nulls_add_head_rcu| io-wq.c                        | function call                   
hlist_nulls_del_init_rcu| io-wq.c                   | hlist_nulls_del_init_rcu(&worker->nulls_node)                   | hlist_nulls_del_init_rcu| io-wq.c                        | function call                   
hlist_nulls_del_rcu     | io-wq.c                   | hlist_nulls_del_rcu(&worker->nulls_node)                        | hlist_nulls_del_rcu     | io-wq.c                        | function call                   
hlist_nulls_for_each_entry_rcu | io-wq.c              | hlist_nulls_for_each_entry_rcu(worker, n, &wq->free_list, nulls_node) { | hlist_nulls_for_each_entry_rcu | io-wq.c                  | function call                   
if                      | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                      | advise.c                       | preprocessor directive         
init_completion         | io-wq.c                   | init_completion(&worker->ref_done);                             | init_completion         | io-wq.c                        | function call                   
INIT_DELAYED_WORK       | io-wq.c                   | INIT_DELAYED_WORK(&worker->work, io_workqueue_create);          | INIT_DELAYED_WORK       | io-wq.c                        | macro                          
INIT_HLIST_NULLS_HEAD   | io-wq.c                   | INIT_HLIST_NULLS_HEAD(&wq->free_list, 0);                       | INIT_HLIST_NULLS_HEAD   | io-wq.c                        | macro                          
INIT_LIST_HEAD          | io-wq.c                   | INIT_LIST_HEAD(&wq->wait.entry);                                | INIT_LIST_HEAD          | io-wq.c                        | macro                          
init_task_work          | io-wq.c                   | init_task_work(&worker->create_work, func);                     | init_task_work          | io-wq.c                        | function call                   
INIT_WQ_LIST            | io-wq.c                   | INIT_WQ_LIST(&acct->work_list);                                  | INIT_WQ_LIST            | io-wq.c                        | macro                          
io_acct_cancel_pending_work | io-wq.c               | static bool io_acct_cancel_pending_work(struct io_wq *wq,        | io_acct_cancel_pending_work | io-wq.c                  | function definition             
__io_acct_run_queue     | io-wq.c                   | static inline bool __io_acct_run_queue(struct io_wq_acct *acct) | __io_acct_run_queue     | io-wq.c                        | function definition             
io_acct_run_queue       | io-wq.c                   | static inline bool io_acct_run_queue(struct io_wq_acct *acct)   | io_acct_run_queue       | io-wq.c                        | function definition             
io_assign_current_work  | io-wq.c                   | static void io_assign_current_work(struct io_worker *worker,    | io_assign_current_work  | io-wq.c                        | function definition             
io_get_acct             | io-wq.c                   | static inline struct io_wq_acct *io_get_acct(struct io_wq *wq, bool bound
io_get_next_work        | io-wq.c                   | struct io_wq_acct *acct                                        | io_get_next_work        | io-wq.c                        | function definition                   
io_get_work_hash        | io-wq.c                   | struct io_wq_work *work                                        | io_get_work_hash        | io-wq.c                        | function definition                   
io_init_new_worker      | io-wq.c                   | struct io_wq *wq, struct io_worker *worker                     | io_init_new_worker      | io-wq.c                        | function definition                   
io_queue_worker_create  | io-wq.c                   | struct io_worker *worker                                        | io_queue_worker_create  | io-wq.c                        | function definition                   
io_run_cancel           | io-wq.c                   | struct io_wq_work *work, struct io_wq *wq                      | io_run_cancel           | io-wq.c                        | function definition                   
io_run_task_work       | io-wq.c                   | io_run_task_work()                                              | io_run_task_work       | io-wq.c                        | function call                       
io_should_retry_thread | io-wq.c                   | struct io_worker *worker, long err                             | io_should_retry_thread | io-wq.c                        | function definition                   
io_task_worker_match   | io-wq.c                   | struct callback_head *cb, void *data                           | io_task_worker_match   | io-wq.c                        | function definition                   
io_task_work_match     | io-wq.c                   | struct callback_head *cb, void *data                           | io_task_work_match     | io-wq.c                        | function definition                   
io_wait_on_hash        | io-wq.c                   | struct io_wq *wq, unsigned int hash                             | io_wait_on_hash        | io-wq.c                        | function definition                   
__io_worker_busy       | io-wq.c                   | struct io_wq *wq, struct io_worker *worker                      | __io_worker_busy       | io-wq.c                        | function definition                   
io_worker_cancel_cb    | io-wq.c                   | struct io_worker *worker                                        | io_worker_cancel_cb    | io-wq.c                        | function definition                   
io_worker_exit         | io-wq.c                   | struct io_worker *worker                                        | io_worker_exit         | io-wq.c                        | function definition                   
io_worker_get          | io-wq.c                   | struct io_worker *worker                                        | io_worker_get          | io-wq.c                        | function definition                   
io_worker_handle_work  | io-wq.c                   | struct io_wq_acct *acct,                                        | io_worker_handle_work  | io-wq.c                        | function definition                   
__io_worker_idle       | io-wq.c                   | struct io_wq *wq, struct io_worker *worker                      | __io_worker_idle       | io-wq.c                        | function definition                   
io_worker_ref_put      | io-wq.c                   | struct io_wq *wq                                                | io_worker_ref_put      | io-wq.c                        | function definition                   
io_worker_release      | io-wq.c                   | struct io_worker *worker                                        | io_worker_release      | io-wq.c                        | function definition                   
io_work_get_acct       | io-wq.c                   | struct io_wq *wq                                                | io_work_get_acct       | io-wq.c                        | function definition                   
io_workqueue_create    | io-wq.c                   | struct work_struct *work                                        | io_workqueue_create    | io-wq.c                        | function definition                   
io_wq_activate_free_worker | io-wq.c               | struct io_wq *wq, struct io_worker *worker                      | io_wq_activate_free_worker | io-wq.c                      | function definition                   
io_wq_cancel_cb        | cancel.c                  | io_wq_cancel_cb(tctx->io_wq, io_cancel_cb, cd, all)            | io_wq_cancel_cb        | io-wq.c                        | function call                       
io_wq_cancel_pending_work | io-wq.c                | struct io_wq *wq                                                | io_wq_cancel_pending_work | io-wq.c                      | function definition                   
io_wq_cancel_running_work | io-wq.c               | struct io_wq *wq                                                | io_wq_cancel_running_work | io-wq.c                      | function definition                   
io_wq_cancel_tw_create | io-wq.c                   | struct io_wq *wq                                                | io_wq_cancel_tw_create | io-wq.c                        | function definition                   
io_wq_cpu_affinity     | io-wq.c                   | struct io_uring_task *tctx, cpumask_var_t mask                  | io_wq_cpu_affinity     | io-wq.c                        | function definition                   
io_wq_cpu_offline      | io-wq.c                   | unsigned int cpu, struct hlist_node *node                        | io_wq_cpu_offline      | io-wq.c                        | function definition                   
__io_wq_cpu_online     | io-wq.c                   | struct io_wq *wq, unsigned int cpu, bool online                  | __io_wq_cpu_online     | io-wq.c                        | function definition                   
io_wq_cpu_online       | io-wq.c                   | unsigned int cpu, struct hlist_node *node                        | io_wq_cpu_online       | io-wq.c                        | function definition                   
io_wq_create           | io-wq.c                   | unsigned bounded, struct io_wq_data *data                        | io_wq_create           | io-wq.c                        | function definition                   
io_wq_create_worker    | io-wq.c                   | struct io_wq *wq, struct io_wq_acct *acct                        | io_wq_create_worker    | io-wq.c                        | function definition                   
io_wq_current_is_worker | cancel.c                 | io_wq_current_is_worker() && tctx != current->io_uring         | io_wq_current_is_worker | cancel.c                     | conditional branch                
io_wq_dec_running      | io-wq.c                   | struct io_worker *worker                                        | io_wq_dec_running      | io-wq.c                        | function definition                   
io_wq_destroy          | io-wq.c                   | struct io_wq *wq                                                | io_wq_destroy          | io-wq.c                        | function definition                   
io_wq_enqueue          | io-wq.c                   | wq, linked                                                      | io_wq_enqueue          | io-wq.c                        | function call                       
io_wq_exit_start       | io-wq.c                   | struct io_wq *wq                                                | io_wq_exit_start       | io-wq.c                        | function definition                   
io_wq_exit_workers     | io-wq.c                   | struct io_wq *wq                                                | io_wq_exit_workers     | io-wq.c                        | function definition                   
io_wq_for_each_worker  | io-wq.c                   | struct io_wq *wq,                                                | io_wq_for_each_worker  | io-wq.c                        | function definition                   
io_wq_get_acct         | io-wq.c                   | struct io_worker *worker                                        | io_wq_get_acct         | io-wq.c                        | function definition                   
io_wq_hash_wake        | io-wq.c                   | struct wait_queue_entry *wait, unsigned mode                     | io_wq_hash_wake        | io-wq.c                        | function definition                   
io_wq_hash_work        | io-wq.c                   | struct io_wq_work *work, void *val                               | io_wq_hash_work        | io-wq.c                        | function definition                   
io_wq_inc_running      | io-wq.c                   | struct io_worker *worker                                        | io_wq_inc_running      | io-wq.c                        | function definition                   
io_wq_init             | io-wq.c                   | void                                                            | io_wq_init             | io-wq.c                        | function definition                   
io_wq_insert_work      | io-wq.c                   | struct io_wq *wq, struct io_wq_work *work                        | io_wq_insert_work      | io-wq.c                        | function definition                   
io_wq_is_hashed        | io-wq.c                   | if (!io_wq_is_hashed(work))                                      | io_wq_is_hashed        | io-wq.c                        | function call                       
io_wq_max_workers      | io-wq.c                   | struct io_wq *wq, int *new_count                                 | io_wq_max_workers      | io-wq.c                        | function definition                   
IO_WQ_NR_HASH_BUCKETS  | io-wq.c                   | (1u << IO_WQ_HASH_ORDER)                                         | IO_WQ_NR_HASH_BUCKETS  | io-wq.c                        | macro                            
io_wq_put_and_exit     | io-wq.c                   | struct io_wq *wq                                                | io_wq_put_and_exit     | io-wq.c                        | function definition                   
io_wq_put_hash         | io-wq.c                   | data->hash                                                       | io_wq_put_hash         | io-wq.c                        | function call                       
io_wq_remove_pending   | io-wq.c                   | struct io_wq *wq                                                | io_wq_remove_pending   | io-wq.c                        | function definition                   
io_wq_worker           | io-wq.c                   | void *data                                                       | io_wq_worker           | io-wq.c                        | function definition                   
io_wq_worker_affinity  | io-wq.c                   | struct io_worker *worker, void *data                             | io_wq_worker_affinity  | io-wq.c                        | function definition                   
__io_wq_worker_cancel  | io-wq.c                   | struct io_worker *worker, void *data                             | __io_wq_worker_cancel  | io-wq.c                        | function definition                   
io_wq_worker_cancel    | io-wq.c                   | struct io_worker *worker, void *data                             | io_wq_worker_cancel    | io-wq.c                        | function definition                   
io_wq_worker_running   | io-wq.c                   | struct task_struct *tsk                                         | io_wq_worker_running   | io-wq.c                        | function definition                   
io_wq_worker_sleeping  | io-wq.c                   | struct task_struct *tsk                                         | io_wq_worker_sleeping  | io-wq.c                        | function definition                   
io_wq_worker_stopped   | io-wq.c                   | bool io_wq_worker_stopped(void)                                  | io_wq_worker_stopped   | io-wq.c                        | function definition                   
io_wq_worker_wake      | io-wq.c                   | struct io_worker *worker, void *data                             | io_wq_worker_wake      | io-wq.c                        | function definition                   
io_wq_work_match_all   | io-wq.c                   | struct io_wq_work *work, void *data                              | io_wq_work_match_all   | io-wq.c                        | function definition                   
io_wq_work_match_item  | io-wq.c                   | struct io_wq_work *work, void *data                              | io_wq_work_match_item  | io-wq.c                        | function definition                   
IS_ERR                | eventfd.c                  | if (IS_ERR(ev_fd->cq_ev_fd))                                     | IS_ERR                | eventfd.c                  | function call               
kfree                  | alloc_cache.h              | kfree(*iov);                                                     | kfree                  | alloc_cache.h              | function call               
kfree_rcu              | io-wq.c                    | kfree_rcu(worker, rcu);                                          | kfree_rcu              | io-wq.c                    | function call               
kzalloc                | io-wq.c                    | worker = kzalloc(sizeof(*worker), GFP_KERNEL);                   | kzalloc                | io-wq.c                    | function call               
likely                 | io-wq.c                    | * Most likely an attempt to queue unbounded work on an io_wq that | likely                 | io-wq.c                    | macro                       
list_add_tail_rcu      | io-wq.c                    | list_add_tail_rcu(&worker->all_list, &wq->all_list);             | list_add_tail_rcu      | io-wq.c                    | function call               
list_del_init          | io-wq.c                    | list_del_init(&wq->wait.entry);                                   | list_del_init          | io-wq.c                    | function call               
list_del_rcu           | io-wq.c                    | list_del_rcu(&worker->all_list);                                 | list_del_rcu           | io-wq.c                    | function call               
list_empty             | io-wq.c                    | if (list_empty(&wq->wait.entry))                                  | list_empty             | io-wq.c                    | function call               
list_for_each_entry_rcu| io-wq.c                    | list_for_each_entry_rcu(worker, &wq->all_list, all_list)         | list_for_each_entry_rcu| io-wq.c                    | function call               
max_t                  | io-wq.c                    | prev[i] = max_t(int, acct->max_workers, prev[i]);                 | max_t                  | io-wq.c                    | function call               
msecs_to_jiffies       | io-wq.c                    | msecs_to_jiffies(worker->init_retries * 5));                     | msecs_to_jiffies       | io-wq.c                    | function call               
__must_hold            | cancel.c                   | __must_hold(&ctx->uring_lock)                                     | __must_hold            | cancel.c                   | function call               
pr_warn_once           | io-wq.c                    | pr_warn_once("io-wq is not configured for unbound workers");      | pr_warn_once           | io-wq.c                    | function call               
PTR_ERR                | eventfd.c                  | int ret = PTR_ERR(ev_fd->cq_ev_fd);                              | PTR_ERR                | eventfd.c                  | function call               
put_task_struct        | io-wq.c                    | put_task_struct(wq->task);                                        | put_task_struct        | io-wq.c                    | function call               
queue_create_worker_retry| io-wq.c                  | static void queue_create_worker_retry(struct io_worker *worker)   | queue_create_worker_retry| io-wq.c                  | function definition         
raw_smp_processor_id   | io-wq.c                    | exit_mask = !cpumask_test_cpu(raw_smp_processor_id(),            | raw_smp_processor_id   | io-wq.c                    | function call               
raw_spin_lock          | io-wq.c                    | raw_spin_lock(&wq->lock);                                         | raw_spin_lock          | io-wq.c                    | function call               
raw_spin_lock_init     | io-wq.c                    | raw_spin_lock_init(&worker->lock);                                | raw_spin_lock_init     | io-wq.c                    | function call               
raw_spin_unlock        | io-wq.c                    | raw_spin_unlock(&wq->lock);                                       | raw_spin_unlock        | io-wq.c                    | function call               
rcu_read_lock         | eventfd.c                  | rcu_read_lock();                                                 | rcu_read_lock         | eventfd.c                  | function call               
rcu_read_unlock       | eventfd.c                  | rcu_read_unlock();                                               | rcu_read_unlock       | eventfd.c                  | function call               
refcount_dec_and_test | eventfd.c                  | if (refcount_dec_and_test(&ev_fd->refs))                         | refcount_dec_and_test | eventfd.c                  | function call               
refcount_inc          | io-wq.c                    | refcount_inc(&data->hash->refs);                                  | refcount_inc          | io-wq.c                    | function call               
refcount_inc_not_zero | eventfd.c                  | if (io_eventfd_trigger(ev_fd) && refcount_inc_not_zero(&ev_fd->refs))| refcount_inc_not_zero | eventfd.c                  | function call               
refcount_set          | eventfd.c                  | refcount_set(&ev_fd->refs, 1);                                    | refcount_set          | eventfd.c                  | function call               
__releases            | io-wq.c                    | __releases(&acct->lock)                                           | __releases            | io-wq.c                    | function call               
schedule_delayed_work | io-wq.c                    | schedule_delayed_work(&worker->work,                             | schedule_delayed_work | io-wq.c                    | function call               
schedule_timeout      | io-wq.c                    | ret = schedule_timeout(WORKER_IDLE_TIMEOUT);                      | schedule_timeout      | io-wq.c                    | function call               
set_bit                | io-wq.c                    | set_bit(IO_WORKER_F_FREE, &worker->flags);                       | set_bit                | io-wq.c                    | function call               
set_cpus_allowed_ptr  | io-wq.c                    | set_cpus_allowed_ptr(tsk, wq->cpu_mask);                         | set_cpus_allowed_ptr  | io-wq.c                    | function call               
__set_current_state   | futex.c                    | __set_current_state(TASK_RUNNING);                                | __set_current_state   | futex.c                    | function call               
set_current_state     | io-wq.c                    | set_current_state(TASK_INTERRUPTIBLE);                            | set_current_state     | io-wq.c                    | function call               
set_mask_bits         | io-wq.c                    | set_mask_bits(&worker->flags, 0,                                  | set_mask_bits         | io-wq.c                    | function call               
__set_notify_signal   | io-wq.c                    | __set_notify_signal(worker->task);                                | __set_notify_signal   | io-wq.c                    | function call               
set_task_comm         | io-wq.c                    | set_task_comm(current, buf);                                      | set_task_comm         | io-wq.c                    | function call               
signal_pending        | io-wq.c                    | if (signal_pending(current))                                      | signal_pending        | io-wq.c                    | function call               
sizeof                | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL); | sizeof                | alloc_cache.c              | function call               
snprintf              | io-wq.c                    | snprintf(buf, sizeof(buf), "iou-wrk-%d", wq->task->pid);         | snprintf              | io-wq.c                    | function call               
spin_lock_irq         | io-wq.c                    | spin_lock_irq(&wq->hash->wait.lock);                              | spin_lock_irq         | io-wq.c                    | function call               
spin_unlock_irq       | io-wq.c                    | spin_unlock_irq(&wq->hash->wait.lock);                            | spin_unlock_irq       | io-wq.c                    | function call               
subsys_initcall       | io-wq.c                    | subsys_initcall(io_wq_init);                                      | subsys_initcall       | io-wq.c                    | function call               
switch                | advise.c                   | switch (fa->advice)                                               | switch                | advise.c                   | conditional branch             
task                  | cancel.c                   | ret = io_async_cancel_one(node->task->io_uring, cd);             | task                  | cancel.c                   | function call               
task_rlimit           | io-wq.c                    | task_rlimit(current, RLIMIT_NPROC);                               | task_rlimit           | io-wq.c                    | function call               
task_work_add         | io-wq.c                    | if (!task_work_add(wq->task, &worker->create_work, TWA_SIGNAL))   | task_work_add         | io-wq.c                    | function call               
task_work_cancel_match| io-wq.c                    | struct callback_head *cb = task_work_cancel_match(wq->task,       | task_work_cancel_match| io-wq.c                    | function call               
test_and_clear_bit    | io-wq.c                    | if (test_and_clear_bit(IO_ACCT_STALLED_BIT, &acct->flags))       | test_and_clear_bit    | io-wq.c                    | function call               
test_and_set_bit      | io-wq.c                    | if (!test_and_set_bit(hash, &wq->hash->map))                     | test_and_set_bit      | io-wq.c                    | function call               
test_and_set_bit_lock | futex.c                    | test_and_set_bit_lock(0, &iof->futexv_owned))                   | test_and_set_bit_lock | futex.c                    | function call               
test_bit              | filetable.h                | WARN_ON_ONCE(!test_bit(bit, table->bitmap));                     | test_bit              | filetable.h                | function call               
unlikely              | cancel.c                   | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                  | unlikely              | cancel.c                   | conditional branch             
wait_for_completion   | io-wq.c                    | wait_for_completion(&worker->ref_done);                           | wait_for_completion   | io-wq.c                    | function call               
wake_up               | io-wq.c                    | wake_up(&wq->hash->wait);                                         | wake_up               | io-wq.c                    | function call               
wake_up_new_task      | io-wq.c                    | wake_up_new_task(tsk);                                            | wake_up_new_task      | io-wq.c                    | function call               
wake_up_process       | io-wq.c                    | wake_up_process(worker->task);                                    | wake_up_process       | io-wq.c                    | function call               
WARN_ON_ONCE          | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                 | WARN_ON_ONCE          | advise.c                   | function call               
while                 | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)               | while                 | alloc_cache.c              | loop                       
WORKER_IDLE_TIMEOUT   | io-wq.c                    | #define WORKER_IDLE_TIMEOUT	(5 * HZ)                              | WORKER_IDLE_TIMEOUT   | io-wq.c                    | macro                       
wq_has_sleeper        | io-wq.c                    | if (wq_has_sleeper(&wq->hash->wait))                              | wq_has_sleeper        | io-wq.c                    | function call               
wq_list_add_after     | io-wq.c                    | wq_list_add_after(&work->list, &tail->list, &acct->work_list);    | wq_list_add_after     | io-wq.c                    | function call               
wq_list_add_tail      | io-wq.c                    | wq_list_add_tail(&work->list, &acct->work_list);                  | wq_list_add_tail      | io-wq.c                    | function call               
wq_list_cut           | io-wq.c                    | wq_list_cut(&acct->work_list, &tail->list, prev);                 | wq_list_cut           | io-wq.c                    | function call               
wq_list_del           | io-wq.c                    | wq_list_del(&acct->work_list, node, prev);                        | wq_list_del           | io-wq.c                    | function call               
wq_list_empty         | io-wq.c                    | !wq_list_empty(&acct->work_list);                                 | wq_list_empty         | io-wq.c                    | function call               
wq_list_for_each      | io-wq.c                    | wq_list_for_each(node, prev, &acct->work_list) {                  | wq_list_for_each      | io-wq.c                    | function call               
wq_next_work          | io-wq.c                    | next_hashed = wq_next_work(work);                                 | wq_next_work          | io-wq.c                    | function call 
copy_from_user         | cancel.c                   | &sc, arg, sizeof(sc)                                              | copy_from_user          | cancel.c                        | function call
defined                | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | defined                 | advise.c                        | macro
do_epoll_ctl           | epoll.c                    | komentar: "calls do_epoll_ctl()"                                  | do_epoll_ctl            | epoll.c                         | function reference
ep_op_has_event        | epoll.c                    | epoll->op                                                         | ep_op_has_event         | epoll.c                         | function call
execution              | epoll.c                    | komentar: flags controlling request execution                     | execution               | epoll.c                         | doc/comment
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro
io_epoll_ctl           | epoll.c                    | komentar: Handles epoll_ctl operations                            | io_epoll_ctl            | epoll.c                         | function definition
io_epoll_ctl_prep      | epoll.c                    | req, sqe                                                          | io_epoll_ctl_prep       | epoll.c                         | function definition
io_kiocb_to_cmd        | advise.c                   | req, struct io_madvise                                            | io_kiocb_to_cmd         | advise.c                        | function call
io_req_set_res         | advise.c                   | req, ret, 0                                                       | io_req_set_res          | advise.c                        | function call
READ_ONCE              | advise.c                   | sqe->addr                                                         | READ_ONCE               | advise.c                        | function call
req_set_fail           | advise.c                   | req                                                               | req_set_fail            | advise.c                        | function call
sizeof                 | alloc_cache.c              | sizeof(void *)                                                    | sizeof                  | alloc_cache.c                   | macro
u64_to_user_ptr        | epoll.c                    | READ_ONCE(sqe->addr)                                              | u64_to_user_ptr         | epoll.c                         | function call
_acquires               | io-wq.c                     | &acct->lock                                                   | __acquires               | io-wq.c                        | macro                         
ALIGN                   | io_uring.c                  | off, SMP_CACHE_BYTES                                          | ALIGN                    | io_uring.c                     | macro                         
alloc_workqueue         | io_uring.c                  | "iou_exit", WQ_UNBOUND, 64                                    | alloc_workqueue          | io_uring.c                     | function call                
anon_inode_create_getfile | io_uring.c               | "[io_uring]", &io_uring_fops, ctx                             | anon_inode_create_getfile| io_uring.c                     | function call                
array_index_nospec      | io_uring.c                  | opcode, IORING_OP_LAST                                        | array_index_nospec       | io_uring.c                     | function call                
array_size              | io_uring.c                  | sizeof(u32), sq_entries                                       | array_size               | io_uring.c                     | function call                
ARRAY_SIZE              | cancel.c                    | sc.pad                                                        | ARRAY_SIZE               | cancel.c                       | macro                         
atomic_andnot           | io_uring.c                  | IORING_SQ_CQ_OVERFLOW, &ctx->rings->sq_flags                  | atomic_andnot            | io_uring.c                     | function call                
atomic_dec              | io-wq.c                     | &acct->nr_running                                             | atomic_dec               | io-wq.c                        | function call                
atomic_inc              | io-wq.c                     | &acct->nr_running                                             | atomic_inc               | io-wq.c                        | function call                
atomic_or               | io-wq.c                     | IO_WQ_WORK_CANCEL, &work->flags                               | atomic_or                | io-wq.c                        | function call                
atomic_read             | io-wq.c                     | &work->flags                                                  | atomic_read              | io-wq.c                        | function call                
atomic_set              | eventfd.c                   | &ev_fd->ops, 0                                                | atomic_set               | eventfd.c                      | function call                
audit_uring_entry       | io_uring.c                  | req->opcode                                                   | audit_uring_entry        | io_uring.c                     | function call                
audit_uring_exit        | io_uring.c                  | !ret, ret                                                     | audit_uring_exit         | io_uring.c                     | function call                
autoremove_wake_function| io_uring.c                  | curr, mode, wake_flags, key                                   | autoremove_wake_function | io_uring.c                     | function call                
BIT                     | eventfd.c                   | IO_EVENTFD_OP_SIGNAL_BIT, &ev_fd->ops                         | BIT                      | eventfd.c                      | macro                         
blk_finish_plug         | io_uring.c                  | &state->plug                                                  | blk_finish_plug          | io_uring.c                     | function call                
blk_start_plug_nr_ios   | io_uring.c                  | &state->plug, state->submit_nr                                | blk_start_plug_nr_ios    | io_uring.c                     | function call                
BUG_ON                  | io_uring.c                  | !tctx                                                         | BUG_ON                   | io_uring.c                     | macro                         
BUILD_BUG_ON            | io-wq.c                     | IO_WQ_ACCT_BOUND != IO_WQ_BOUND                               | BUILD_BUG_ON             | io-wq.c                        | macro                         
BUILD_BUG_SQE_ELEM      | io_uring.c                  | eoffset, etype, ename                                         | BUILD_BUG_SQE_ELEM       | io_uring.c                     | macro                         
BUILD_BUG_SQE_ELEM_SIZE | io_uring.c                  | eoffset, esize, ename                                         | BUILD_BUG_SQE_ELEM_SIZE  | io_uring.c                     | macro                         
__BUILD_BUG_VERIFY_OFFSET_SIZE | io_uring.c         | stype, eoffset, esize, ename                                  | __BUILD_BUG_VERIFY_OFFSET_SIZE | io_uring.c              | macro                         
capable                 | io_uring.c                  | CAP_SYS_ADMIN                                                 | capable                  | io_uring.c                     | function call                
check_add_overflow      | filetable.c                 | range.off, range.len, &end                                    | check_add_overflow       | filetable.c                    | function call                
check_shl_overflow      | io_uring.c                  | off, 1, &off                                                  | check_shl_overflow       | io_uring.c                     | function call                
clamp                   | io_uring.c                  | hash_bits, 1, 8                                               | clamp                    | io_uring.c                     | function call                
cleanup                 | io_uring.c                  | def->cleanup                                                  | cleanup                  | io_uring.c                     | variable access              
clear_bit               | io-wq.c                     | IO_WORKER_F_FREE, &worker->flags                              | clear_bit                | io-wq.c                        | function call                
complete                | io-wq.c                     | &worker->ref_done                                             | complete                 | io-wq.c                        | function call                
cond_resched            | io-wq.c                     | (none)                                                        | cond_resched             | io-wq.c                        | function call                
container_of            | cancel.c                    | work, struct io_kiocb, work                                   | container_of             | cancel.c                       | macro                         
copy_from_user          | cancel.c                    | &sc, arg, sizeof(sc)                                          | copy_from_user           | cancel.c                       | function call                
copy_to_user            | io_uring.c                  | params, p, sizeof(*p)                                         | copy_to_user             | io_uring.c                     | function call                
ctx_flush_and_put       | io_uring.c                  | ctx, ts                                                       | ctx_flush_and_put        | io_uring.c                     | function definition          
current_cred            | io_uring.c                  | current_cred()                                                | current_cred             | io_uring.c                     | function call                
current_pending_io      | io_uring.c                  | (none)                                                        | current_pending_io       | io_uring.c                     | function definition          
current_user            | io_uring.c                  | current_user()                                                | current_user             | io_uring.c                     | function call                
DEFINE_STATIC_KEY_FALSE| io_uring.c                  | io_key_has_sqarray                                            | DEFINE_STATIC_KEY_FALSE  | io_uring.c                     | macro                         
DEFINE_WAIT             | cancel.c                    | wait                                                           | DEFINE_WAIT              | cancel.c                       | macro                         
destroy_hrtimer_on_stack | io_uring.c                | &iowq->t                                                      | destroy_hrtimer_on_stack | io_uring.c                     | function call                
entries                | alloc_cache.c              | if (!cache->entries)                                            | entries                 | alloc_cache.c                   | macro                          
ERR_PTR                | io-wq.c                    | return ERR_PTR(-EINVAL);                                        | ERR_PTR                 | io-wq.c                         | function call                   
fail                   | fdinfo.c                   | If we fail to get the lock                                      | fail                    | fdinfo.c                        | keyword                        
fd_install             | io_uring.c                 | fd_install(fd, file);                                           | fd_install              | io_uring.c                      | function call                   
fget                   | cancel.c                   | file = fget(sc.fd);                                             | fget                    | cancel.c                        | function call                   
file_inode             | io_uring.c                 | file_inode(req->file)                                           | file_inode              | io_uring.c                      | function call                   
finish_wait            | cancel.c                   | finish_wait(&ctx->cq_wait, &wait);                              | finish_wait             | cancel.c                        | function call                   
flush_delayed_work     | io_uring.c                 | flush_delayed_work(&last_ctx->fallback_work);                   | flush_delayed_work      | io_uring.c                      | function call                   
for                    | Makefile                   | Makefile for io_uring                                           | for                     | Makefile                        | keyword                        
fput                   | cancel.c                   | fput(file);                                                     | fput                    | cancel.c                        | function call                   
free_uid               | io_uring.c                 | free_uid(ctx->user);                                            | free_uid                | io_uring.c                      | function call                   
func                   | futex.c                    | req->io_task_work.func = io_futex_complete;                     | func                    | futex.c                         | function pointer               
get_cred               | io_uring.c                 | get_cred(req->creds);                                           | get_cred                | io_uring.c                      | function call                   
get_current_cred       | io_uring.c                 | req->creds = get_current_cred();                                | get_current_cred        | io_uring.c                      | function call                   
get_task_struct        | io-wq.c                    | get_task_struct(data->task);                                    | get_task_struct         | io-wq.c                         | function call                   
get_timespec64         | io_uring.c                 | get_timespec64(&ext_arg->ts, u64_to_user_ptr(arg.ts))           | get_timespec64          | io_uring.c                      | function call                   
get_uid                | io_uring.c                 | ctx->user = get_uid(current_user());                            | get_uid                 | io_uring.c                      | function call                   
get_unused_fd_flags    | io_uring.c                 | get_unused_fd_flags(O_RDWR | O_CLOEXEC);                        | get_unused_fd_flags     | io_uring.c                      | function call                   
gid_valid              | io_uring.c                 | if (!gid_valid(io_uring_group))                                 | gid_valid               | io_uring.c                      | function call                   
guard                  | io_uring.c                 | guard(rcu)();                                                   | guard                   | io_uring.c                      | macro                          
head                   | fdinfo.c                   | unsigned int sq_head = READ_ONCE(r->sq.head);                   | head                    | fdinfo.c                        | variable                       
held                   | eventfd.c                  | * lock held.                                                    | held                    | eventfd.c                       | comment                        
hrtimer_cancel         | io_uring.c                 | hrtimer_cancel(&iowq->t);                                       | hrtimer_cancel          | io_uring.c                      | function call                   
hrtimer_set_expires    | io_uring.c                 | hrtimer_set_expires(timer, iowq->timeout);                      | hrtimer_set_expires     | io_uring.c                      | function call                   
hrtimer_set_expires_range_ns | io_uring.c           | hrtimer_set_expires_range_ns(&iowq->t, timeout, 0);             | hrtimer_set_expires_range_ns | io_uring.c                | function call                   
hrtimer_setup_on_stack | io_uring.c                 | hrtimer_setup_on_stack(&iowq->t, io_cqring_min_timer_wakeup, ...) | hrtimer_setup_on_stack | io_uring.c                      | function call                   
hrtimer_start_expires  | io_uring.c                 | hrtimer_start_expires(&iowq->t, HRTIMER_MODE_ABS);              | hrtimer_start_expires   | io_uring.c                      | function call                   
if                     | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)      | if                      | advise.c                        | macro                          
ilog2                  | io_uring.c                 | hash_bits = ilog2(p->cq_entries) - 5;                            | ilog2                   | io_uring.c                      | function call                   
in_compat_syscall      | io_uring.c                 | if (in_compat_syscall())                                        | in_compat_syscall       | io_uring.c                      | function call                   
INDIRECT_CALL_2        | io_uring.c                 | INDIRECT_CALL_2(req->io_task_work.func, ...)                    | INDIRECT_CALL_2         | io_uring.c                      | macro                          
in_group_p             | io_uring.c                 | return in_group_p(io_uring_group);                              | in_group_p              | io_uring.c                      | function call                   
__initcall             | io_uring.c                 | __initcall(io_uring_init);                                      | __initcall              | io_uring.c                      | macro                          
init_completion        | io-wq.c                    | init_completion(&worker->ref_done);                             | init_completion         | io-wq.c                         | function call                   
INIT_DELAYED_WORK      | io-wq.c                    | INIT_DELAYED_WORK(&worker->work, io_workqueue_create);          | INIT_DELAYED_WORK       | io-wq.c                         | macro                          
INIT_HLIST_HEAD        | io_uring.c                 | INIT_HLIST_HEAD(&table->hbs[i].list);                           | INIT_HLIST_HEAD         | io_uring.c                      | macro                          
INIT_LIST_HEAD         | io-wq.c                    | INIT_LIST_HEAD(&wq->wait.entry);                                | INIT_LIST_HEAD          | io-wq.c                         | macro                          
init_llist_head        | io_uring.c                 | init_llist_head(&ctx->work_llist);                              | init_llist_head         | io_uring.c                      | function call                   
init_task_work         | io-wq.c                    | init_task_work(&worker->create_work, func);                     | init_task_work          | io-wq.c                         | function call                   
init_waitqueue_func_entry | io_uring.c             | init_waitqueue_func_entry(&iowq.wq, io_wake_function);          | init_waitqueue_func_entry | io_uring.c                   | function call                   
init_waitqueue_head    | io_uring.c                 | init_waitqueue_head(&ctx->sqo_sq_wait);                         | init_waitqueue_head     | io_uring.c                      | function call                   
INIT_WORK              | io_uring.c                 | INIT_WORK(&ctx->exit_work, io_ring_exit_work);                  | INIT_WORK               | io_uring.c                      | macro                          
INIT_WQ_LIST           | io-wq.c                    | INIT_WQ_LIST(&acct->work_list);                                 | INIT_WQ_LIST            | io-wq.c                         | macro                          
io_account_cq_overflow | io_uring.c                 | static void io_account_cq_overflow(struct io_ring_ctx *ctx)     | io_account_cq_overflow  | io_uring.c                      | function definition             
io_activate_pollwq     | io_uring.c                 | void io_activate_pollwq(struct io_ring_ctx *ctx)                | io_activate_pollwq      | io_uring.c                      | function definition             
io_activate_pollwq_cb  | io_uring.c                 | static void io_activate_pollwq_cb(struct callback_head *cb)     | io_activate_pollwq_cb   | io_uring.c                      | function definition             
io_add_aux_cqe         | io_uring.c                 | void io_add_aux_cqe(struct io_ring_ctx *ctx, ...)               | io_add_aux_cqe          | io_uring.c                      | function definition             
io_allocate_scq_urings | io_uring.c                 | static int io_allocate_scq_urings(struct io_ring_ctx *ctx, ...) | io_allocate_scq_urings  | io_uring.c                      | function definition             
io_alloc_cache_free    | alloc_cache.c              | void io_alloc_cache_free(struct io_alloc_cache *cache, ...)     | io_alloc_cache_free     | alloc_cache.c                   | function definition             
io_alloc_cache_init    | alloc_cache.c              | bool io_alloc_cache_init(struct io_alloc_cache *cache)          | io_alloc_cache_init     | alloc_cache.c                   | function definition             
io_alloc_cache_put         | alloc_cache.h   | static inline bool io_alloc_cache_put(...)                      | io_alloc_cache_put          | alloc_cache.h   | function       
io_alloc_hash_table        | io_uring.c      | static int io_alloc_hash_table(...)                             | io_alloc_hash_table         | io_uring.c      | function       
io_alloc_req               | io_uring.c      | * io_alloc_req() should be called only under ->uring_lock       | io_alloc_req                | io_uring.c      | comment        
__io_alloc_req_refill      | io_uring.c      | __cold bool __io_alloc_req_refill(...)                          | __io_alloc_req_refill       | io_uring.c      | function       
io_allowed_defer_tw_run    | io_uring.c      | io_allowed_defer_tw_run(ctx))                                   | io_allowed_defer_tw_run     | io_uring.c      | function call  
io_allowed_run_tw          | io_uring.c      | if (!io_allowed_run_tw(ctx))                                    | io_allowed_run_tw           | io_uring.c      | function call  
__io_arm_ltimeout          | io_uring.c      | static noinline void __io_arm_ltimeout(...)                     | __io_arm_ltimeout           | io_uring.c      | function       
io_arm_ltimeout            | io_uring.c      | static inline void io_arm_ltimeout(...)                         | io_arm_ltimeout             | io_uring.c      | function       
io_arm_poll_handler        | io_uring.c      | if (io_arm_poll_handler(...) != IO_APOLL_OK)                    | io_arm_poll_handler         | io_uring.c      | function call  
io_assign_file             | io_uring.c      | static bool io_assign_file(...)                                 | io_assign_file              | io_uring.c      | function       
io_cancel_ctx_cb           | io_uring.c      | static __cold bool io_cancel_ctx_cb(...)                        | io_cancel_ctx_cb            | io_uring.c      | function       
io_cancel_defer_files      | io_uring.c      | static __cold bool io_cancel_defer_files(...)                   | io_cancel_defer_files       | io_uring.c      | function       
io_cancel_task_cb          | io_uring.c      | static bool io_cancel_task_cb(...)                              | io_cancel_task_cb           | io_uring.c      | function       
io_check_restriction       | io_uring.c      | static inline bool io_check_restriction(...)                    | io_check_restriction        | io_uring.c      | function       
io_clean_op                | io_uring.c      | static void io_clean_op(...)                                    | io_clean_op                 | io_uring.c      | function       
io_commit_cqring           | io_uring.c      | io_commit_cqring(ctx);                                          | io_commit_cqring            | io_uring.c      | function call  
__io_commit_cqring_flush   | io_uring.c      | void __io_commit_cqring_flush(...)                              | __io_commit_cqring_flush    | io_uring.c      | function       
io_commit_cqring_flush     | io_uring.c      | io_commit_cqring_flush(ctx);                                    | io_commit_cqring_flush      | io_uring.c      | function call  
io_commit_sqring           | io_uring.c      | static void io_commit_sqring(...)                               | io_commit_sqring            | io_uring.c      | function       
io_cqe_cache_refill        | io_uring.c      | bool io_cqe_cache_refill(...)                                   | io_cqe_cache_refill         | io_uring.c      | function       
__io_cq_lock               | io_uring.c      | static inline void __io_cq_lock(...)                            | __io_cq_lock                | io_uring.c      | function       
io_cq_lock                 | io_uring.c      | static inline void io_cq_lock(...)                              | io_cq_lock                  | io_uring.c      | function       
io_cqring_do_overflow_flush| io_uring.c      | static void io_cqring_do_overflow_flush(...)                    | io_cqring_do_overflow_flush | io_uring.c      | function       
io_cqring_event_overflow   | io_uring.c      | static bool io_cqring_event_overflow(...)                       | io_cqring_event_overflow    | io_uring.c      | function       
__io_cqring_events         | io_uring.c      | static inline unsigned int __io_cqring_events(...)              | __io_cqring_events          | io_uring.c      | function       
io_cqring_events           | io_uring.c      | static unsigned io_cqring_events(...)                           | io_cqring_events            | io_uring.c      | function       
__io_cqring_events_user    | io_uring.c      | static inline unsigned int __io_cqring_events_user(...)         | __io_cqring_events_user     | io_uring.c      | function       
io_cqring_min_timer_wakeup | io_uring.c      | static enum hrtimer_restart io_cqring_min_timer_wakeup(...)     | io_cqring_min_timer_wakeup  | io_uring.c      | function       
__io_cqring_overflow_flush | io_uring.c      | static void __io_cqring_overflow_flush(...)                     | __io_cqring_overflow_flush  | io_uring.c      | function       
io_cqring_overflow_kill    | io_uring.c      | static void io_cqring_overflow_kill(...)                        | io_cqring_overflow_kill     | io_uring.c      | function   
io_cqring_schedule_timeout  | io_uring.c      | static int io_cqring_schedule_timeout(...)                       | io_cqring_schedule_timeout  | io_uring.c      | function       
io_cqring_timer_wakeup      | io_uring.c      | static enum hrtimer_restart io_cqring_timer_wakeup(...)          | io_cqring_timer_wakeup      | io_uring.c      | function       
io_cqring_wait              | io_uring.c      | * in set_current_state() on the io_cqring_wait() side.           | io_cqring_wait              | io_uring.c      | comment        
__io_cqring_wait_schedule   | io_uring.c      | static int __io_cqring_wait_schedule(...)                        | __io_cqring_wait_schedule   | io_uring.c      | function       
io_cqring_wait_schedule     | io_uring.c      | static inline int io_cqring_wait_schedule(...)                   | io_cqring_wait_schedule     | io_uring.c      | function       
io_cqring_wake              | io_uring.c      | io_cqring_wake(ctx);                                            | io_cqring_wake              | io_uring.c      | function call  
__io_cq_unlock_post         | io_uring.c      | static inline void __io_cq_unlock_post(...)                     | __io_cq_unlock_post         | io_uring.c      | function       
io_cq_unlock_post           | io_uring.c      | static void io_cq_unlock_post(...)                               | io_cq_unlock_post           | io_uring.c      | function       
IO_CQ_WAKE_FORCE            | io_uring.c      | #define IO_CQ_WAKE_FORCE (IO_CQ_WAKE_INIT >> 1)                  | IO_CQ_WAKE_FORCE            | io_uring.c      | macro          
IO_CQ_WAKE_INIT             | io_uring.c      | #define IO_CQ_WAKE_INIT (-1U)                                    | IO_CQ_WAKE_INIT             | io_uring.c      | macro          
io_create_region            | io_uring.c      | ret = io_create_region(ctx, &ctx->ring_region, &rd, IORING_OFF_CQ_RING); | io_create_region           | io_uring.c      | function call  
io_destroy_buffers          | io_uring.c      | io_destroy_buffers(ctx);                                        | io_destroy_buffers          | io_uring.c      | function call  
IO_DISARM_MASK              | io_uring.c      | #define IO_DISARM_MASK (REQ_F_ARM_LTIMEOUT | REQ_F_LINK_TIMEOUT | REQ_F_FAIL) | IO_DISARM_MASK            | io_uring.c      | macro          
io_disarm_next              | io_uring.c      | requests with any of those set should undergo io_disarm_next()   | io_disarm_next              | io_uring.c      | function       
io_do_iopoll                | io_uring.c      | if (io_do_iopoll(ctx, true) == 0)                                | io_do_iopoll                | io_uring.c      | function call  
io_drain_req                | io_uring.c      | static __cold void io_drain_req(...)                             | io_drain_req                | io_uring.c      | function       
io_eventfd_flush_signal     | eventfd.c       | void io_eventfd_flush_signal(...)                                | io_eventfd_flush_signal     | eventfd.c       | function       
io_eventfd_signal           | eventfd.c       | void io_eventfd_signal(...)                                      | io_eventfd_signal           | eventfd.c       | function       
io_eventfd_unregister       | eventfd.c       | * Check again if ev_fd exists in case an io_eventfd_unregister call | io_eventfd_unregister      | eventfd.c       | function       
io_extract_req              | io_uring.c      | req = io_extract_req(ctx);                                       | io_extract_req              | io_uring.c      | function       
io_fallback_req_func        | io_uring.c      | static __cold void io_fallback_req_func(...)                     | io_fallback_req_func        | io_uring.c      | function       
__io_fallback_tw            | io_uring.c      | static __cold void __io_fallback_tw(...)                         | __io_fallback_tw            | io_uring.c      | function       
io_fallback_tw              | io_uring.c      | static void io_fallback_tw(...)                                  | io_fallback_tw              | io_uring.c      | function       
io_file_can_poll            | io_uring.c      | if (!io_file_can_poll(req))                                      | io_file_can_poll            | io_uring.c      | function call  
io_file_get_fixed           | cancel.c        | req->file = io_file_get_fixed(req, cancel->fd,                   | io_file_get_fixed           | cancel.c        | function call  
io_file_get_flags           | filetable.h     | io_req_flags_t io_file_get_flags(struct file *file);            | io_file_get_flags           | filetable.h     | function       
io_file_get_normal          | cancel.c        | req->file = io_file_get_normal(req, cancel->fd);                 | io_file_get_normal          | cancel.c        | function call  
io_fill_cqe_aux             | io_uring.c      | static bool io_fill_cqe_aux(...)                                 | io_fill_cqe_aux             | io_uring.c      | function       
io_fill_cqe_req             | io_uring.c      | if (!io_fill_cqe_req(ctx, req))                                  | io_fill_cqe_req             | io_uring.c      | function call  
io_flush_timeouts           | io_uring.c      | io_flush_timeouts(ctx);                                          | io_flush_timeouts           | io_uring.c      | function call  
io_for_each_link            | io_uring.c      | io_for_each_link(req, head) {                                    | io_for_each_link            | io_uring.c      | function call  
io_free_batch_list          | io_uring.c      | static void io_free_batch_list(...)                               | io_free_batch_list          | io_uring.c      | function       
io_free_region              | io_uring.c      | io_free_region(ctx, &ctx->sq_region);                           | io_free_region              | io_uring.c      | function call  
io_free_req                 | io_uring.c      | __cold void io_free_req(...)                                     | io_free_req                 | io_uring.c      | function       
io_futex_cache_free         | futex.c         | void io_futex_cache_free(...)                                    | io_futex_cache_free         | futex.c         | function       
io_futex_cache_init         | futex.c         | bool io_futex_cache_init(...)                                    | io_futex_cache_init         | futex.c         | function       
io_futex_remove_all         | futex.c         | bool io_futex_remove_all(...)                                    | io_futex_remove_all         | futex.c         | function       
io_get_cqe                  | io_uring.c      | * through a control-dependency in io_get_cqe (smp_store_release to | io_get_cqe                  | io_uring.c      | function call  
io_get_cqe_overflow         | io_uring.c      | if (!io_get_cqe_overflow(ctx, &cqe, true))                       | io_get_cqe_overflow         | io_uring.c      | function call  
io_get_ext_arg              | io_uring.c      | static int io_get_ext_arg(...)                                    | io_get_ext_arg              | io_uring.c      | function       
io_get_ext_arg_reg          | io_uring.c      | static struct io_uring_reg_wait *io_get_ext_arg_reg(...)         | io_get_ext_arg_reg          | io_uring.c      | function       
io_get_sequence             | io_uring.c      | static u32 io_get_sequence(...)                                  | io_get_sequence             | io_uring.c      | function       
io_get_sqe                  | io_uring.c      | static bool io_get_sqe(...)                                      | io_get_sqe                  | io_uring.c      | function       
io_get_sqring               | io_uring.c      | * which pairs with smp_load_acquire in io_get_sqring (smp_store_release | io_get_sqring               | io_uring.c      | function       
io_get_task_refs                | io_uring.c      | io_get_task_refs(left);                                          | io_get_task_refs              | io_uring.c      | function call  
io_get_time                      | io_uring.c      | start_time = io_get_time(ctx);                                   | io_get_time                   | io_uring.c      | function call  
io_handle_tw_list                | io_uring.c      | struct llist_node *io_handle_tw_list(...)                         | io_handle_tw_list             | io_uring.c      | function       
io_has_work                      | io_uring.c      | if (io_should_wake(iowq) || io_has_work(iowq->ctx))              | io_has_work                   | io_uring.c      | function call  
io_init_fail_req                 | io_uring.c      | static __cold int io_init_fail_req(...)                           | io_init_fail_req              | io_uring.c      | function       
io_init_req                      | io_uring.c      | static int io_init_req(...)                                       | io_init_req                   | io_uring.c      | function       
io_init_req_drain                | io_uring.c      | static void io_init_req_drain(...)                                | io_init_req_drain             | io_uring.c      | function       
io_iopoll_check                  | io_uring.c      | static int io_iopoll_check(...)                                   | io_iopoll_check               | io_uring.c      | function       
io_iopoll_req_issued             | io_uring.c      | static void io_iopoll_req_issued(...)                             | io_iopoll_req_issued          | io_uring.c      | function       
io_iopoll_try_reap_events        | io_uring.c      | static __cold void io_iopoll_try_reap_events(...)                 | io_iopoll_try_reap_events     | io_uring.c      | function       
io_issue_sqe                     | io_uring.c      | * handlers and io_issue_sqe() are done with it, e.g. inline completion path. | io_issue_sqe                 | io_uring.c      | function call  
io_is_uring_fops                 | filetable.c     | if (io_is_uring_fops(file))                                       | io_is_uring_fops              | filetable.c     | function call  
io_kbuf_drop                     | io_uring.c      | io_kbuf_drop(req);                                               | io_kbuf_drop                 | io_uring.c      | function call  
io_kbuf_recycle                  | io_uring.c      | io_kbuf_recycle(req, 0);                                          | io_kbuf_recycle              | io_uring.c      | function call  
io_kill_timeouts                 | io_uring.c      | ret |= io_kill_timeouts(ctx, tctx, cancel_all);                   | io_kill_timeouts             | io_uring.c      | function call  
io_local_work_pending            | io_uring.c      | if (!io_local_work_pending(ctx))                                  | io_local_work_pending         | io_uring.c      | function call  
io_match_linked                  | io_uring.c      | static bool io_match_linked(...)                                  | io_match_linked               | io_uring.c      | function       
io_match_task                    | io_uring.c      | * As io_match_task() but protected against racing with linked timeouts. | io_match_task                 | io_uring.c      | function call  
io_match_task_safe               | futex.c         | if (!io_match_task_safe(req, tctx, cancel_all))                   | io_match_task_safe            | futex.c         | function call  
io_move_task_work_from_local     | io_uring.c      | static void __cold io_move_task_work_from_local(...)              | io_move_task_work_from_local  | io_uring.c      | function       
io_napi_busy_loop                | io_uring.c      | io_napi_busy_loop(ctx, &iowq);                                   | io_napi_busy_loop             | io_uring.c      | function call  
io_napi_free                     | io_uring.c      | io_napi_free(ctx);                                               | io_napi_free                  | io_uring.c      | function call  
io_napi_init                     | io_uring.c      | io_napi_init(ctx);                                               | io_napi_init                  | io_uring.c      | function call  
io_poll_issue                    | io_uring.c      | int io_poll_issue(...)                                            | io_poll_issue                 | io_uring.c      | function       
io_poll_remove_all               | io_uring.c      | ret |= io_poll_remove_all(ctx, tctx, cancel_all);                 | io_poll_remove_all            | io_uring.c      | function call   
io_poll_wq_wake                 | io_uring.c      | io_poll_wq_wake(ctx);                                            | io_poll_wq_wake               | io_uring.c      | function call  
__io_post_aux_cqe               | io_uring.c      | static bool __io_post_aux_cqe(...)                               | __io_post_aux_cqe             | io_uring.c      | function       
io_post_aux_cqe                 | io_uring.c      | bool io_post_aux_cqe(...)                                         | io_post_aux_cqe               | io_uring.c      | function call  
io_preinit_req                   | io_uring.c      | static void io_preinit_req(...)                                   | io_preinit_req                | io_uring.c      | function       
io_prep_async_link               | io_uring.c      | static void io_prep_async_link(...)                               | io_prep_async_link            | io_uring.c      | function       
io_prep_async_work               | io_uring.c      | static void io_prep_async_work(...)                               | io_prep_async_work            | io_uring.c      | function       
__io_prep_linked_timeout        | io_uring.c      | static struct io_kiocb *__io_prep_linked_timeout(...)             | __io_prep_linked_timeout      | io_uring.c      | function       
io_prep_linked_timeout          | io_uring.c      | static inline struct io_kiocb *io_prep_linked_timeout(...)       | io_prep_linked_timeout        | io_uring.c      | function       
io_put_file                      | io_uring.c      | io_put_file(req);                                                | io_put_file                   | io_uring.c      | function call  
io_put_kbuf                      | io_uring.c      | io_req_set_res(req, res, io_put_kbuf(req, res, IO_URING_F_UNLOCKED)); | io_put_kbuf                 | io_uring.c      | function call  
io_put_task                      | io_uring.c      | static inline void io_put_task(req);                              | io_put_task                   | io_uring.c      | function       
io_queue_async                   | io_uring.c      | static void io_queue_async(req, ret);                             | io_queue_async                | io_uring.c      | function       
io_queue_deferred                | io_uring.c      | static __cold noinline void io_queue_deferred(ctx);               | io_queue_deferred             | io_uring.c      | function       
io_queue_iowq                    | io_uring.c      | static void io_queue_iowq(req);                                   | io_queue_iowq                 | io_uring.c      | function       
io_queue_linked_timeout          | io_uring.c      | io_queue_linked_timeout(__io_prep_linked_timeout(req));           | io_queue_linked_timeout       | io_uring.c      | function call  
io_queue_next                    | io_uring.c      | void io_queue_next(req);                                          | io_queue_next                 | io_uring.c      | function       
io_queue_sqe                     | io_uring.c      | static void io_queue_sqe(req);                                    | io_queue_sqe                  | io_uring.c      | function       
io_queue_sqe_fallback            | io_uring.c      | static void io_queue_sqe_fallback(req);                           | io_queue_sqe_fallback         | io_uring.c      | function       
io_region_get_ptr                | io_uring.c      | ctx->rings = rings = io_region_get_ptr(&ctx->ring_region);       | io_region_get_ptr             | io_uring.c      | function call  
io_req_add_to_cache              | io_uring.c      | static inline void io_req_add_to_cache(req, ctx);                 | io_req_add_to_cache           | io_uring.c      | function call  
io_req_assign_rsrc_node          | io_uring.c      | io_req_assign_rsrc_node(&req->file_node, node);                  | io_req_assign_rsrc_node       | io_uring.c      | function call  
io_req_cache_empty               | io_uring.c      | if (!ret && io_req_cache_empty(ctx))                              | io_req_cache_empty            | io_uring.c      | function call  
io_req_caches_free               | io_uring.c      | static void io_req_caches_free(ctx);                              | io_req_caches_free            | io_uring.c      | function       
IO_REQ_CLEAN_FLAGS               | io_uring.c      | #define IO_REQ_CLEAN_FLAGS (REQ_F_BUFFER_SELECTED | REQ_F_NEED_CLEANUP | \ | IO_REQ_CLEAN_FLAGS | io_uring.c | macro
IO_REQ_CLEAN_SLOW_FLAGS          | io_uring.c      | #define IO_REQ_CLEAN_SLOW_FLAGS (REQ_F_REFCOUNT | REQ_F_LINK | REQ_F_HARDLINK |\ | IO_REQ_CLEAN_SLOW_FLAGS | io_uring.c | macro
io_req_complete_defer            | io_uring.c      | io_req_complete_defer(req);                                       | io_req_complete_defer        | io_uring.c      | function call  
io_req_complete_post             | io_uring.c      | static void io_req_complete_post(req, issue_flags);              | io_req_complete_post         | io_uring.c      | function       
io_req_cqe_overflow              | io_uring.c      | static void io_req_cqe_overflow(req);                             | io_req_cqe_overflow          | io_uring.c      | function       
io_req_defer_failed              | io_uring.c      | void io_req_defer_failed(req, res);                               | io_req_defer_failed          | io_uring.c      | function       
io_req_find_next                 | io_uring.c      | static inline struct io_kiocb *io_req_find_next(req);             | io_req_find_next             | io_uring.c      | function       
__io_req_find_next_prep          | io_uring.c      | static void __io_req_find_next_prep(req);                         | __io_req_find_next_prep      | io_uring.c      | function       
IO_REQ_LINK_FLAGS                | io_uring.c      | #define IO_REQ_LINK_FLAGS (REQ_F_LINK | REQ_F_HARDLINK)           | IO_REQ_LINK_FLAGS            | io_uring.c      | macro
io_req_local_work_add            | io_uring.c      | static inline void io_req_local_work_add(req, ctx);               | io_req_local_work_add        | io_uring.c      | function       
io_req_normal_work_add           | io_uring.c      | static void io_req_normal_work_add(req);                          | io_req_normal_work_add       | io_uring.c      | function       
io_req_post_cqe                  | io_uring.c      | bool io_req_post_cqe(req, res, cflags);                          | io_req_post_cqe              | io_uring.c      | function       
io_req_put_rsrc_nodes            | io_uring.c      | io_req_put_rsrc_nodes(req);                                       | io_req_put_rsrc_nodes        | io_uring.c      | function call  
io_req_queue_iowq                | io_uring.c      | void io_req_queue_iowq(req);                                      | io_req_queue_iowq            | io_uring.c      | function       
io_req_queue_iowq_tw             | io_uring.c      | static void io_req_queue_iowq_tw(req, ts);                        | io_req_queue_iowq_tw         | io_uring.c      | function       
__io_req_set_refcount            | io_uring.c      | __io_req_set_refcount(req->link, 2);                              | __io_req_set_refcount        | io_uring.c      | function       
io_req_set_refcount              | io_uring.c      | io_req_set_refcount(req);                                         | io_req_set_refcount          | io_uring.c      | function       
io_req_set_res                   | advise.c        | io_req_set_res(req, ret, 0);                                      | io_req_set_res               | advise.c        | function call  
io_req_task_cancel               | io_uring.c      | static void io_req_task_cancel(req, ts);                          | io_req_task_cancel           | io_uring.c      | function       
io_req_task_complete             | futex.c         | io_req_task_complete(req, ts);                                    | io_req_task_complete         | futex.c         | function call  
io_req_task_queue                | io_uring.c      | io_req_task_queue(de->req);                                       | io_req_task_queue            | io_uring.c      | function call  
io_req_task_queue_fail           | io_uring.c      | io_req_task_queue_fail(req, -ECANCELED);                          | io_req_task_queue_fail       | io_uring.c      | function call  
io_req_task_submit               | io_uring.c      | void io_req_task_submit(req, ts);                                 | io_req_task_submit           | io_uring.c      | function       
__io_req_task_work_add           | io_uring.c      | void __io_req_task_work_add(req, flags);                          | __io_req_task_work_add       | io_uring.c      | function       
io_req_task_work_add             | futex.c         | io_req_task_work_add(req);                                        | io_req_task_work_add         | futex.c         | function call  
io_req_task_work_add_remote      | io_uring.c      | void io_req_task_work_add_remote(req, ctx, ...);                  | io_req_task_work_add_remote  | io_uring.c      | function call  
io_req_track_inflight            | io_uring.c      | static inline void io_req_track_inflight(req);                    | io_req_track_inflight        | io_uring.c      | function       
io_ring_add_registered_file      | io_uring.c      | ret = io_ring_add_registered_file(tctx, file, 0, IO_RINGFD_REG_MAX); | io_ring_add_registered_file | io_uring.c      | function call  
io_ring_ctx_alloc                | io_uring.c      | static __cold struct io_ring_ctx *io_ring_ctx_alloc(p);           | io_ring_ctx_alloc            | io_uring.c      | function       
io_ring_ctx_free                 | io_uring.c      | static __cold void io_ring_ctx_free(ctx);                          | io_ring_ctx_free             | io_uring.c      | function       
io_ring_ctx_ref_free             | io_uring.c      | static __cold void io_ring_ctx_ref_free(ref);                      | io_ring_ctx_ref_free         | io_uring.c      | function       
io_ring_ctx_wait_and_kill        | io_uring.c      | static __cold void io_ring_ctx_wait_and_kill(ctx);                | io_ring_ctx_wait_and_kill    | io_uring.c      | function       
io_ring_exit_work                | io_uring.c      | static __cold void io_ring_exit_work(work);                        | io_ring_exit_work            | io_uring.c      | function       
io_rings_free                    | io_uring.c      | static void io_rings_free(ctx);                                   | io_rings_free                | io_uring.c      | function       
io_ring_submit_lock              | cancel.c        | io_ring_submit_lock(ctx, issue_flags);                            | io_ring_submit_lock          | cancel.c        | function call  
io_ring_submit_unlock            | cancel.c        | io_ring_submit_unlock(ctx, issue_flags);                          | io_ring_submit_unlock        | cancel.c        | function call  
io_rsrc_node_lookup              | cancel.c        | node = io_rsrc_node_lookup(ctx->file_table.data, fd);             | io_rsrc_node_lookup          | cancel.c        | function call  
__io_run_local_work              | io_uring.c      | static int __io_run_local_work(ctx, ts, ...);                     | __io_run_local_work          | io_uring.c      | function       
io_run_local_work                | io_uring.c      | static int io_run_local_work(ctx, min_events, ...);               | io_run_local_work            | io_uring.c      | function call  
io_run_local_work_continue       | io_uring.c      | static bool io_run_local_work_continue(ctx, events, ...);         | io_run_local_work_continue   | io_uring.c      | function       
io_run_local_work_locked         | io_uring.c      | static inline int io_run_local_work_locked(ctx, ...);             | io_run_local_work_locked     | io_uring.c      | function       
__io_run_local_work_loop         | io_uring.c      | static int __io_run_local_work_loop(node, ...);                   | __io_run_local_work_loop     | io_uring.c      | function       
io_run_task_work                 | io-wait.c        | static void io_run_task_work(work);                               | io_run_task_work             | io-wait.c       | function call  
io_should_terminate_tw         | io_uring.c         | if (unlikely(io_should_terminate_tw()))
io_should_wake                 | io_uring.c         | if (io_should_wake(iowq) || io_has_work(iowq->ctx))
io_slot_file                   | cancel.c           | cd->file = io_slot_file(node);
io_slot_flags                  | filetable.h        | static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
io_sqe_buffers_unregister       | io_uring.c         | io_sqe_buffers_unregister(ctx);
io_sqe_files_unregister        | io_uring.c         | io_sqe_files_unregister(ctx);
io_sq_offload_create           | io_uring.c         | ret = io_sq_offload_create(ctx, p);
io_sqpoll_wait_sq              | io_uring.c         | io_sqpoll_wait_sq(ctx);
io_sqring_entries              | io_uring.c         | unsigned int entries = io_sqring_entries(ctx);
io_sqring_full                 | io_uring.c         | if (!io_sqring_full(ctx))
io_sq_thread_finish            | io_uring.c         | io_sq_thread_finish(ctx);
io_sq_thread_park              | io_uring.c         | io_sq_thread_park(sqd);
io_sq_thread_unpark            | io_uring.c         | io_sq_thread_unpark(sqd);
io_submit_fail_init            | io_uring.c         | static __cold int io_submit_fail_init(const struct io_uring_sqe *sqe, 
__io_submit_flush_completions   | io_uring.c         | void __io_submit_flush_completions(struct io_ring_ctx *ctx)
io_submit_flush_completions     | io_uring.c         | io_submit_flush_completions(ctx);
io_submit_sqe                  | io_uring.c         | static inline int io_submit_sqe(struct io_ring_ctx *ctx, struct io_kiocb *req,
io_submit_sqes                 | io_uring.c         | int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr)
io_submit_state_end            | io_uring.c         | static void io_submit_state_end(struct io_ring_ctx *ctx)
io_submit_state_start          | io_uring.c         | static void io_submit_state_start(struct io_submit_state *state,
io_task_refs_refill            | io_uring.c         | void io_task_refs_refill(struct io_uring_task *tctx)
io_task_work_pending           | io_uring.c         | io_task_work_pending(ctx)) 
io_tctx_exit_cb                | io_uring.c         | static __cold void io_tctx_exit_cb(struct callback_head *cb)
IO_TCTX_REFS_CACHE_NR          | io_uring.c         | #define IO_TCTX_REFS_CACHE_NR	(1U << 10)
io_tw_lock                     | futex.c            | io_tw_lock(ctx, ts);
io_unregister_personality      | io_uring.c         | io_unregister_personality(ctx, index);
__io_uring_add_tctx_node       | io_uring.c         | ret = __io_uring_add_tctx_node(ctx);
io_uring_add_tctx_node         | io_uring.c         | ret = io_uring_add_tctx_node(ctx);
io_uring_allowed               | io_uring.c         | static inline bool io_uring_allowed(void)
__io_uring_cancel              | io_uring.c         | void __io_uring_cancel(bool cancel_all)
io_uring_cancel_generic        | io_uring.c         | __cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd)
io_uring_clean_tctx            | io_uring.c         | io_uring_clean_tctx(tctx);
io_uring_create                | io_uring.c         | static __cold int io_uring_create(unsigned entries, struct io_uring_params *p,
io_uring_del_tctx_node         | io_uring.c         | io_uring_del_tctx_node((unsigned long)work->ctx);
io_uring_drop_tctx_refs        | io_uring.c         | static __cold void io_uring_drop_tctx_refs(struct task_struct *task)
io_uring_fill_params           | io_uring.c         | int io_uring_fill_params(unsigned entries, struct io_uring_params *p)
__io_uring_free                | io_uring.c         | __io_uring_free(current);
io_uring_get_file              | io_uring.c         | static struct file *io_uring_get_file(struct io_ring_ctx *ctx)
io_uring_init                  | io_uring.c         | static int __init io_uring_init(void)
io_uring_install_fd            | io_uring.c         | static int io_uring_install_fd(struct file *file)
io_uring_optable_init          | io_uring.c         | io_uring_optable_init();
io_uring_poll                  | io_uring.c         | static __poll_t io_uring_poll(struct file *file, poll_table *wait)
io_uring_release               | io_uring.c         | static int io_uring_release(struct inode *inode, struct file *file)
io_uring_setup                 | io_uring.c         | static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
io_uring_try_cancel_iowq       | io_uring.c         | static __cold bool io_uring_try_cancel_iowq(struct io_ring_ctx *ctx)
io_uring_try_cancel_requests   | io_uring.c         | static bool io_uring_try_cancel_requests(struct io_ring_ctx *ctx,
io_uring_try_cancel_uring_cmd  | io_uring.c         | ret |= io_uring_try_cancel_uring_cmd(ctx, tctx, cancel_all);
io_uring_unreg_ringfd          | io_uring.c         | io_uring_unreg_ringfd();
io_validate_ext_arg            | io_uring.c         | static int io_validate_ext_arg(struct io_ring_ctx *ctx, unsigned flags,
io_waitid_remove_all           | io_uring.c         | ret |= io_waitid_remove_all(ctx, tctx, cancel_all);
io_wake_function               | io_uring.c         | static int io_wake_function(struct wait_queue_entry *curr, unsigned int mode,
io_wq_cancel_cb                | cancel.c           | cancel_ret = io_wq_cancel_cb(tctx->io_wq, io_cancel_cb, cd, all);
io_wq_current_is_worker        | cancel.c           | WARN_ON_ONCE(!io_wq_current_is_worker() && tctx != current->io_uring);
io_wq_enqueue                  | io-wq.c            | io_wq_enqueue(wq, linked);
io_wq_exit_start               | io-wq.c            | void io_wq_exit_start(struct io_wq *wq)
io_wq_free_work                | io_uring.c         | struct io_wq_work *io_wq_free_work(struct io_wq_work *work)
io_wq_hash_work                | io-wq.c            | void io_wq_hash_work(struct io_wq_work *work, void *val)
io_wq_is_hashed                | io-wq.c            | if (!io_wq_is_hashed(work)) {
io_wq_put_hash                 | io-wq.c            | io_wq_put_hash(data->hash);
io_wq_submit_work              | io_uring.c         | void io_wq_submit_work(struct io_wq_work *work)
io_wq_worker_stopped           | io-wq.c            | bool io_wq_worker_stopped(void)
IS_ERR                         | eventfd.c          | if (IS_ERR(ev_fd->cq_ev_fd)) {
issue                          | futex.c            | * happened post setup, the task_work will be run post this issue and
kfree                          | alloc_cache.h      | kfree(*iov);
kmalloc                        | alloc_cache.c      | obj = kmalloc(cache->elem_size, gfp);
KMEM_CACHE                     | io_uring.c         | io_buf_cachep = KMEM_CACHE(io_buffer,
kmem_cache_alloc               | io_uring.c         | reqs[0] = kmem_cache_alloc(req_cachep, gfp);
kmem_cache_alloc_bulk          | io_uring.c         | ret = kmem_cache_alloc_bulk(req_cachep, gfp, ARRAY_SIZE(reqs), reqs);
kmem_cache_create              | io_uring.c         | req_cachep = kmem_cache_create("io_kiocb", sizeof(struct io_kiocb), &kmem_args,
kmem_cache_free                | io_uring.c         | kmem_cache_free(req_cachep, req);
ktime_add                      | io_uring.c         | iowq.timeout = ktime_add(iowq.timeout, start_time);
ktime_add_ns                   | cancel.c           | timeout = ktime_add_ns(timespec64_to_ktime(ts), ktime_get_ns());
ktime_compare                  | io_uring.c         | ktime_compare(iowq->min_timeout, iowq->timeout) >= 0
ktime_compare          | io_uring.c                | iowq->min_timeout, iowq->timeout                               | ktime_compare          | io_uring.c                     | function call
kvfree                 | alloc_cache.c             | cache->entries                                                | kvfree                 | alloc_cache.c                  | function call
kvmalloc_array         | alloc_cache.c             | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | kvmalloc_array         | alloc_cache.c                  | function call
kzalloc                | io-wq.c                   | worker = kzalloc(sizeof(*worker), GFP_KERNEL)                  | kzalloc                | io-wq.c                        | function call
likely                 | io-wq.c                   | * Most likely an attempt to queue unbounded work on an io_wq  | likely                 | io-wq.c                        | macro
list_add_tail          | io_uring.c                | &ocqe->list, &ctx->cq_overflow_list                            | list_add_tail          | io_uring.c                     | function call
list_cut_position      | io_uring.c                | &list, &ctx->defer_list, &de->list                              | list_cut_position      | io_uring.c                     | function call
list_del               | io_uring.c                | &ocqe->list                                                  | list_del               | io_uring.c                     | function call
list_del_init          | io-wq.c                   | &wq->wait.entry                                              | list_del_init          | io-wq.c                        | function call
list_empty             | io-wq.c                   | if (list_empty(&wq->wait.entry))                               | list_empty             | io-wq.c                        | function call
list_empty_careful     | io_uring.c                | if (!req_need_defer(req, seq) && list_empty_careful(&ctx->defer_list)) | list_empty_careful     | io_uring.c                     | function call
list_first_entry       | io_uring.c                | struct io_defer_entry *de = list_first_entry(&ctx->defer_list, list) | list_first_entry       | io_uring.c                     | function call
list_for_each_entry    | cancel.c                  | list_for_each_entry(node, &ctx->tctx_list, ctx_node)           | list_for_each_entry    | cancel.c                       | function call
list_for_each_entry_reverse | io_uring.c           | list_for_each_entry_reverse(de, &ctx->defer_list, list)       | list_for_each_entry_reverse | io_uring.c                  | function call
LIST_HEAD              | io_uring.c                | LIST_HEAD(list)                                               | LIST_HEAD              | io_uring.c                     | macro
list_rotate_left       | io_uring.c                | list_rotate_left(&ctx->tctx_list)                              | list_rotate_left       | io_uring.c                     | function call
llist_add              | io_uring.c                | if (llist_add(&req->io_task_work.node, ...)                   | llist_add              | io_uring.c                     | function call
llist_del_all          | io_uring.c                | struct llist_node *node = llist_del_all(&ctx->fallback_llist)  | llist_del_all          | io_uring.c                     | function call
llist_empty            | io_uring.c                | if (!llist_empty(&ctx->work_llist))                           | llist_empty            | io_uring.c                     | function call
llist_for_each_entry_safe | io_uring.c             | llist_for_each_entry_safe(req, tmp, node, io_task_work.node)   | llist_for_each_entry_safe | io_uring.c                   | function call
llist_reverse_order    | io_uring.c                | node = llist_reverse_order(node)                               | llist_reverse_order    | io_uring.c                     | function call
load                   | io_uring.c                | * entry load(s) with the head store), pairing with an implicit barrier | load                   | io_uring.c                     | function call
lock                   | eventfd.c                 | * lock held.                                                   | lock                   | eventfd.c                      | function call
lockdep_assert        | io_uring.c                | lockdep_assert(!io_wq_current_is_worker())                    | lockdep_assert         | io_uring.c                     | function call
lockdep_assert_held   | futex.c                   | lockdep_assert_held(&ctx->uring_lock)                          | lockdep_assert_held    | futex.c                        | function call
make_kgid              | io_uring.c                | io_uring_group = make_kgid(&init_user_ns, sysctl_io_uring_group) | make_kgid              | io_uring.c                     | function call
max                    | io-wq.c                   | * below the max number of workers, create one.                 | max                    | io-wq.c                        | macro
mb                     | io_uring.c                | provides mb() which pairs with barrier from wq_has_sleeper    | mb                     | io_uring.c                     | function call
memcpy                 | io_uring.c                | memcpy(cqe, &ocqe->cqe, cqe_size)                              | memcpy                 | io_uring.c                     | function call
memory                 | io_uring.c                | * A note on the read/write ordering memory barriers            | memory                 | io_uring.c                     | comment
memset                 | alloc_cache.c             | memset(obj, 0, cache->init_clear)                              | memset                 | alloc_cache.c                  | function call
min                    | fdinfo.c                  | sq_entries = min(sq_tail - sq_head, ctx->sq_entries)          | min                    | fdinfo.c                       | function call
mmdrop                 | io_uring.c                | mmdrop(ctx->mm_account)                                       | mmdrop                 | io_uring.c                     | function call
mmgrab                 | io_uring.c                | mmgrab(current->mm)                                           | mmgrab                 | io_uring.c                     | function call
__must_hold            | cancel.c                  | __must_hold(&ctx->uring_lock)                                 | __must_hold            | cancel.c                       | macro
mutex_init             | io_uring.c                | mutex_init(&ctx->uring_lock)                                   | mutex_init             | io_uring.c                     | function call
mutex_lock             | cancel.c                  | mutex_lock(&ctx->uring_lock)                                   | mutex_lock             | cancel.c                       | function call
mutex_unlock           | cancel.c                  | mutex_unlock(&ctx->uring_lock)                                 | mutex_unlock           | cancel.c                       | function call
need_resched           | io_uring.c                | if (need_resched())                                            | need_resched           | io_uring.c                     | function call
ns_capable_noaudit     | io_uring.c                | if (!ns_capable_noaudit(&init_user_ns, CAP_IPC_LOCK))         | ns_capable_noaudit     | io_uring.c                     | function call
offsetof               | io_uring.c                | offsetof(struct io_async_msghdr, clear)                        | offsetof               | io_uring.c                     | macro
override_creds         | io_uring.c                | creds = override_creds(req->creds)                             | override_creds         | io_uring.c                     | function call
PAGE_ALIGN             | io_uring.c                | rd.size = PAGE_ALIGN(size)                                     | PAGE_ALIGN             | io_uring.c                     | macro
percpu_counter_add     | io_uring.c                | percpu_counter_add(&tctx->inflight, refill)                    | percpu_counter_add     | io_uring.c                     | function call
percpu_counter_read_positive | io_uring.c          | return percpu_counter_read_positive(&tctx->inflight)          | percpu_counter_read_positive | io_uring.c                 | function call
percpu_counter_sub     | io_uring.c                | percpu_counter_sub(&tctx->inflight, 1)                         | percpu_counter_sub     | io_uring.c                     | function call
percpu_counter_sum     | io_uring.c                | return percpu_counter_sum(&tctx->inflight)                    | percpu_counter_sum     | io_uring.c                     | function call
percpu_ref_exit        | io_uring.c                | percpu_ref_exit(&ctx->refs)                                    | percpu_ref_exit        | io_uring.c                     | function call
percpu_ref_get         | io_uring.c                | percpu_ref_get(&ctx->refs)                                     | percpu_ref_get         | io_uring.c                     | function call
percpu_ref_get_many    | io_uring.c                | percpu_ref_get_many(&ctx->refs, ret)                           | percpu_ref_get_many    | io_uring.c                     | function call
percpu_ref_init        | io_uring.c                | percpu_ref_init(&ctx->refs, io_ring_ctx_ref_free)              | percpu_ref_init        | io_uring.c                     | function call
percpu_ref_kill        | io_uring.c                | percpu_ref_kill(&ctx->refs)                                    | percpu_ref_kill        | io_uring.c                     | function call
percpu_ref_put         | io_uring.c                | percpu_ref_put(&ctx->refs)                                     | percpu_ref_put         | io_uring.c                     | function call
percpu_ref_put_many    | io_uring.c                | percpu_ref_put_many(&ctx->refs, nr)                            | percpu_ref_put_many    | io_uring.c                     | function call
poll_wait              | io_uring.c                | poll_wait(file, &ctx->poll_wq, wait)                           | poll_wait              | io_uring.c                     | function call
prep                   | io_uring.c                | /* linked timeouts should have two refs once prep'ed */         | prep                   | io_uring.c                     | comment
prepare_to_wait        | cancel.c                  | prepare_to_wait(&ctx->cq_wait, &wait, TASK_INTERRUPTIBLE)      | prepare_to_wait        | cancel.c                       | function call
prepare_to_wait_exclusive | io_uring.c             | prepare_to_wait_exclusive(&ctx->cq_wait, &iowq.wq, ...)       | prepare_to_wait_exclusive | io_uring.c                   | function call
PTR_ERR                | eventfd.c                 | int ret = PTR_ERR(ev_fd->cq_ev_fd)                             | PTR_ERR                | eventfd.c                      | macro
put_cred               | io_uring.c                | put_cred(req->creds)                                           | put_cred               | io_uring.c                     | function call
put_task_struct        | io-wq.c                   | put_task_struct(wq->task)                                      | put_task_struct        | io-wq.c                        | function call
put_task_struct_many   | io_uring.c                | put_task_struct_many(task, refs)                               | put_task_struct_many   | io_uring.c                     | function call
queue_work             | io_uring.c                | queue_work(iou_wq, &ctx->exit_work)                            | queue_work             | io_uring.c                     | function call
raw_spin_lock_init     | io-wq.c                   | raw_spin_lock_init(&worker->lock)                              | raw_spin_lock_init     | io-wq.c                        | function call
raw_spin_lock_irq      | io_uring.c                | raw_spin_lock_irq(&ctx->timeout_lock)                          | raw_spin_lock_irq      | io_uring.c                     | function call
raw_spin_unlock_irq    | io_uring.c                | raw_spin_unlock_irq(&ctx->timeout_lock)                        | raw_spin_unlock_irq    | io_uring.c                     | function call
READ_ONCE             | advise.c                  | ma->addr = READ_ONCE(sqe->addr)                                | READ_ONCE             | advise.c                       | macro
refcount_add           | io_uring.c                | refcount_add(refill, &current->usage)                           | refcount_add           | io_uring.c                     | function call
register_sysctl_init  | io_uring.c                | register_sysctl_init("kernel", kernel_io_uring_disabled_table) | register_sysctl_init  | io_uring.c                     | function call
__releases             | io-wq.c                   | __releases(&acct->lock)                                         | __releases             | io-wq.c                        | macro
req_fail_link_node     | io_uring.c                | static inline void req_fail_link_node(struct io_kiocb *req, int res) | req_fail_link_node     | io_uring.c                     | function definition
req_need_defer         | io_uring.c                | static bool req_need_defer(struct io_kiocb *req, u32 seq)      | req_need_defer         | io_uring.c                     | function definition
req_ref_get            | io_uring.c                | req_ref_get(req)                                               | req_ref_get            | io_uring.c                     | function call
req_ref_put            | io_uring.c                | req_ref_put(req)                                               | req_ref_put            | io_uring.c                     | function call
req_ref_put_and_test   | io_uring.c                | if (!req_ref_put_and_test(req))                                | req_ref_put_and_test   | io_uring.c                     | function call
req_set_fail           | advise.c                  | req_set_fail(req)                                              | req_set_fail           | advise.c                       | function call
request                | cancel.c                  | * Returns true if the request matches the criteria outlined by 'cd'. | request               | cancel.c                       | comment
restore_saved_sigmask_unless | io_uring.c           | restore_saved_sigmask_unless(ret == -EINTR)                    | restore_saved_sigmask_unless | io_uring.c                   | function call
restrictions          | io_uring.c                | * Check SQE restrictions (opcode and flags).                    | restrictions           | io_uring.c                     | comment
revert_creds          | io_uring.c                | revert_creds(creds)                                            | revert_creds           | io_uring.c                     | function call
rings_size            | io_uring.c                | unsigned long rings_size(unsigned int flags, unsigned int sq_entries, | rings_size             | io_uring.c                     | function definition
roundup_pow_of_two    | io_uring.c                | p->sq_entries = roundup_pow_of_two(entries)                    | roundup_pow_of_two     | io_uring.c                     | macro
same_thread_group      | io_uring.c                | if (WARN_ON_ONCE(!same_thread_group(tctx->task, current)))     | same_thread_group      | io_uring.c                     | function call
schedule               | io_uring.c                | schedule()                                                     | schedule               | io_uring.c                     | function call
schedule_delayed_work | io-wq.c                   | schedule_delayed_work(&worker->work, ...)                      | schedule_delayed_work | io-wq.c                        | function call
security_uring_override_creds | io_uring.c         | ret = security_uring_override_creds(req->creds)                | security_uring_override_creds | io_uring.c                 | function call
set_bit                | io-wq.c                   | set_bit(IO_WORKER_F_FREE, &worker->flags)                      | set_bit                | io-wq.c                        | macro
set_compat_user_sigmask | io_uring.c               | ret = set_compat_user_sigmask((const compat_sigset_t __user *)ext_arg->sig, | set_compat_user_sigmask | io_uring.c                 | function call
__set_current_state    | futex.c                   | __set_current_state(TASK_RUNNING)                              | __set_current_state    | futex.c                        | function call
set_current_state      | io-wq.c                   | set_current_state(TASK_INTERRUPTIBLE)                          | set_current_state      | io-wq.c                        | function call
__set_notify_signal    | io-wq.c                   | __set_notify_signal(worker->task)                              | __set_notify_signal    | io-wq.c                        | function call
set_user_sigmask       | io_uring.c                | ret = set_user_sigmask(ext_arg->sig, ext_arg->argsz)           | set_user_sigmask       | io_uring.c                     | function call
shorter                | io_uring.c                | /* no general timeout, or shorter (or equal), we are done */    | shorter                | io_uring.c                     | comment
S_ISBLK                | io_uring.c                | } else if (!req->file || !S_ISBLK(file_inode(req->file)->i_mode)) | S_ISBLK                | io_uring.c                     | macro
S_ISREG                | io_uring.c                | if (S_ISREG(file_inode(file)->i_mode))                          | S_ISREG                | io_uring.c                     | macro
sizeof                 | alloc_cache.c             | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                 | alloc_cache.c                  | operator
sizeof_field           | io_uring.c                | .usersize = sizeof_field(struct io_kiocb, cmd.data)           | sizeof_field           | io_uring.c                     | macro
sizes                  | io_uring.c                | * ring size, we return the actual sq/cq ring sizes (among other things) | sizes                 | io_uring.c                     | comment
smp_mb                 | io_uring.c                | * do). It also needs a smp_mb() before updating CQ head (ordering the | smp_mb                 | io_uring.c                     | function call
smp_rmb                | io_uring.c                | * appropriate smp_rmb() to pair with the smp_wmb() the kernel uses | smp_rmb                | io_uring.c                     | function call
smp_store_release      | io_uring.c                | * through a control-dependency in io_get_cqe (smp_store_release to | smp_store_release      | io_uring.c                     | function call
smp_wmb               | io_uring.c                 | * appropriate smp_rmb() to pair with the smp_wmb() the kernel uses | smp_wmb                | io_uring.c                    | function call                  
spin_lock             | cancel.c                   | &ctx->completion_lock                                            | spin_lock              | cancel.c                      | function call                  
spin_lock_init        | io_uring.c                 | &ctx->msg_lock                                                   | spin_lock_init         | io_uring.c                    | function call                  
spin_unlock           | cancel.c                   | &ctx->completion_lock                                            | spin_unlock            | cancel.c                      | function call                  
SQE_COMMON_FLAGS      | io_uring.c                 | #define SQE_COMMON_FLAGS (IOSQE_FIXED_FILE | IOSQE_IO_LINK | \   | SQE_COMMON_FLAGS         | io_uring.c                    | macro                        
SQE_VALID_FLAGS       | io_uring.c                 | #define SQE_VALID_FLAGS (SQE_COMMON_FLAGS | IOSQE_BUFFER_SELECT | \ | SQE_VALID_FLAGS          | io_uring.c                    | macro                        
static_branch_dec     | io_uring.c                 | &io_key_has_sqarray                                              | static_branch_dec      | io_uring.c                    | function call                  
static_branch_inc     | io_uring.c                 | &io_key_has_sqarray                                              | static_branch_inc      | io_uring.c                    | function call                  
static_branch_unlikely| io_uring.c                 | if (static_branch_unlikely(&io_key_has_sqarray) &&               | static_branch_unlikely | io_uring.c                    | conditional branch            
struct_size           | io_uring.c                 | off = struct_size(rings, cqes, cq_entries);                      | struct_size            | io_uring.c                    | function call                  
submission            | futex.c                    | * under the submission lock. 1 means We got woken while setting up,| submission             | futex.c                       | function call                  
switch                | advise.c                   | fa->advice                                                       | switch                 | advise.c                      | conditional branch            
synchronize_rcu       | io_uring.c                 | synchronize_rcu();                                               | synchronize_rcu        | io_uring.c                    | function call                  
SYSCALL_DEFINE2       | io_uring.c                 | SYSCALL_DEFINE2(io_uring_setup, u32, entries,                     | SYSCALL_DEFINE2        | io_uring.c                    | macro                        
SYSCALL_DEFINE6       | io_uring.c                 | SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,  | SYSCALL_DEFINE6        | io_uring.c                    | macro                        
tail                  | fdinfo.c                   | unsigned int sq_tail = READ_ONCE(r->sq.tail);                    | tail                   | fdinfo.c                      | variable assignment           
task_sigpending       | io_uring.c                 | if (task_sigpending(current))                                      | task_sigpending        | io_uring.c                    | function call                  
task_work_add         | io-wq.c                    | if (!task_work_add(wq->task, &worker->create_work, TWA_SIGNAL)) {  | task_work_add          | io-wq.c                       | function call                  
task_work_pending     | fdinfo.c                   | task_work_pending(req->tctx->task));                              | task_work_pending      | fdinfo.c                      | function call                  
tctx_inflight         | io_uring.c                 | static s64 tctx_inflight(struct io_uring_task *tctx, bool tracked) | tctx_inflight          | io_uring.c                    | function definition           
tctx_task_work        | io_uring.c                 | void tctx_task_work(struct callback_head *cb)                     | tctx_task_work         | io_uring.c                    | function definition           
tctx_task_work_run    | io_uring.c                 | struct llist_node *tctx_task_work_run(struct io_uring_task *tctx,| tctx_task_work_run     | io_uring.c                    | function definition           
test_bit              | filetable.h                | WARN_ON_ONCE(!test_bit(bit, table->bitmap));                      | test_bit               | filetable.h                   | function call                  
thread                | fdinfo.c                   | * sq->thread might be NULL if we raced with the sqpoll             | thread                 | fdinfo.c                      | variable assignment           
time_after            | io_uring.c                 | if (WARN_ON_ONCE(time_after(jiffies, timeout))) {                 | time_after             | io_uring.c                    | function call                  
timespec64_to_ktime   | cancel.c                   | timeout = ktime_add_ns(timespec64_to_ktime(ts), ktime_get_ns());  | timespec64_to_ktime    | cancel.c                      | function call                  
trace_io_uring_complete | io_uring.c               | trace_io_uring_complete(ctx, NULL, cqe);                          | trace_io_uring_complete | io_uring.c                    | function call                  
trace_io_uring_cqe_overflow | io_uring.c            | trace_io_uring_cqe_overflow(ctx, user_data, res, cflags, ocqe);   | trace_io_uring_cqe_overflow | io_uring.c                 | function call                  
trace_io_uring_cqring_wait | io_uring.c            | trace_io_uring_cqring_wait(ctx, min_events);                      | trace_io_uring_cqring_wait | io_uring.c                 | function call                  
trace_io_uring_create  | io_uring.c                | trace_io_uring_create(ret, ctx, p->sq_entries, p->cq_entries, p->flags);| trace_io_uring_create  | io_uring.c                  | function call                  
trace_io_uring_defer   | io_uring.c                | trace_io_uring_defer(req);                                        | trace_io_uring_defer   | io_uring.c                    | function call                  
trace_io_uring_file_get | io_uring.c               | trace_io_uring_file_get(req, fd);                                  | trace_io_uring_file_get | io_uring.c                   | function call                  
trace_io_uring_link    | io_uring.c                | trace_io_uring_link(req, link->last);                             | trace_io_uring_link    | io_uring.c                   | function call                  
trace_io_uring_local_work_run | io_uring.c          | trace_io_uring_local_work_run(ctx, ret, loops);                   | trace_io_uring_local_work_run | io_uring.c                | function call                  
trace_io_uring_queue_async_work | io_uring.c        | trace_io_uring_queue_async_work(req, io_wq_is_hashed(&req->work)); | trace_io_uring_queue_async_work | io_uring.c              | function call                  
trace_io_uring_req_failed | io_uring.c             | trace_io_uring_req_failed(sqe, req, ret);                        | trace_io_uring_req_failed | io_uring.c                   | function call                  
trace_io_uring_submit_req | io_uring.c            | trace_io_uring_submit_req(req);                                   | trace_io_uring_submit_req | io_uring.c                  | function call                  
trace_io_uring_task_work_run | io_uring.c          | trace_io_uring_task_work_run(tctx, *count);                       | trace_io_uring_task_work_run | io_uring.c                | function call                  
true                  | advise.c                   | return true                                                        | true                   | advise.c                      | return statement              
try_cmpxchg           | io_uring.c                 | } while (!try_cmpxchg(&ctx->work_llist.first, &head,              | try_cmpxchg            | io_uring.c                    | function call                  
u64_to_user_ptr       | epoll.c                    | ev = u64_to_user_ptr(READ_ONCE(sqe->addr));                       | u64_to_user_ptr       | epoll.c                       | function call                  
unlikely              | cancel.c                   | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                   | unlikely               | cancel.c                      | conditional branch            
unsafe_get_user       | io_uring.c                 | unsafe_get_user(arg.sigmask, &uarg->sigmask, uaccess_end);        | unsafe_get_user        | io_uring.c                    | function call                  
user_access_begin     | io_uring.c                 | if (!user_access_begin(uarg, sizeof(*uarg)))                      | user_access_begin      | io_uring.c                    | function call                  
user_access_end       | io_uring.c                 | user_access_end();                                                | user_access_end        | io_uring.c                    | function call                  
wait_for_completion_interruptible | io_uring.c    | wait_for_completion_interruptible(&exit.completion);             | wait_for_completion_interruptible | io_uring.c           | function call                  
wait_for_completion_interruptible_timeout | io_uring.c| } while (!wait_for_completion_interruptible_timeout(&ctx->ref_comp, interval)); | wait_for_completion_interruptible_timeout | io_uring.c  | function call                  
wake_up               | io-wq.c                    | wake_up(&wq->hash->wait);                                         | wake_up                | io-wq.c                       | function call                  
wake_up_all           | io_uring.c                 | wake_up_all(&ctx->poll_wq);                                       | wake_up_all            | io_uring.c                    | function call                  
wake_up_process       | io-wq.c                    | wake_up_process(worker->task);                                    | wake_up_process        | io-wq.c                       | function call                  
wake_up_state         | io_uring.c                 | wake_up_state(ctx->submitter_task, TASK_INTERRUPTIBLE);           | wake_up_state          | io_uring.c                    | function call                  
WARN_ON_ONCE          | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                  | WARN_ON_ONCE           | advise.c                      | function call                  
while                 | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)                | while                  | alloc_cache.c                 | loop statement               
wq_has_sleeper        | io-wq.c                    | if (wq_has_sleeper(&wq->hash->wait))                               | wq_has_sleeper         | io-wq.c                       | function call                  
wq_list_add_head      | io_uring.c                 | wq_list_add_head(&req->comp_list, &ctx->iopoll_list);             | wq_list_add_head       | io_uring.c                    | function call                  
wq_list_add_tail         | io-wq.c                    | wq_list_add_tail(&work->list, &acct->work_list);              | wq_list_add_tail         | io-wq.c                        | function call
wq_list_empty            | io-wq.c                    | !wq_list_empty(&acct->work_list);                              | wq_list_empty            | io-wq.c                        | function call
__wq_list_for_each       | io_uring.c                 | __wq_list_for_each(node, &state->compl_reqs) {                | __wq_list_for_each       | io_uring.c                     | function call
wq_stack_add_head        | io_uring.c                 | wq_stack_add_head(&req->comp_list, &ctx->submit_state.free_list); | wq_stack_add_head        | io_uring.c                     | function call
WRITE_ONCE               | io_uring.c                 | * io_uring also uses READ/WRITE_ONCE() for _any_ store or load that happens | WRITE_ONCE               | io_uring.c                     | macro
xa_destroy               | io_uring.c                 | xa_destroy(&ctx->io_bl_xa);                                    | xa_destroy               | io_uring.c                     | function call
xa_for_each              | fdinfo.c                   | xa_for_each(&ctx->personalities, index, cred)                  | xa_for_each              | fdinfo.c                       | function call
xa_init                  | io_uring.c                 | xa_init(&ctx->io_bl_xa);                                       | xa_init                  | io_uring.c                     | function call
xa_init_flags            | io_uring.c                 | xa_init_flags(&ctx->personalities, XA_FLAGS_ALLOC1);           | xa_init_flags            | io_uring.c                     | function call
xa_load                  | io_uring.c                 | req->creds = xa_load(&ctx->personalities, personality);        | xa_load                  | io_uring.c                     | function call
File: ./sync.c
fsnotify_modify          | rw.c                       | fsnotify_modify(req->file);                                     | fsnotify_modify          | rw.c                           | function call
if                       | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                       | advise.c                       | macro
io_fallocate             | opdef.c                    | .issue = io_fallocate,                                          | io_fallocate             | opdef.c                        | function call
io_fallocate_prep        | opdef.c                    | .prep = io_fallocate_prep,                                      | io_fallocate_prep        | opdef.c                        | function call
io_fsync                 | opdef.c                    | .issue = io_fsync,                                              | io_fsync                 | opdef.c                        | function call
io_fsync_prep            | opdef.c                    | .prep = io_fsync_prep,                                          | io_fsync_prep            | opdef.c                        | function call
io_kiocb_to_cmd          | advise.c                   | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise); | io_kiocb_to_cmd          | advise.c                       | function call
io_req_set_res           | advise.c                   | io_req_set_res(req, ret, 0);                                    | io_req_set_res           | advise.c                       | function call
io_sfr_prep              | opdef.c                    | .prep = io_sfr_prep,                                            | io_sfr_prep              | opdef.c                        | function call
io_sync_file_range       | opdef.c                    | .issue = io_sync_file_range,                                    | io_sync_file_range       | opdef.c                        | function call
READ_ONCE                | advise.c                   | ma->addr = READ_ONCE(sqe->addr);                                | READ_ONCE                | advise.c                       | function call
sync_file_range          | sync.c                     | /* sync_file_range always requires a blocking context */         | sync_file_range          | sync.c                         | comment
unlikely                | cancel.c                   | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                 | unlikely                 | cancel.c                       | macro
vfs_fallocate            | sync.c                     | ret = vfs_fallocate(req->file, sync->mode, sync->off, sync->len); | vfs_fallocate            | sync.c                         | function call
vfs_fsync_range          | sync.c                     | ret = vfs_fsync_range(req->file, sync->off, end > 0 ? end : LLONG_MAX, | vfs_fsync_range          | sync.c                         | function call
WARN_ON_ONCE             | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);               | WARN_ON_ONCE             | advise.c                       | function call
File: ./memmap.c
alloc_pages             | memmap.c                   | page = alloc_pages(gfp, order);                                 | alloc_pages             | memmap.c                       | function call
alloc_pages_bulk_node    | memmap.c                   | nr_allocated = alloc_pages_bulk_node(gfp, NUMA_NO_NODE,         | alloc_pages_bulk_node    | memmap.c                       | function call
check_add_overflow      | filetable.c                | if (check_add_overflow(range.off, range.len, &end))             | check_add_overflow      | filetable.c                    | function call
ERR_PTR                 | io-wq.c                    | return ERR_PTR(-EINVAL);                                        | ERR_PTR                 | io-wq.c                        | function call
for                      | Makefile                   | # Makefile for io_uring                                          | for                     | Makefile                       | loop
get_order               | memmap.c                   | order = get_order(size);                                        | get_order               | memmap.c                       | function call
get_unmapped_area       | io_uring.c                 | .get_unmapped_area = io_uring_get_unmapped_area,                | get_unmapped_area       | io_uring.c                     | function call
guard                   | io_uring.c                 | guard(rcu)();                                                   | guard                   | io_uring.c                     | function call
if                       | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                       | advise.c                       | macro
__io_account_mem        | memmap.c                   | ret = __io_account_mem(ctx->user, nr_pages);                    | __io_account_mem        | memmap.c                       | function call
io_check_coalesce_buffer| memmap.c                   | if (io_check_coalesce_buffer(mr->pages, mr->nr_pages, &ifd)) {  | io_check_coalesce_buffer | memmap.c                       | function call
io_create_region        | io_uring.c                 | ret = io_create_region(ctx, &ctx->ring_region, &rd, IORING_OFF_CQ_RING); | io_create_region        | io_uring.c                     | function call
io_create_region_mmap_safe | kbuf.c                  | ret = io_create_region_mmap_safe(ctx, &bl->region, &rd, mmap_offset); | io_create_region_mmap_safe | kbuf.c                        | function call
io_free_region          | io_uring.c                 | io_free_region(ctx, &ctx->sq_region);                           | io_free_region          | io_uring.c                     | function call
io_mem_alloc_compound   | memmap.c                   | static void *io_mem_alloc_compound(struct page **pages, int nr_pages, | io_mem_alloc_compound   | memmap.c                       | function definition
io_mmap_get_region      | memmap.c                   | static struct io_mapped_region *io_mmap_get_region(struct io_ring_ctx *ctx, | io_mmap_get_region      | memmap.c                       | function definition
io_pbuf_get_region      | kbuf.c                     | struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx, | io_pbuf_get_region      | kbuf.c                         | function definition
io_pin_pages            | memmap.c                   | struct page **io_pin_pages(unsigned long uaddr, unsigned long len, int *npages) | io_pin_pages            | memmap.c                       | function definition
io_region_allocate_pages | memmap.c                   | static int io_region_allocate_pages(struct io_ring_ctx *ctx,                   | io_region_allocate_pages | memmap.c                       | function definition
io_region_get_ptr       | io_uring.c                 | ctx->rings = rings = io_region_get_ptr(&ctx->ring_region);                   | io_region_get_ptr       | io_uring.c                     | function call
io_region_init_ptr      | memmap.c                   | static int io_region_init_ptr(struct io_mapped_region *mr)                    | io_region_init_ptr      | memmap.c                       | function definition
io_region_is_set        | memmap.c                   | if (!io_region_is_set(mr))                                                   | io_region_is_set        | memmap.c                       | function call
io_region_mmap          | memmap.c                   | static int io_region_mmap(struct io_ring_ctx *ctx,                           | io_region_mmap          | memmap.c                       | function definition
io_region_pin_pages     | memmap.c                   | static int io_region_pin_pages(struct io_ring_ctx *ctx,                      | io_region_pin_pages     | memmap.c                       | function definition
io_region_validate_mmap | memmap.c                   | static void *io_region_validate_mmap(struct io_ring_ctx *ctx,                | io_region_validate_mmap | memmap.c                       | function definition
__io_unaccount_mem      | memmap.c                   | __io_unaccount_mem(ctx->user, mr->nr_pages);                                | __io_unaccount_mem      | memmap.c                       | function call
io_uring_get_unmapped_area | io_uring.c               | .get_unmapped_area = io_uring_get_unmapped_area,                            | io_uring_get_unmapped_area | io_uring.c                   | function call
io_uring_mmap           | io_uring.c                 | .mmap = io_uring_mmap,                                                       | io_uring_mmap           | io_uring.c                     | function call
io_uring_nommu_mmap_capabilities | io_uring.c           | .mmap_capabilities = io_uring_nommu_mmap_capabilities,                       | io_uring_nommu_mmap_capabilities | io_uring.c                | function call
io_uring_validate_mmap_request | memmap.c              | static void *io_uring_validate_mmap_request(struct file *file, loff_t pgoff, | io_uring_validate_mmap_request | memmap.c                    | function definition
IS_ERR                  | eventfd.c                  | if (IS_ERR(ev_fd->cq_ev_fd))                                               | IS_ERR                  | eventfd.c                      | macro
is_nommu_shared_mapping | memmap.c                   | return is_nommu_shared_mapping(vma->vm_flags) ? 0 : -EINVAL;               | is_nommu_shared_mapping | memmap.c                       | function call
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                       | kmalloc                 | alloc_cache.c                  | function call
kvfree                  | alloc_cache.c              | kvfree(cache->entries);                                                    | kvfree                  | alloc_cache.c                  | function call
kvmalloc_array          | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);         | kvmalloc_array          | alloc_cache.c                  | function call
lockdep_assert_held     | futex.c                    | lockdep_assert_held(&ctx->uring_lock);                                      | lockdep_assert_held     | futex.c                        | function call
memchr_inv              | memmap.c                   | if (memchr_inv(&reg->__resv, 0, sizeof(reg->__resv)))                        | memchr_inv              | memmap.c                       | function call
memcpy                  | io_uring.c                 | memcpy(cqe, &ocqe->cqe, cqe_size);                                         | memcpy                  | io_uring.c                     | function call
memset                  | alloc_cache.c              | memset(obj, 0, cache->init_clear);                                          | memset                  | alloc_cache.c                  | function call
min                     | fdinfo.c                   | sq_entries = min(sq_tail - sq_head, ctx->sq_entries);                       | min                     | fdinfo.c                       | macro
mm_get_unmapped_area    | memmap.c                   | return mm_get_unmapped_area(current->mm, filp, addr, len, pgoff, flags);   | mm_get_unmapped_area    | memmap.c                       | function call
page_address            | memmap.c                   | return page_address(page);                                                 | page_address            | memmap.c                       | function call
pin_user_pages_fast     | memmap.c                   | ret = pin_user_pages_fast(uaddr, nr_pages, FOLL_WRITE | FOLL_LONGTERM,      | pin_user_pages_fast     | memmap.c                       | function call
PTR_ERR                 | eventfd.c                  | int ret = PTR_ERR(ev_fd->cq_ev_fd);                                        | PTR_ERR                 | eventfd.c                      | macro
release_pages           | memmap.c                   | release_pages(mr->pages, nr_refs);                                          | release_pages           | memmap.c                       | function call
return                  | advise.c                   | return -EINVAL;                                                           | return                  | advise.c                       | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);        | sizeof                  | alloc_cache.c                  | operator
switch                  | advise.c                   | switch (fa->advice) {                                                     | switch                  | advise.c                       | statement
unpin_user_pages        | memmap.c                   | unpin_user_pages(pages, ret);                                              | unpin_user_pages        | memmap.c                       | function call
vmap                    | memmap.c                   | /* memory was vmap'ed for the kernel, freeing the region vunmap's it */      | vmap                    | memmap.c                       | comment
vm_flags_set            | memmap.c                   | vm_flags_set(vma, VM_DONTEXPAND);                                          | vm_flags_set            | memmap.c                       | function call
vm_insert_pages         | memmap.c                   | return vm_insert_pages(vma, vma->vm_start, mr->pages, &nr_pages);           | vm_insert_pages         | memmap.c                       | function call
vunmap                  | memmap.c                   | /* memory was vmap'ed for the kernel, freeing the region vunmap's it */      | vunmap                  | memmap.c                       | comment
WARN_ON_ONCE            | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                          | WARN_ON_ONCE            | advise.c                       | function call
do_madvise             | advise.c                   | ret = do_madvise(current->mm, ma->addr, ma->len, ma->advice);                     | do_madvise             | advise.c                     | function call
if                     | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                          | if                     | advise.c                     | conditional directive
io_fadvise             | advise.c                   | struct io_fadvise {                                                                | io_fadvise             | advise.c                     | structure definition
io_fadvise_force_async | advise.c                   | static bool io_fadvise_force_async(struct io_fadvise *fa)                          | io_fadvise_force_async | advise.c                     | function definition
io_fadvise_prep        | advise.c                   | int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)           | io_fadvise_prep        | advise.c                     | function definition
io_kiocb_to_cmd        | advise.c                   | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);                   | io_kiocb_to_cmd        | advise.c                     | function call
io_madvise             | advise.c                   | struct io_madvise {                                                                | io_madvise             | advise.c                     | structure definition
io_madvise_prep        | advise.c                   | int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)           | io_madvise_prep        | advise.c                     | function definition
io_req_set_res         | advise.c                   | io_req_set_res(req, ret, 0);                                                      | io_req_set_res         | advise.c                     | function call
READ_ONCE              | advise.c                   | ma->addr = READ_ONCE(sqe->addr);                                                  | READ_ONCE              | advise.c                     | macro
req_set_fail           | advise.c                   | req_set_fail(req);                                                                | req_set_fail           | advise.c                     | function call
switch                 | advise.c                   | switch (fa->advice) {                                                             | switch                 | advise.c                     | statement
vfs_fadvise            | advise.c                   | ret = vfs_fadvise(req->file, fa->offset, fa->len, fa->advice);                     | vfs_fadvise            | advise.c                     | function call
WARN_ON_ONCE           | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                                  | WARN_ON_ONCE           | advise.c                     | function call
array_index_nospec     | io_uring.c                 | opcode = array_index_nospec(opcode, IORING_OP_LAST);                              | array_index_nospec     | io_uring.c                   | function call
atomic_set             | eventfd.c                  | atomic_set(&ev_fd->ops, 0);                                                      | atomic_set             | eventfd.c                    | function call
cond_resched           | io-wq.c                    | cond_resched();                                                                   | cond_resched           | io-wq.c                      | function call
copy_from_user         | cancel.c                   | if (copy_from_user(&sc, arg, sizeof(sc)))                                          | copy_from_user         | cancel.c                     | function call
copy_to_user           | io_uring.c                 | if (copy_to_user(params, p, sizeof(*p)))                                          | copy_to_user           | io_uring.c                   | function call
ERR_PTR                | io-wq.c                    | return ERR_PTR(-EINVAL);                                                         | ERR_PTR                | io-wq.c                      | macro
fget                   | cancel.c                   | file = fget(sc.fd);                                                              | fget                   | cancel.c                     | function call
fput                   | cancel.c                   | fput(file);                                                                      | fput                   | cancel.c                     | function call
init_llist_head        | io_uring.c                 | init_llist_head(&ctx->work_llist);                                                | init_llist_head        | io_uring.c                   | function call
init_task_work         | io-wq.c                    | init_task_work(&worker->create_work, func);                                       | init_task_work         | io-wq.c                      | function call
init_waitqueue_head    | io_uring.c                 | init_waitqueue_head(&ctx->sqo_sq_wait);                                           | init_waitqueue_head    | io_uring.c                   | function call
io_init_wq_offload     | tctx.c                     | static struct io_wq *io_init_wq_offload(struct io_ring_ctx *ctx,                  | io_init_wq_offload     | tctx.c                       | function definition
io_is_uring_fops       | filetable.c                | if (io_is_uring_fops(file))                                                      | io_is_uring_fops       | filetable.c                  | function call
io_ring_add_registered_fd | tctx.c                  | static int io_ring_add_registered_fd(struct io_uring_task *tctx, int fd,           | io_ring_add_registered_fd | tctx.c                    | function definition
io_ring_add_registered_file | io_uring.c              | ret = io_ring_add_registered_file(tctx, file, 0, IO_RINGFD_REG_MAX);              | io_ring_add_registered_file | io_uring.c               | function call
io_ringfd_register     | register.c                 | ret = io_ringfd_register(ctx, arg, nr_args);                                      | io_ringfd_register     | register.c                   | function call
io_ringfd_unregister   | register.c                 | ret = io_ringfd_unregister(ctx, arg, nr_args);                                    | io_ringfd_unregister   | register.c                   | function call
__io_uring_add_tctx_node | io_uring.c               | ret = __io_uring_add_tctx_node(ctx);                                              | __io_uring_add_tctx_node | io_uring.c                 | function call
__io_uring_add_tctx_node_from_submit | tctx.c        | int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx)                 | __io_uring_add_tctx_node_from_submit | tctx.c              | function definition
io_uring_alloc_task_context | io_uring.h             | int io_uring_alloc_task_context(struct task_struct *task,                        | io_uring_alloc_task_context | io_uring.h               | function definition
io_uring_clean_tctx    | io_uring.c                 | io_uring_clean_tctx(tctx);                                                       | io_uring_clean_tctx    | io_uring.c                   | function call
io_uring_del_tctx_node | io_uring.c                 | io_uring_del_tctx_node((unsigned long)work->ctx);                                | io_uring_del_tctx_node | io_uring.c                   | function call
io_uring_enter          | io_uring.c                 | SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,            | io_uring_enter          | io_uring.c                   | syscall definition
__io_uring_free         | io_uring.c                 | __io_uring_free(current);                                                     | __io_uring_free         | io_uring.c                   | function call
io_uring_try_cancel_iowq | io_uring.c                 | static __cold bool io_uring_try_cancel_iowq(struct io_ring_ctx *ctx)           | io_uring_try_cancel_iowq | io_uring.c                   | function definition
io_uring_unreg_ringfd   | io_uring.c                 | io_uring_unreg_ringfd();                                                      | io_uring_unreg_ringfd   | io_uring.c                   | function call
io_wq_create            | io-wq.c                    | struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data)           | io_wq_create            | io-wq.c                      | function definition
io_wq_max_workers       | io-wq.c                    | int io_wq_max_workers(struct io_wq *wq, int *new_count)                         | io_wq_max_workers       | io-wq.c                      | function definition
io_wq_put_and_exit      | io-wq.c                    | void io_wq_put_and_exit(struct io_wq *wq)                                       | io_wq_put_and_exit      | io-wq.c                      | function definition
IS_ERR                  | eventfd.c                  | if (IS_ERR(ev_fd->cq_ev_fd)) {                                                 | IS_ERR                  | eventfd.c                    | macro
kfree                   | alloc_cache.h              | kfree(*iov);                                                                    | kfree                   | alloc_cache.h                | function call
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                          | kmalloc                 | alloc_cache.c                | function call
kzalloc                 | io-wq.c                    | worker = kzalloc(sizeof(*worker), GFP_KERNEL);                                  | kzalloc                 | io-wq.c                      | function call
list_add                | kbuf.c                     | list_add(&buf->list, &bl->buf_list);                                           | list_add                | kbuf.c                       | function call
list_del                | io_uring.c                 | list_del(&ocqe->list);                                                         | list_del                | io_uring.c                   | function call
list_empty              | io-wq.c                    | if (list_empty(&wq->wait.entry)) {                                              | list_empty              | io-wq.c                      | function call
min                     | fdinfo.c                   | sq_entries = min(sq_tail - sq_head, ctx->sq_entries);                          | min                     | fdinfo.c                     | macro
mutex_lock              | cancel.c                   | mutex_lock(&ctx->uring_lock);                                                  | mutex_lock              | cancel.c                     | function call
mutex_unlock            | cancel.c                   | mutex_unlock(&ctx->uring_lock);                                                | mutex_unlock            | cancel.c                     | function call
num_online_cpus         | tctx.c                     | concurrency = min(ctx->sq_entries, 4 * num_online_cpus());                     | num_online_cpus         | tctx.c                       | function call
percpu_counter_destroy  | tctx.c                     | percpu_counter_destroy(&tctx->inflight);                                       | percpu_counter_destroy  | tctx.c                       | function call
percpu_counter_init     | tctx.c                     | ret = percpu_counter_init(&tctx->inflight, 0, GFP_KERNEL);                     | percpu_counter_init     | tctx.c                       | function call
PTR_ERR                 | eventfd.c                  | int ret = PTR_ERR(ev_fd->cq_ev_fd);                                            | PTR_ERR                 | eventfd.c                    | macro
refcount_set            | eventfd.c                  | refcount_set(&ev_fd->refs, 1);                                                 | refcount_set            | eventfd.c                    | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);            | sizeof                  | alloc_cache.c                | operator
unlikely                | cancel.c                   | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                                | unlikely                | cancel.c                     | macro
WARN_ON_ONCE            | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                               | WARN_ON_ONCE            | advise.c                     | function call
xa_empty                | fdinfo.c                   | if (has_lock && !xa_empty(&ctx->personalities)) {                              | xa_empty                | fdinfo.c                     | macro
xa_erase                | kbuf.c                     | xa_erase(&ctx->io_bl_xa, bl->bgid);                                            | xa_erase                | kbuf.c                       | function call
xa_err                  | kbuf.c                     | return xa_err(xa_store(&ctx->io_bl_xa, bgid, bl, GFP_KERNEL));                  | xa_err                  | kbuf.c                       | function call
xa_for_each             | fdinfo.c                   | xa_for_each(&ctx->personalities, index, cred)                                  | xa_for_each             | fdinfo.c                     | macro
xa_init                 | io_uring.c                 | xa_init(&ctx->io_bl_xa);                                                       | xa_init                 | io_uring.c                   | function call
xa_load                 | io_uring.c                 | req->creds = xa_load(&ctx->personalities, personality);                        | xa_load                 | io_uring.c                   | function call
xa_store                | kbuf.c                     | return xa_err(xa_store(&ctx->io_bl_xa, bgid, bl, GFP_KERNEL));                  | xa_store                | kbuf.c                       | function call
free                    | alloc_cache.c              | void (*free)(const void *))                                                  | free                    | alloc_cache.c                | function pointer
if                      | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                     | if                      | advise.c                     | preprocessor directive
io_alloc_cache_free      | alloc_cache.c              | void io_alloc_cache_free(struct io_alloc_cache *cache,                        | io_alloc_cache_free      | alloc_cache.c                | function definition
io_alloc_cache_get       | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)                            | io_alloc_cache_get       | alloc_cache.c                | function call
io_alloc_cache_init      | alloc_cache.c              | bool io_alloc_cache_init(struct io_alloc_cache *cache,                        | io_alloc_cache_init      | alloc_cache.c                | function definition
io_cache_alloc_new       | alloc_cache.c              | void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp)              | io_cache_alloc_new       | alloc_cache.c                | function definition
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                          | kmalloc                 | alloc_cache.c                | function call
kvfree                  | alloc_cache.c              | kvfree(cache->entries);                                                       | kvfree                  | alloc_cache.c                | function call
kvmalloc_array          | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);           | kvmalloc_array          | alloc_cache.c                | function call
memset                  | alloc_cache.c              | memset(obj, 0, cache->init_clear);                                             | memset                  | alloc_cache.c                | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);           | sizeof                  | alloc_cache.c                | operator
void                    | alloc_cache.c              | void io_alloc_cache_free(struct io_alloc_cache *cache,                        | void                    | alloc_cache.c                | return type
while                   | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)                            | while                   | alloc_cache.c                | loop
file_getxattr           | xattr.c                    | ret = file_getxattr(req->file, &ix->ctx);                                       | file_getxattr           | xattr.c                      | function call
filename_getxattr       | xattr.c                    | ret = filename_getxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);      | filename_getxattr       | xattr.c                      | function call
filename_setxattr       | xattr.c                    | ret = filename_setxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);      | filename_setxattr       | xattr.c                      | function call
file_setxattr           | xattr.c                    | ret = file_setxattr(req->file, &ix->ctx);                                       | file_setxattr           | xattr.c                      | function call
getname                 | fs.c                       | ren->oldpath = getname(oldf);                                                  | getname                 | fs.c                         | function call
if                      | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                     | if                      | advise.c                     | preprocessor directive
import_xattr_name       | xattr.c                    | ret = import_xattr_name(ix->ctx.kname, name);                                  | import_xattr_name       | xattr.c                      | function call
io_fgetxattr            | opdef.c                    | .issue = io_fgetxattr,                                                         | io_fgetxattr            | opdef.c                      | function call
io_fgetxattr_prep       | opdef.c                    | .prep = io_fgetxattr_prep,                                                     | io_fgetxattr_prep       | opdef.c                      | function call
io_fsetxattr            | opdef.c                    | .issue = io_fsetxattr,                                                         | io_fsetxattr            | opdef.c                      | function call
io_fsetxattr_prep       | opdef.c                    | .prep = io_fsetxattr_prep,                                                     | io_fsetxattr_prep       | opdef.c                      | function call
io_getxattr             | opdef.c                    | .issue = io_getxattr,                                                         | io_getxattr             | opdef.c                      | function call
__io_getxattr_prep      | xattr.c                    | static int __io_getxattr_prep(struct io_kiocb *req,                           | __io_getxattr_prep      | xattr.c                      | function definition
io_getxattr_prep        | opdef.c                    | .prep = io_getxattr_prep,                                                     | io_getxattr_prep        | opdef.c                      | function call
io_kiocb_to_cmd         | advise.c                   | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);               | io_kiocb_to_cmd         | advise.c                     | function call
io_req_set_res          | advise.c                   | io_req_set_res(req, ret, 0);                                                  | io_req_set_res          | advise.c                     | function call
io_setxattr             | opdef.c                    | .issue = io_setxattr,                                                         | io_setxattr             | opdef.c                      | function call
__io_setxattr_prep      | xattr.c                    | static int __io_setxattr_prep(struct io_kiocb *req,                           | __io_setxattr_prep      | xattr.c                      | function definition
io_setxattr_prep        | opdef.c                    | .prep = io_setxattr_prep,                                                     | io_setxattr_prep        | opdef.c                      | function call
io_xattr_cleanup       | opdef.c                    | .cleanup = io_xattr_cleanup,                                                  | io_xattr_cleanup       | opdef.c                      | function call
io_xattr_finish         | xattr.c                    | static void io_xattr_finish(struct io_kiocb *req, int ret)                     | io_xattr_finish         | xattr.c                      | function definition
IS_ERR                  | eventfd.c                  | if (IS_ERR(ev_fd->cq_ev_fd)) {                                                 | IS_ERR                  | eventfd.c                    | macro
kfree                   | alloc_cache.h              | kfree(*iov);                                                                    | kfree                   | alloc_cache.h                | function call
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                          | kmalloc                 | alloc_cache.c                | function call
kvfree                  | alloc_cache.c              | kvfree(cache->entries);                                                       | kvfree                  | alloc_cache.c                | function call
PTR_ERR                 | eventfd.c                  | int ret = PTR_ERR(ev_fd->cq_ev_fd);                                            | PTR_ERR                 | eventfd.c                    | macro
putname                 | fs.c                       | putname(ren->oldpath);                                                        | putname                 | fs.c                         | function call
READ_ONCE               | advise.c                   | ma->addr = READ_ONCE(sqe->addr);                                               | READ_ONCE               | advise.c                     | macro
setxattr_copy           | xattr.c                    | ret = setxattr_copy(name, &ix->ctx);                                           | setxattr_copy           | xattr.c                      | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);           | sizeof                  | alloc_cache.c                | operator
u64_to_user_ptr         | epoll.c                    | ev = u64_to_user_ptr(READ_ONCE(sqe->addr));                                    | u64_to_user_ptr         | epoll.c                      | function call
unlikely                | cancel.c                   | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                                | unlikely                | cancel.c                     | macro
WARN_ON_ONCE            | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                               | WARN_ON_ONCE            | advise.c                     | function call
__acquires              | io-wq.c                    | __acquires(&acct->lock)                                                     | __acquires              | io-wq.c                      | macro
alloc_cpumask_var       | io-wq.c                    | if (!alloc_cpumask_var(&wq->cpu_mask, GFP_KERNEL))                           | alloc_cpumask_var       | io-wq.c                      | function call
array_index_nospec      | io_uring.c                 | opcode = array_index_nospec(opcode, IORING_OP_LAST);                        | array_index_nospec      | io_uring.c                   | function call
array_size              | io_uring.c                 | sq_array_size = array_size(sizeof(u32), sq_entries);                        | array_size              | io_uring.c                   | function call
ARRAY_SIZE              | cancel.c                   | for (i = 0; i < ARRAY_SIZE(sc.pad); i++)                                      | ARRAY_SIZE              | cancel.c                     | macro
atomic_read             | io-wq.c                    | return io_get_acct(wq, !(atomic_read(&work->flags) & IO_WQ_WORK_UNBOUND));    | atomic_read             | io-wq.c                      | function call
atomic_set              | eventfd.c                  | atomic_set(&ev_fd->ops, 0);                                                  | atomic_set              | eventfd.c                    | function call
BUILD_BUG_ON            | io-wq.c                    | BUILD_BUG_ON((int) IO_WQ_ACCT_BOUND != (int) IO_WQ_BOUND);                   | BUILD_BUG_ON            | io-wq.c                      | macro
compat_get_bitmap       | register.c                 | ret = compat_get_bitmap(cpumask_bits(new_mask),                              | compat_get_bitmap       | register.c                   | function call
COPY_FLAGS              | register.c                 | #define COPY_FLAGS (IORING_SETUP_NO_SQARRAY | IORING_SETUP_SQE128 | ...)      | COPY_FLAGS              | register.c                   | macro
copy_from_user          | cancel.c                   | if (copy_from_user(&sc, arg, sizeof(sc)))                                    | copy_from_user          | cancel.c                     | function call
Copyright               | io-wq.c                    | * Copyright (C) 2019 Jens Axboe                                              | Copyright               | io-wq.c                      | comment
copy_to_user            | io_uring.c                 | if (copy_to_user(params, p, sizeof(*p)))                                     | copy_to_user            | io_uring.c                   | function call
cpumask_bits            | register.c                 | ret = compat_get_bitmap(cpumask_bits(new_mask),                              | cpumask_bits            | register.c                   | function call
cpumask_clear           | register.c                 | cpumask_clear(new_mask);                                                     | cpumask_clear           | register.c                   | function call
cpumask_size            | register.c                 | if (len > cpumask_size())                                                    | cpumask_size            | register.c                   | function call
ERR_PTR                 | io-wq.c                    | return ERR_PTR(-EINVAL);                                                     | ERR_PTR                 | io-wq.c                      | macro
fget                    | cancel.c                   | file = fget(sc.fd);                                                          | fget                    | cancel.c                     | function call
for                     | Makefile                   | # Makefile for io_uring                                                      | for                     | Makefile                     | loop
fput                    | cancel.c                   | fput(file);                                                                  | fput                    | cancel.c                     | function call
free_cpumask_var        | io-wq.c                    | free_cpumask_var(wq->cpu_mask);                                              | free_cpumask_var        | io-wq.c                      | function call
get_current_cred        | io_uring.c                 | req->creds = get_current_cred();                                             | get_current_cred        | io_uring.c                   | function call
get_file                | msg_ring.c                 | get_file(msg->src_file);                                                     | get_file                | msg_ring.c                   | function call
get_task_struct         | io-wq.c                    | wq->task = get_task_struct(data->task);                                      | get_task_struct         | io-wq.c                      | function call
if                      | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                    | if                      | advise.c                     | preprocessor directive
in_compat_syscall       | io_uring.c                 | if (in_compat_syscall())                                                     | in_compat_syscall       | io_uring.c                   | function call
io_activate_pollwq      | io_uring.c                 | __cold void io_activate_pollwq(struct io_ring_ctx *ctx)                      | io_activate_pollwq      | io_uring.c                   | function definition
io_create_region_mmap_safe | kbuf.c                   | ret = io_create_region_mmap_safe(ctx, &bl->region, &rd, mmap_offset);        | io_create_region_mmap_safe | kbuf.c                    | function call
io_eventfd_register     | eventfd.c                  | int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,           | io_eventfd_register     | eventfd.c                    | function definition
io_eventfd_unregister   | eventfd.c                  | * Check again if ev_fd exists in case an io_eventfd_unregister call           | io_eventfd_unregister   | eventfd.c                    | function definition
io_free_region          | io_uring.c                 | io_free_region(ctx, &ctx->sq_region);                                        | io_free_region          | io_uring.c                   | function call
io_is_uring_fops        | filetable.c                | if (io_is_uring_fops(file))                                                  | io_is_uring_fops        | filetable.c                  | function call
io_parse_restrictions   | register.c                 | static __cold int io_parse_restrictions(void __user *arg, unsigned int nr_args, | io_parse_restrictions   | register.c                   | function definition
io_probe                | register.c                 | static __cold int io_probe(struct io_ring_ctx *ctx, void __user *arg,       | io_probe                | register.c                   | function definition
io_put_sq_data          | register.c                 | io_put_sq_data(sqd);                                                         | io_put_sq_data          | register.c                   | function call
io_region_get_ptr       | io_uring.c                 | ctx->rings = rings = io_region_get_ptr(&ctx->ring_region);                   | io_region_get_ptr       | io_uring.c                   | function call
io_region_is_set         | memmap.c                  | if (!io_region_is_set(mr))                                                    | io_region_is_set         | memmap.c                     | function call
io_register_clock        | register.c                | static int io_register_clock(struct io_ring_ctx *ctx,                        | io_register_clock        | register.c                   | function definition
io_register_clone_buffers| register.c                | ret = io_register_clone_buffers(ctx, arg);                                    | io_register_clone_buffers| register.c                   | function call
io_register_enable_rings | register.c                | static int io_register_enable_rings(struct io_ring_ctx *ctx)                  | io_register_enable_rings | register.c                   | function definition
io_register_file_alloc_range | filetable.c            | int io_register_file_alloc_range(struct io_ring_ctx *ctx,                     | io_register_file_alloc_range | filetable.c                | function definition
io_register_files_update | register.c                | ret = io_register_files_update(ctx, arg, nr_args);                           | io_register_files_update | register.c                   | function call
io_register_free_rings   | register.c                | static void io_register_free_rings(struct io_ring_ctx *ctx,                   | io_register_free_rings   | register.c                   | function definition
__io_register_iowq_aff   | register.c                | static __cold int __io_register_iowq_aff(struct io_ring_ctx *ctx,             | __io_register_iowq_aff   | register.c                   | function definition
io_register_iowq_aff     | register.c                | static __cold int io_register_iowq_aff(struct io_ring_ctx *ctx,               | io_register_iowq_aff     | register.c                   | function definition
io_register_iowq_max_workers | register.c            | static __cold int io_register_iowq_max_workers(struct io_ring_ctx *ctx,       | io_register_iowq_max_workers | register.c                | function definition
io_register_mem_region   | register.c                | static int io_register_mem_region(struct io_ring_ctx *ctx, void __user *uarg)| io_register_mem_region   | register.c                   | function definition
io_register_napi         | napi.c                    | int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)              | io_register_napi         | napi.c                       | function definition
io_register_pbuf_ring    | kbuf.c                    | int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)         | io_register_pbuf_ring    | kbuf.c                       | function definition
io_register_pbuf_status  | kbuf.c                    | int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg)       | io_register_pbuf_status  | kbuf.c                       | function definition
io_register_personality  | register.c                | static int io_register_personality(struct io_ring_ctx *ctx)                   | io_register_personality  | register.c                   | function definition
io_register_resize_rings | register.c                | static int io_register_resize_rings(struct io_ring_ctx *ctx, void __user *arg)| io_register_resize_rings | register.c                   | function definition
io_register_restrictions | register.c                | static __cold int io_register_restrictions(struct io_ring_ctx *ctx,           | io_register_restrictions | register.c                   | function definition
io_register_rsrc         | register.c                | ret = io_register_rsrc(ctx, arg, nr_args, IORING_RSRC_FILE);                 | io_register_rsrc         | register.c                   | function call
io_register_rsrc_update  | register.c                | ret = io_register_rsrc_update(ctx, arg, nr_args,                             | io_register_rsrc_update  | register.c                   | function call
io_ringfd_register       | register.c                | ret = io_ringfd_register(ctx, arg, nr_args);                                  | io_ringfd_register       | register.c                   | function call
io_ringfd_unregister     | register.c                | ret = io_ringfd_unregister(ctx, arg, nr_args);                                | io_ringfd_unregister     | register.c                   | function call
IORING_MAX_RESTRICTIONS  | register.c                | #define IORING_MAX_RESTRICTIONS (IORING_RESTRICTION_LAST + ...)               | IORING_MAX_RESTRICTIONS  | register.c                   | macro
io_sqe_buffers_register  | register.c                | ret = io_sqe_buffers_register(ctx, arg, nr_args, NULL);                      | io_sqe_buffers_register  | register.c                   | function call
io_sqe_buffers_unregister| io_uring.c                | io_sqe_buffers_unregister(ctx);                                               | io_sqe_buffers_unregister| io_uring.c                   | function call
io_sqe_files_register    | register.c                | ret = io_sqe_files_register(ctx, arg, nr_args, NULL);                        | io_sqe_files_register    | register.c                   | function call
io_sqe_files_unregister  | io_uring.c                | io_sqe_files_unregister(ctx);                                                 | io_sqe_files_unregister  | io_uring.c                   | function call
io_sqpoll_wq_cpu_affinity| register.c                | ret = io_sqpoll_wq_cpu_affinity(ctx, new_mask);                              | io_sqpoll_wq_cpu_affinity| register.c                   | function call
io_sq_thread_park       | io_uring.c                | io_sq_thread_park(sqd);                                                      | io_sq_thread_park       | io_uring.c                   | function call
io_sq_thread_unpark     | io_uring.c                | io_sq_thread_unpark(sqd);                                                    | io_sq_thread_unpark     | io_uring.c                   | function call
io_sync_cancel          | cancel.c                  | int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg)                | io_sync_cancel          | cancel.c                     | function definition
io_unregister_iowq_aff  | register.c                | static __cold int io_unregister_iowq_aff(struct io_ring_ctx *ctx)             | io_unregister_iowq_aff  | register.c                   | function definition
io_unregister_napi      | napi.c                    | int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)            | io_unregister_napi      | napi.c                       | function definition
io_unregister_pbuf_ring | kbuf.c                    | int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)       | io_unregister_pbuf_ring | kbuf.c                       | function definition
io_unregister_personality| io_uring.c               | io_unregister_personality(ctx, index);                                       | io_unregister_personality| io_uring.c                   | function call
io_uring_fill_params    | io_uring.c                | int io_uring_fill_params(unsigned entries, struct io_uring_params *p)         | io_uring_fill_params    | io_uring.c                   | function definition
io_uring_op_supported   | opdef.c                   | bool io_uring_op_supported(u8 opcode)                                         | io_uring_op_supported   | opdef.c                      | function definition
__io_uring_register     | register.c                | static int __io_uring_register(struct io_ring_ctx *ctx, unsigned opcode,     | __io_uring_register     | register.c                   | function definition
io_uring_register       | register.c                | * Code related to the io_uring_register() syscall                             | io_uring_register       | register.c                   | function call
io_uring_register_blind | register.c                | static int io_uring_register_blind(unsigned int opcode, void __user *arg,    | io_uring_register_blind | register.c                   | function definition
io_uring_register_get_file| register.c               | struct file *io_uring_register_get_file(unsigned int fd, bool registered)     | io_uring_register_get_file| register.c                  | function call
io_uring_sync_msg_ring  | msg_ring.c                | int io_uring_sync_msg_ring(struct io_uring_sqe *sqe)                         | io_uring_sync_msg_ring  | msg_ring.c                   | function definition
io_wq_cpu_affinity      | io-wq.c                   | int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask)       | io_wq_cpu_affinity      | io-wq.c                      | function definition
io_wq_max_workers       | io-wq.c                   | int io_wq_max_workers(struct io_wq *wq, int *new_count)                       | io_wq_max_workers       | io-wq.c                      | function definition
IS_ERR                  | eventfd.c                 | if (IS_ERR(ev_fd->cq_ev_fd))                                                 | IS_ERR                  | eventfd.c                    | macro
kfree                   | alloc_cache.h             | kfree(*iov);                                                                 | kfree                   | alloc_cache.h                | function call
kzalloc                 | io-wq.c                   | worker = kzalloc(sizeof(*worker), GFP_KERNEL);                               | kzalloc                 | io-wq.c                      | function call
list_for_each_entry     | cancel.c                  | list_for_each_entry(node, &ctx->tctx_list, ctx_node)                         | list_for_each_entry     | cancel.c                     | function call
memchr_inv              | memmap.c                  | if (memchr_inv(&reg->__resv, 0, sizeof(reg->__resv)))                        | memchr_inv              | memmap.c                     | function call
memdup_user             | register.c                | res = memdup_user(arg, size);                                                | memdup_user             | register.c                   | function call
memset                  | alloc_cache.c             | memset(obj, 0, cache->init_clear);                                           | memset                  | alloc_cache.c                | function call
__must_hold           | cancel.c                   | &ctx->uring_lock                                                | __must_hold            | cancel.c                        | macro                          
mutex_lock            | cancel.c                   | &ctx->uring_lock                                                | mutex_lock             | cancel.c                        | function call                   
mutex_unlock          | cancel.c                   | &ctx->uring_lock                                                | mutex_unlock           | cancel.c                        | function call                   
PAGE_ALIGN            | io_uring.c                 | size                                                            | PAGE_ALIGN             | io_uring.c                      | macro                          
percpu_ref_is_dying   | io_uring.h                 | &ctx->refs                                                      | percpu_ref_is_dying    | io_uring.h                      | function call                   
PTR_ERR               | eventfd.c                  | ev_fd->cq_ev_fd                                                 | PTR_ERR                | eventfd.c                       | macro                          
put_cred              | io_uring.c                 | req->creds                                                      | put_cred               | io_uring.c                      | function call                   
READ_ONCE             | advise.c                   | sqe->addr                                                       | READ_ONCE              | advise.c                        | function call                   
refcount_inc          | io-wq.c                    | &data->hash->refs                                               | refcount_inc           | io-wq.c                         | function call                   
__releases            | io-wq.c                    | &acct->lock                                                     | __releases             | io-wq.c                         | macro                          
RESIZE_FLAGS          | register.c                 | IORING_SETUP_CQSIZE, IORING_SETUP_CLAMP                         | RESIZE_FLAGS           | register.c                      | macro                          
rings_size            | io_uring.c                 | flags, sq_entries                                               | rings_size             | io_uring.c                      | function definition            
__set_bit             | filetable.h                | bit, table->bitmap                                              | __set_bit              | filetable.h                     | function call                   
sizeof                | alloc_cache.c              | void *                                                          | sizeof                 | alloc_cache.c                   | operator                       
spin_lock             | cancel.c                   | &ctx->completion_lock                                           | spin_lock              | cancel.c                        | function call                   
spin_unlock           | cancel.c                   | &ctx->completion_lock                                           | spin_unlock            | cancel.c                        | function call                   
struct_size           | io_uring.c                 | rings, cqes, cq_entries                                         | struct_size            | io_uring.c                      | macro                          
swap_old              | register.c                 | ctx, o, n, field                                                | swap_old               | register.c                      | macro                          
switch                | advise.c                   | fa->advice                                                      | switch                 | advise.c                        | conditional branch             
SYSCALL_DEFINE4       | register.c                 | io_uring_register, fd, opcode, arg                              | SYSCALL_DEFINE4        | register.c                      | macro                          
test_bit              | filetable.h                | bit, table->bitmap                                              | test_bit               | filetable.h                     | function call                   
trace_io_uring_register | register.c               | ctx, opcode, ctx->file_table.data.nr                            | trace_io_uring_register| register.c                      | function call                   
u64_to_user_ptr       | epoll.c                    | READ_ONCE(sqe->addr)                                            | u64_to_user_ptr        | epoll.c                         | macro                          
unlikely              | cancel.c                   | req->flags & REQ_F_BUFFER_SELECT                                | unlikely               | cancel.c                        | macro                          
wake_up               | io-wq.c                    | &wq->hash->wait                                                 | wake_up                | io-wq.c                         | function call                   
WARN_ON_ONCE          | advise.c                   | issue_flags & IO_URING_F_NONBLOCK                               | WARN_ON_ONCE           | advise.c                        | macro                          
while                 | alloc_cache.c              | io_alloc_cache_get(cache)                                       | while                  | alloc_cache.c                   | loop                           
wq_has_sleeper        | io-wq.c                    | &wq->hash->wait                                                 | wq_has_sleeper         | io-wq.c                         | function call                   
WRITE_ONCE            | io_uring.c                 | READ/WRITE_ONCE()                                               | WRITE_ONCE             | io_uring.c                      | function call                   
xa_alloc_cyclic       | register.c                 | &ctx->personalities, &id, creds                                 | xa_alloc_cyclic        | register.c                      | function call                   
xa_erase              | kbuf.c                     | &ctx->io_bl_xa, bl->bgid                                        | xa_erase               | kbuf.c                          | function call                   
XA_LIMIT              | register.c                 | 0, USHRT_MAX, &ctx->pers_next                                   | XA_LIMIT               | register.c                      | macro                          
atomic64_add              | rsrc.c       | &ctx->mm_account->pinned_vm                                  | atomic64_add            | rsrc.c                          | function call             
atomic64_sub              | rsrc.c       | &ctx->mm_account->pinned_vm                                  | atomic64_sub            | rsrc.c                          | function call             
atomic_long_read          | rsrc.c       | &user->locked_vm                                             | atomic_long_read        | rsrc.c                          | function call             
atomic_long_try_cmpxchg   | rsrc.c       | &user->locked_vm                                             | atomic_long_try_cmpxchg | rsrc.c                          | function call             
bvec_set_page             | rsrc.c       | &imu->bvec[i], pages[i], vec_len, off                        | bvec_set_page           | rsrc.c                          | function call             
compound_head             | rsrc.c       | compound_head(pages[i]) == hpage                             | compound_head           | rsrc.c                          | function call             
folio_nr_pages            | rsrc.c       | folio_nr_pages(folio)                                        | folio_nr_pages          | rsrc.c                          | function call             
folio_page_idx            | rsrc.c       | folio_page_idx(folio, page_array[i-1])                       | folio_page_idx          | rsrc.c                          | function call             
folio_shift               | rsrc.c       | folio_shift(folio)                                           | folio_shift             | rsrc.c                          | function call             
folio_size                | rsrc.c       | folio_size(folio) != (1UL << data->folio_shift)             | folio_size              | rsrc.c                          | function call             
headpage_already_acct     | rsrc.c       | headpage_already_acct(...)                                   | headpage_already_acct   | rsrc.c                          | function call             
io_account_mem            | rsrc.c       | io_account_mem(...)                                          | io_account_mem          | rsrc.c                          | function call             
io_buffer_account_pin     | rsrc.c       | io_buffer_account_pin(...)                                   | io_buffer_account_pin   | rsrc.c                          | function call             
io_buffer_unmap           | rsrc.c       | io_buffer_unmap(...)                                         | io_buffer_unmap         | rsrc.c                          | function call             
io_buffer_validate        | rsrc.c       | io_buffer_validate(...)                                      | io_buffer_validate      | rsrc.c                          | function call             
io_clone_buffers          | rsrc.c       | io_clone_buffers(...)                                        | io_clone_buffers        | rsrc.c                          | function call             
io_coalesce_buffer        | rsrc.c       | io_coalesce_buffer(...)                                      | io_coalesce_buffer      | rsrc.c                          | function call             
io_files_update_with_index_alloc | rsrc.c | io_files_update_with_index_alloc(...)                        | io_files_update_with_index_alloc | rsrc.c                 | function call             
io_free_rsrc_node         | rsrc.c       | io_free_rsrc_node(...)                                       | io_free_rsrc_node       | rsrc.c                          | function call             
io_put_rsrc_node          | rsrc.c       | io_put_rsrc_node(ctx, data->nodes[data->nr])                | io_put_rsrc_node        | rsrc.c                          | function call             
__io_register_rsrc_update | rsrc.c       | __io_register_rsrc_update(...)                               | __io_register_rsrc_update | rsrc.c                        | function call             
io_sqe_buffer_register    | rsrc.c       | io_sqe_buffer_register(...)                                  | io_sqe_buffer_register  | rsrc.c                          | function call             
__io_sqe_buffers_update   | rsrc.c       | __io_sqe_buffers_update(...)                                 | __io_sqe_buffers_update | rsrc.c                          | function call             
__io_sqe_files_update     | rsrc.c       | __io_sqe_files_update(...)                                   | __io_sqe_files_update   | rsrc.c                          | function call             
io_unaccount_mem          | rsrc.c       | io_unaccount_mem(...)                                        | io_unaccount_mem        | rsrc.c                          | function call             
IORING_MAX_FIXED_FILES    | rsrc.c       | digunakan sebagai batas                                      | IORING_MAX_FIXED_FILES  | rsrc.c                          | macro                     
IORING_MAX_REG_BUFFERS    | rsrc.c       | digunakan sebagai batas                                      | IORING_MAX_REG_BUFFERS  | rsrc.c                          | macro                     
iovec_from_user           | rsrc.c       | iovec_from_user(...)                                         | iovec_from_user         | rsrc.c                          | function call             
iov_iter_advance          | rsrc.c       | iov_iter_advance(...)                                        | iov_iter_advance        | rsrc.c                          | function call             
iov_iter_bvec           | rsrc.c           | iov_iter_bvec(iter, ddir, imu->bvec, imu->nr_bvecs, len)        | iov_iter_bvec           | rsrc.c                          | function call              
IS_ERR                  | eventfd.c        | IS_ERR(ev_fd->cq_ev_fd)                                         | IS_ERR                  | eventfd.c                       | macro                     
kfree                   | alloc_cache.h    | kfree(*iov)                                                      | kfree                   | alloc_cache.h                   | function call              
kvfree                  | alloc_cache.c    | kvfree(cache->entries)                                          | kvfree                  | alloc_cache.c                   | function call              
kvmalloc                | rsrc.c           | kvmalloc(struct_size(imu, bvec, nr_pages), GFP_KERNEL)         | kvmalloc                | rsrc.c                          | function call              
kvmalloc_array          | alloc_cache.c    | kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL)             | kvmalloc_array          | alloc_cache.c                   | function call              
kzalloc                 | io-wq.c          | kzalloc(sizeof(*worker), GFP_KERNEL)                            | kzalloc                 | io-wq.c                         | function call              
lockdep_assert_held     | futex.c          | lockdep_assert_held(&ctx->uring_lock)                           | lockdep_assert_held     | futex.c                         | macro                     
lock_two_rings          | rsrc.c           | static void lock_two_rings(...)                                 | lock_two_rings          | rsrc.c                          | function definition        
max                     | io-wq.c          | below the max number of workers                                 | max                     | io-wq.c                         | macro                     
memchr_inv              | memmap.c         | memchr_inv(&reg->__resv, 0, sizeof(reg->__resv))               | memchr_inv              | memmap.c                        | function call              
memset                  | alloc_cache.c    | memset(obj, 0, cache->init_clear)                               | memset                  | alloc_cache.c                   | function call              
min                     | fdinfo.c         | min(sq_tail - sq_head, ctx->sq_entries)                         | min                     | fdinfo.c                        | macro                     
min_t                   | kbuf.c           | min_t(__u16, tail - head, UIO_MAXIOV)                           | min_t                   | kbuf.c                          | macro                     
mutex_lock              | cancel.c         | mutex_lock(&ctx->uring_lock)                                    | mutex_lock              | cancel.c                        | function call              
mutex_lock_nested       | rsrc.c           | mutex_lock_nested(&ctx2->uring_lock, SINGLE_DEPTH_NESTING)     | mutex_lock_nested       | rsrc.c                          | function call              
mutex_unlock            | cancel.c         | mutex_unlock(&ctx->uring_lock)                                  | mutex_unlock            | cancel.c                        | function call              
page                    | kbuf.c           | one page even for 4K                                            | page                    | kbuf.c                          | macro/constant             
PageCompound            | rsrc.c           | !PageCompound(pages[i])                                         | PageCompound            | rsrc.c                          | macro                     
page_folio              | rsrc.c           | struct folio *folio = page_folio(page_array[0])                | page_folio              | rsrc.c                          | function call              
page_size               | rsrc.c           | page_size(hpage) >> PAGE_SHIFT                                  | page_size               | rsrc.c                          | function call              
PTR_ERR                 | eventfd.c        | int ret = PTR_ERR(ev_fd->cq_ev_fd)                              | PTR_ERR                 | eventfd.c                       | macro                     
READ_ONCE               | advise.c         | READ_ONCE(sqe->addr)                                            | READ_ONCE               | advise.c                        | macro                     
refcount_dec_and_test   | eventfd.c        | refcount_dec_and_test(&ev_fd->refs)                             | refcount_dec_and_test   | eventfd.c                       | function call              
refcount_inc            | io-wq.c          | refcount_inc(&data->hash->refs)                                 | refcount_inc            | io-wq.c                         | function call              
refcount_set            | eventfd.c        | refcount_set(&ev_fd->refs, 1)                                   | refcount_set            | eventfd.c                       | function call              
req_set_fail            | advise.c         | req_set_fail(req)                                               | req_set_fail            | advise.c                        | function call              
rlimit                  | net.c            | rlimit(RLIMIT_NOFILE)                                           | rlimit                  | net.c                           | function call              
sizeof                  | alloc_cache.c    | sizeof(void *)                                                  | sizeof                  | alloc_cache.c                   | macro                     
struct_size             | io_uring.c       | struct_size(rings, cqes, cq_entries)                            | struct_size             | io_uring.c                      | macro                     
swap                    | register.c       | used for swap.                                                  | swap                    | register.c                      | keyword                    
switch                  | advise.c         | switch (fa->advice)                                             | switch                  | advise.c                        | keyword                    
u64_to_user_ptr         | epoll.c          | u64_to_user_ptr(READ_ONCE(sqe->addr))                          | u64_to_user_ptr         | epoll.c                         | macro                     
unlikely                | cancel.c         | unlikely(req->flags & REQ_F_BUFFER_SELECT)                     | unlikely                | cancel.c                        | macro                     
unpin_user_page         | rsrc.c           | unpin_user_page(imu->bvec[i].bv_page)                          | unpin_user_page         | rsrc.c                          | function call              
unpin_user_pages        | memmap.c         | unpin_user_pages(pages, ret)                                   | unpin_user_pages        | memmap.c                        | function call              
WARN_ON_ONCE            | advise.c         | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK)               | WARN_ON_ONCE            | advise.c                        | macro                     
while                   | alloc_cache.c    | while ((entry = io_alloc_cache_get(cache)) != NULL)           | while                   | alloc_cache.c                   | keyword                    
yet                     | io-wq.c          | isn't yet discoverable                                          | yet                     | io-wq.c                         | keyword/semantic marker     
cmd_to_io_kiocb           | msg_ring.c                | struct io_kiocb *req = cmd_to_io_kiocb(msg);                              | cmd_to_io_kiocb           | msg_ring.c                    | function call                   
defined                   | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                 | defined                   | advise.c                      | macro                          
do_sock_getsockopt        | uring_cmd.c               | err = do_sock_getsockopt(sock, compat, level, optname,                    | do_sock_getsockopt        | uring_cmd.c                  | function call                   
do_sock_setsockopt        | uring_cmd.c               | return do_sock_setsockopt(sock, compat, level, optname, optval_s,         | do_sock_setsockopt        | uring_cmd.c                  | function call                   
EXPORT_SYMBOL_GPL         | uring_cmd.c               | EXPORT_SYMBOL_GPL(io_uring_cmd_mark_cancelable);                           | EXPORT_SYMBOL_GPL         | uring_cmd.c                  | macro                          
hlist_add_head            | futex.c                   | hlist_add_head(&req->hash_node, &ctx->futex_list);                        | hlist_add_head            | futex.c                       | function call                   
hlist_del                 | uring_cmd.c               | hlist_del(&req->hash_node);                                               | hlist_del                 | uring_cmd.c                  | function call                   
hlist_for_each_entry_safe | futex.c                   | hlist_for_each_entry_safe(req, tmp, &ctx->futex_list, hash_node) {        | hlist_for_each_entry_safe | futex.c                       | function call                   
if                        | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                 | if                        | advise.c                      | macro                          
io_alloc_cache_put        | alloc_cache.h             | static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,       | io_alloc_cache_put        | alloc_cache.h                | function definition             
ioctl                     | uring_cmd.c               | if (!prot || !prot->ioctl)                                                | ioctl                     | uring_cmd.c                  | function call                   
io_import_fixed           | net.c                     | ret = io_import_fixed(ITER_SOURCE, &kmsg->msg.msg_iter,                   | io_import_fixed           | net.c                         | function call                   
io_iopoll_req_issued      | io_uring.c                | static void io_iopoll_req_issued(struct io_kiocb *req, unsigned int issue_flags) | io_iopoll_req_issued      | io_uring.c                    | function definition             
io_kiocb_to_cmd           | advise.c                  | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);           | io_kiocb_to_cmd           | advise.c                      | function call                   
io_req_assign_buf_node    | net.c                     | io_req_assign_buf_node(sr->notif, node);                                   | io_req_assign_buf_node    | net.c                         | function call                   
io_req_complete_defer     | io_uring.c                | io_req_complete_defer(req);                                               | io_req_complete_defer     | io_uring.c                    | function call                   
io_req_queue_iowq         | io_uring.c                | void io_req_queue_iowq(struct io_kiocb *req)                              | io_req_queue_iowq         | io_uring.c                    | function definition             
io_req_set_cqe32_extra    | uring_cmd.c               | static inline void io_req_set_cqe32_extra(struct io_kiocb *req,           | io_req_set_cqe32_extra    | uring_cmd.c                  | function definition             
io_req_set_res            | advise.c                  | io_req_set_res(req, ret, 0);                                              | io_req_set_res            | advise.c                      | function call                   
__io_req_task_work_add    | io_uring.c                | void __io_req_task_work_add(struct io_kiocb *req, unsigned flags)         | __io_req_task_work_add    | io_uring.c                    | function definition             
io_req_task_work_add      | futex.c                   | io_req_task_work_add(req);                                                | io_req_task_work_add      | futex.c                       | function call                   
io_req_uring_cleanup      | uring_cmd.c               | static void io_req_uring_cleanup(struct io_kiocb *req, unsigned int issue_flags) | io_req_uring_cleanup      | uring_cmd.c                  | function definition             
io_ring_submit_lock       | cancel.c                  | io_ring_submit_lock(ctx, issue_flags);                                    | io_ring_submit_lock       | cancel.c                      | function call                   
io_ring_submit_unlock     | cancel.c                  | io_ring_submit_unlock(ctx, issue_flags);                                  | io_ring_submit_unlock     | cancel.c                      | function call                   
io_rsrc_node_lookup       | cancel.c                  | node = io_rsrc_node_lookup(&ctx->file_table.data, fd);                    | io_rsrc_node_lookup       | cancel.c                      | function call                   
io_should_terminate_tw    | io_uring.c                | if (unlikely(io_should_terminate_tw()))                                    | io_should_terminate_tw    | io_uring.c                    | function call                   
io_submit_flush_completions| io_uring.c                | io_submit_flush_completions(ctx);                                          | io_submit_flush_completions| io_uring.c                    | function call                   
io_uring_alloc_async_data | io_uring.h                | static inline void *io_uring_alloc_async_data(struct io_alloc_cache *cache, | io_uring_alloc_async_data | io_uring.h                    | function definition             
io_uring_cmd              | opdef.c                   | .issue = io_uring_cmd,                                                    | io_uring_cmd              | opdef.c                       | function definition             
io_uring_cmd_del_cancelable | uring_cmd.c             | static void io_uring_cmd_del_cancelable(struct io_uring_cmd *cmd,         | io_uring_cmd_del_cancelable | uring_cmd.c                  | function definition             
__io_uring_cmd_do_in_task| uring_cmd.c               | void __io_uring_cmd_do_in_task(struct io_uring_cmd *ioucmd,               | __io_uring_cmd_do_in_task| uring_cmd.c                   | function definition             
io_uring_cmd_done         | uring_cmd.c               | void io_uring_cmd_done(struct io_uring_cmd *ioucmd, ssize_t ret, u64 res2,| io_uring_cmd_done         | uring_cmd.c                   | function definition             
io_uring_cmd_getsockopt   | uring_cmd.c               | static inline int io_uring_cmd_getsockopt(struct socket *sock,             | io_uring_cmd_getsockopt   | uring_cmd.c                   | function definition             
io_uring_cmd_import_fixed | uring_cmd.c               | * Pi node upfront, prior to io_uring_cmd_import_fixed()                    | io_uring_cmd_import_fixed | uring_cmd.c                   | function call                   
io_uring_cmd_issue_blocking | uring_cmd.c             | void io_uring_cmd_issue_blocking(struct io_uring_cmd *ioucmd)             | io_uring_cmd_issue_blocking| uring_cmd.c                  | function definition             
io_uring_cmd_mark_cancelable | uring_cmd.c            | void io_uring_cmd_mark_cancelable(struct io_uring_cmd *cmd,               | io_uring_cmd_mark_cancelable| uring_cmd.c                  | function definition             
io_uring_cmd_prep         | opdef.c                   | .prep = io_uring_cmd_prep,                                                | io_uring_cmd_prep         | opdef.c                       | function definition             
io_uring_cmd_prep_setup   | uring_cmd.c               | static int io_uring_cmd_prep_setup(struct io_kiocb *req,                  | io_uring_cmd_prep_setup   | uring_cmd.c                   | function definition             
io_uring_cmd_setsockopt   | uring_cmd.c               | static inline int io_uring_cmd_setsockopt(struct socket *sock,             | io_uring_cmd_setsockopt   | uring_cmd.c                   | function definition             
io_uring_cmd_sock         | uring_cmd.c               | int io_uring_cmd_sock(struct io_uring_cmd *cmd, unsigned int issue_flags) | io_uring_cmd_sock         | uring_cmd.c                   | function definition             
io_uring_cmd_work          | uring_cmd.c               | static void io_uring_cmd_work(struct io_kiocb *req, struct io_tw_state *ts)   | io_uring_cmd_work          | uring_cmd.c                   | function definition             
io_uring_try_cancel_uring_cmd| io_uring.c               | ret |= io_uring_try_cancel_uring_cmd(ctx, tctx, cancel_all);                  | io_uring_try_cancel_uring_cmd| io_uring.c                    | function call                   
KERNEL_SOCKPTR             | uring_cmd.c               | KERNEL_SOCKPTR(&optlen));                                                  | KERNEL_SOCKPTR             | uring_cmd.c                   | macro                          
kfree                      | alloc_cache.h             | kfree(*iov);                                                               | kfree                      | alloc_cache.h                 | function call                   
lockdep_assert_held        | futex.c                   | lockdep_assert_held(&ctx->uring_lock);                                       | lockdep_assert_held        | futex.c                       | function call                   
memcpy                     | io_uring.c                | memcpy(cqe, &ocqe->cqe, cqe_size);                                          | memcpy                     | io_uring.c                    | function call                   
READ_ONCE                  | advise.c                  | ma->addr = READ_ONCE(sqe->addr);                                            | READ_ONCE                  | advise.c                      | function call                   
req_set_fail               | advise.c                  | req_set_fail(req);                                                          | req_set_fail               | advise.c                      | function call                   
security_uring_cmd         | uring_cmd.c               | ret = security_uring_cmd(ioucmd);                                            | security_uring_cmd         | uring_cmd.c                   | function call                   
smp_store_release          | io_uring.c                | * through a control-dependency in io_get_cqe (smp_store_release to            | smp_store_release          | io_uring.c                    | function call                   
switch                     | advise.c                  | switch (fa->advice) {                                                       | switch                     | advise.c                      | conditional branch             
task_work_cb               | uring_cmd.c               | ioucmd->task_work_cb(ioucmd, flags);                                        | task_work_cb               | uring_cmd.c                   | function call                   
u64_to_user_ptr            | epoll.c                   | ev = u64_to_user_ptr(READ_ONCE(sqe->addr));                                  | u64_to_user_ptr            | epoll.c                       | function call                   
unlikely                   | cancel.c                  | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                             | unlikely                   | cancel.c                      | conditional branch             
uring_cmd                  | Makefile                  | eventfd.o uring_cmd.o openclose.o \                                          | uring_cmd                  | Makefile                      | compilation unit               
uring_sqe_size             | io_uring.h                | static inline size_t uring_sqe_size(struct io_ring_ctx *ctx)                 | uring_sqe_size             | io_uring.h                    | function definition             
USER_SOCKPTR               | uring_cmd.c               | USER_SOCKPTR(optval),                                                       | USER_SOCKPTR               | uring_cmd.c                   | macro                          
void                       | alloc_cache.c             | void io_alloc_cache_free(struct io_alloc_cache *cache)                       | void                       | alloc_cache.c                 | function definition             
WARN_ON_ONCE               | advise.c                  | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                            | WARN_ON_ONCE               | advise.c                      | macro                          
43adf8449510            | futex.c                   | * See commit 43adf8449510 ("futex: FLAGS_STRICT") for details.               | 43adf8449510            | futex.c                      | commit reference              
container_of            | cancel.c                  | struct io_kiocb *req = container_of(work, struct io_kiocb, work);           | container_of            | cancel.c                     | function call                   
futex2_to_flags         | futex.c                   | iof->futex_flags = futex2_to_flags(flags);                                 | futex2_to_flags         | futex.c                      | function call                   
futex_flags_valid       | futex.c                   | if (!futex_flags_valid(iof->futex_flags))                                  | futex_flags_valid       | futex.c                      | function call                   
futex_parse_waitv       | futex.c                   | ret = futex_parse_waitv(futexv, iof->uwaitv, iof->futex_nr,                | futex_parse_waitv       | futex.c                      | function call                   
futex_queue             | futex.c                   | futex_queue(&ifd->q, hb, NULL);                                            | futex_queue             | futex.c                      | function call                   
futex_unqueue           | futex.c                   | if (!futex_unqueue(&ifd->q))                                               | futex_unqueue           | futex.c                      | function call                   
futex_unqueue_multiple  | futex.c                   | res = futex_unqueue_multiple(futexv, iof->futex_nr);                       | futex_unqueue_multiple  | futex.c                      | function call                   
futex_validate_input    | futex.c                   | if (!futex_validate_input(iof->futex_flags, iof->futex_val) ||             | futex_validate_input    | futex.c                      | function call                   
futex_wait_multiple_setup| futex.c                  | ret = futex_wait_multiple_setup(futexv, iof->futex_nr, &woken);            | futex_wait_multiple_setup| futex.c                      | function call                   
futex_wait_setup        | futex.c                   | ret = futex_wait_setup(iof->uaddr, iof->futex_val, iof->futex_flags,        | futex_wait_setup        | futex.c                      | function call                   
futex_wake              | futex.c                   | ret = futex_wake(iof->uaddr, FLAGS_STRICT | iof->futex_flags,               | futex_wake              | futex.c                      | function call                   
__futex_wake_mark       | futex.c                   | if (unlikely(!__futex_wake_mark(q)))                                        | __futex_wake_mark       | futex.c                      | function call                   
hlist_add_head          | futex.c                   | hlist_add_head(&req->hash_node, &ctx->futex_list);                          | hlist_add_head          | futex.c                      | function call                   
hlist_del_init          | futex.c                   | hlist_del_init(&req->hash_node);                                           | hlist_del_init          | futex.c                      | function call                   
hlist_for_each_entry_safe| futex.c                   | hlist_for_each_entry_safe(req, tmp, &ctx->futex_list, hash_node) {           | hlist_for_each_entry_safe| futex.c                      | function call                   
io_alloc_cache_free     | alloc_cache.c             | void io_alloc_cache_free(struct io_alloc_cache *cache)                      | io_alloc_cache_free     | alloc_cache.c                | function definition             
io_alloc_cache_init     | alloc_cache.c             | bool io_alloc_cache_init(struct io_alloc_cache *cache)                      | io_alloc_cache_init     | alloc_cache.c                | function definition             
io_alloc_cache_put      | alloc_cache.h             | static inline bool io_alloc_cache_put(struct io_alloc_cache *cache)          | io_alloc_cache_put      | alloc_cache.h                | function definition             
io_cache_alloc          | alloc_cache.h             | static inline void *io_cache_alloc(struct io_alloc_cache *cache, gfp_t gfp) | io_cache_alloc          | alloc_cache.h                | function definition             
io_futex_cache_free     | futex.c                   | void io_futex_cache_free(struct io_ring_ctx *ctx)                           | io_futex_cache_free     | futex.c                      | function definition             
io_futex_cache_init     | futex.c                   | bool io_futex_cache_init(struct io_ring_ctx *ctx)                           | io_futex_cache_init     | futex.c                      | function definition             
__io_futex_cancel       | futex.c                   | static bool __io_futex_cancel(struct io_ring_ctx *ctx, struct io_kiocb *req)| __io_futex_cancel       | futex.c                      | function definition             
io_futex_cancel         | cancel.c                  | ret = io_futex_cancel(ctx, cd, issue_flags);                                | io_futex_cancel         | cancel.c                     | function call                   
__io_futex_complete     | futex.c                   | static void __io_futex_complete(struct io_kiocb *req, struct io_tw_state *ts)| __io_futex_complete     | futex.c                      | function definition             
io_futex_complete       | futex.c                   | static void io_futex_complete(struct io_kiocb *req, struct io_tw_state *ts) | io_futex_complete       | futex.c                      | function definition             
io_futex_prep           | futex.c                   | int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)     | io_futex_prep           | futex.c                      | function definition             
io_futex_remove_all     | futex.c                   | bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,| io_futex_remove_all     | futex.c                      | function definition             
io_futexv_claim         | futex.c                   | static bool io_futexv_claim(struct io_futex *iof)                           | io_futexv_claim         | futex.c                      | function definition             
io_futexv_complete      | futex.c                   | static void io_futexv_complete(struct io_kiocb *req, struct io_tw_state *ts)| io_futexv_complete      | futex.c                      | function definition             
io_futexv_prep          | futex.c                   | int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)    | io_futexv_prep          | futex.c                      | function definition             
io_futexv_wait          | futex.c                   | int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags)          | io_futexv_wait          | futex.c                      | function call                   
io_futex_wait           | futex.c                   | int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags)           | io_futex_wait           | futex.c                      | function call                   
io_futex_wake           | futex.c                   | int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags)           | io_futex_wake           | futex.c                      | function call                   
io_futex_wake_fn        | futex.c                   | static void io_futex_wake_fn(struct wake_q_head *wake_q, struct futex_q *q) | io_futex_wake_fn        | futex.c                      | function definition             
io_futex_wakev_fn       | futex.c                   | static void io_futex_wakev_fn(struct wake_q_head *wake_q, struct futex_q *q)| io_futex_wakev_fn       | futex.c                      | function definition             
io_kiocb_to_cmd         | advise.c                  | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);            | io_kiocb_to_cmd         | advise.c                     | function call                   
io_match_task_safe      | futex.c                   | if (!io_match_task_safe(req, tctx, cancel_all))                             | io_match_task_safe      | futex.c                      | function call                   
io_req_set_res          | advise.c                  | io_req_set_res(req, ret, 0);                                               | io_req_set_res          | advise.c                     | function call                   
io_req_task_complete    | futex.c                   | io_req_task_complete(req, ts);                                             | io_req_task_complete    | futex.c                      | function call                   
io_req_task_work_add    | futex.c                   | io_req_task_work_add(req);                                                 | io_req_task_work_add    | futex.c                      | function call                   
io_ring_submit_lock     | cancel.c                  | io_ring_submit_lock(ctx, issue_flags);                                      | io_ring_submit_lock     | cancel.c                     | function call                   
io_ring_submit_unlock   | cancel.c                  | io_ring_submit_unlock(ctx, issue_flags);                                    | io_ring_submit_unlock   | cancel.c                     | function call                   
io_tw_lock             | futex.c                   | io_tw_lock(ctx, ts);                                                       | io_tw_lock             | futex.c                      | function call                   
kcalloc                | futex.c                   | futexv = kcalloc(iof->futex_nr, sizeof(*futexv), GFP_KERNEL);                | kcalloc                | futex.c                      | memory allocation call           
kfree                  | alloc_cache.h             | kfree(*iov);                                                                | kfree                  | alloc_cache.h                | memory deallocation call         
lockdep_assert_held    | futex.c                   | lockdep_assert_held(&ctx->uring_lock);                                      | lockdep_assert_held    | futex.c                      | function call                   
READ_ONCE              | advise.c                  | ma->addr = READ_ONCE(sqe->addr);                                            | READ_ONCE              | advise.c                     | macro call                      
req_set_fail           | advise.c                  | req_set_fail(req);                                                          | req_set_fail           | advise.c                     | function call                   
__set_current_state    | futex.c                   | __set_current_state(TASK_RUNNING);                                           | __set_current_state    | futex.c                      | function call                   
sizeof                 | alloc_cache.c             | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);         | sizeof                 | alloc_cache.c                | operator call                   
test_and_set_bit_lock | futex.c                   | test_and_set_bit_lock(0, &iof->futexv_owned)                                 | test_and_set_bit_lock | futex.c                      | function call                   
test_bit               | filetable.h               | WARN_ON_ONCE(!test_bit(bit, table->bitmap));                                 | test_bit               | filetable.h                  | macro call                      
u64_to_user_ptr        | epoll.c                   | ev = u64_to_user_ptr(READ_ONCE(sqe->addr));                                  | u64_to_user_ptr        | epoll.c                      | macro call                      
unlikely              | cancel.c                  | if (unlikely(req->flags & REQ_F_BUFFER_SELECT))                             | unlikely               | cancel.c                     | macro call                      


If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.
