# Task 2: Dependency Injection
For this assigment, we want a little clarity regarding what kind of functions being imported and used on each source. Do note, we record all function actually being used by the source including function defined by itself if actually used inside the file. For the sake of completion, it's better if you straight disregard include list on the source. Instead, trace each function being used to the declared source.

# Source .c
Source | Libary | Function utilized | Time Used |
-------|--------|--------------| ------------------|
advise.c | io_uring/advise.c | io_fadsive | 1
|| io_uring/advice.c |io_fadsive_force_async | 3
|| io_uring/advise.c |io_fadsive_prep | 1
|| io_uring/advice.c |io_madsive | 1
|| io_uring/advice.c |io_madsive_prep | 1
|| mm/madvise.c |do_madvise | 1
|| include/asm-generic/rwonce.h | READ_ONCE | 8
|| io_uring/io_uring.h |req_set_fail | 1
|| mm/fadvise.c | vfs_fadvise | 1
alloc_cache.c | io_uring/alloc_cache.c| io_alloc_cache_free | 1
|| io_uring/alloc_cache.c| io_alloc_cache_init | 1
|| io_uring/alloc_cache.c| io_alloc_cache_new | 1
cancel.c | io_uring/cancel.c | io_cancel_req_match | 2
|| io_uring/cancel.c | io_cancel_cb | 1
|| include/linux/atomic/atomic-instrumented.h | io_async_cancel_one | 3
|| drivers/gpu/drm/radeon/mkregtable.c | container_of | 2
|| include/linux/uaccess.h | copy_from_user | 1
|| io_uring/cancel.c | io_try_cancel | 2
|| io_uring/cancel.c | io_async_cancel_prep | 1
|| io_uring/cancel.c | __io_async_cancel | 3
|| io_uring/cancel.c | io_async_cancel | 1
|| io_uring/cancel.c | __io_sync_cancel | 3
|| io_uring/cancel.c | io_sync_cancel | 1
|| arch/x86/boot/boot.h | ARRAY_SIZE | 2
|| arch/x86/boot/boot.h | atomic_inc_return | 3
epoll.c | io_uring/epoll.c | io_epoll_ctl | 2
|| io_uring/epoll.c | io_epoll_ctl_prep | 1
eventfd.c | io_uring/eventfd.c | io_eventfd_free | 1
|| io_uring/eventfd.c | io_eventfd_put | 4
|| io_uring/eventfd.c | io_eventfd_do_signal | 1
|| io_uring/eventfd.c | io_eventfd_release | 3
|| io_uring/eventfd.c | __io_eventfd_signal | 3
|| io_uring/eventfd.c | io_eventfd_trigger | 2
|| io_uring/eventfd.c | io_eventfd_grab | 3
|| io_uring/eventfd.c | io_eventfd_signal | 1
|| io_uring/eventfd.c | io_eventfd_flush_signal | 1
|| io_uring/eventfd.c | io_eventfd_register | 1
|| io_uring/eventfd.c | io_eventfd_unregister | 1
|| include/linux/atomic/atomic-instrumented.h | atomic_fetch_or | 1
|| include/linux/atomic/atomic-instrumented.h | atomic_set | 1
|| drivers/comedi/drivers/ni_routing/tools/convert_c_to_py.c | BIT | 1
|| kernel/rcu/tiny.c | call_rcu | 1
|| include/linux/rcupdate.h | call_rcu_hurry| 1
|| drivers/gpu/drm/radeon/mkregtable.c | container_of| 1
|| include/linux/uaccess.h | copy_from_user| 1
|| fs/eventfd.c | eventfd_ctx_fdget| 1
|| fs/eventfd.c | eventfd_ctx_put| 1
|| include/linux/eventfd.h | eventfd_signal_allowed| 1
|| fs/eventfd.c | eventfd_signal_mask| 1
fdinfo.c | io_uring/fdinfo.c | io_uring_show_cred | 2
|| io_uring/fdinfo.c | common_tracking_show_fdinfo | 3
|| io_uring/fdinfo.c | napi_show_fdinfo | 3
|| io_uring/fdinfo.c | io_uring_show_fdinfo | 1
filetable.c | io_uring/filetable.c |io_file_bitmap_get | 2
|| io_uring/filetable.c |io_alloc_file_tables | 1
|| io_uring/filetable.c |io_free_file_tables | 1
|| io_uring/filetable.c |io_install_fixed_file | 2
|| io_uring/filetable.c |__io_fixed_fd_install | 2
|| io_uring/filetable.c |io_fixed_fd_install | 2
|| io_uring/filetable.c |io_fixed_fd_remove | 1
|| io_uring/filetable.c |io_register_file_alloc_range | 1
fs.c | io_uring/fs.c | io_renameat_prep | 1
|| io_uring/fs.c | io_renameat | 1
|| io_uring/fs.c | io_renameat_cleanup | 1
|| io_uring/fs.c | io_unlinkat_prep | 1
|| io_uring/fs.c | io_unlinkat | 1
|| io_uring/fs.c | io_unlinkat_cleanup | 1
|| io_uring/fs.c | io_mkdirat_prep | 1
|| io_uring/fs.c | io_mkdirat_cleanup | 1
|| io_uring/fs.c | io_symlinkat_prep | 1
|| io_uring/fs.c | io_symlinkat | 1
|| io_uring/fs.c | io_linkat_prep | 1
|| io_uring/fs.c | io_linkat | 1
|| io_uring/fs.c | io_link_cleanup | 1
futex.c | io_uring/futex.c | io_futex_cache_init | 1
|| io_uring/futex.c | io_futex_cache_free | 1
|| io_uring/futex.c | __io_futex_complete | 3
|| io_uring/futex.c | io_futex_complete | 1
|| io_uring/futex.c | io_futexv_complete | 1
|| io_uring/futex.c | io_futexv_claim | 3
|| io_uring/futex.c | __io_futex_cancel | 3
|| io_uring/futex.c | io_futex_cancel | 1
|| io_uring/futex.c | io_futex_remove_all | 1
|| io_uring/futex.c | io_futex_prep | 1
|| io_uring/futex.c | io_futex_wakev_fn | 1
|| io_uring/futex.c | io_futexv_prep | 1
|| io_uring/futex.c | io_futex_wake_fn | 1
|| io_uring/futex.c | io_futexv_wait | 1
|| io_uring/futex.c | io_futex_wait | 1
|| io_uring/futex.c | io_futex_wake | 1
io_uring.c | io_uring/io_uring.c | io_uring_try_cancel_requests | 5
|| io_uring/io_uring.c | io_queue_sqe | 4
|| io_uring/io_uring.c | __io_cqring_events | 4
|| io_uring/io_uring.c | __io_cqring_events_user | 3
|| io_uring/io_uring.c | io_match_linked | 3
|| io_uring/io_uring.c | io_match_task_safe | 3
|| io_uring/io_uring.c | req_fail_link_node | 3
|| io_uring/io_uring.c | io_req_add_to_cache | 4
|| io_uring/io_uring.c | io_ring_ctx_ref_free | 1
|| io_uring/io_uring.c | io_fallback_req_func | 1
|| io_uring/io_uring.c | io_alloc_hash_table | 2
|| io_uring/io_uring.c | io_ring_ctx_alloc | 2
|| io_uring/io_uring.c | io_clean_op | 2
|| io_uring/io_uring.c | io_req_track_inflight | 2
|| io_uring/io_uring.c | __io_prep_linked_timeout | 3
|| io_uring/io_uring.c | __io_arm_ltimeout | 2
|| io_uring/io_uring.c | io_arm_ltimeout | 3
|| io_uring/io_uring.c | io_prep_async_work | 3
|| io_uring/io_uring.c | io_prep_async_link | 3
|| io_uring/io_uring.c | io_queue_iowq | 6
|| io_uring/io_uring.c | io_req_queue_iowq_tw | 1
|| io_uring/io_uring.c | io_req_queue_iowq | 1
|| io_uring/io_uring.c | io_queue_deferred | 2
|| io_uring/io_uring.c | __io_commit_cqring_flush | 1
|| io_uring/io_uring.c | __io_cq_lock | 3
|| io_uring/io_uring.c | io_cq_lock | 5
|| io_uring/io_uring.c | __io_cq_unlock_post | 3
|| io_uring/io_uring.c | io_cq_unlock_post | 5
|| io_uring/io_uring.c | __io_cqring_overflow_flush | 4
|| io_uring/io_uring.c | io_cqring_overflow_kill | 3
|| io_uring/io_uring.c | io_put_task | 2
|| io_uring/io_uring.c | io_task_refs_refill | 1
|| io_uring/io_uring.c | io_uring_drop_tctx_refs | 4
|| io_uring/io_uring.c | io_cqring_event_overflow| 4
|| io_uring/io_uring.c | io_req_cqe_overflow | 4
|| io_uring/io_uring.c | io_cqe_cache_refill | 1
|| io_uring/io_uring.c | io_fill_cqe_aux | 4
|| io_uring/io_uring.c | __io_post_aux_cqe | 2
|| io_uring/io_uring.c | io_post_aux_cqe | 1
|| io_uring/io_uring.c | io_add_aux_cqe | 1
|| io_uring/io_uring.c | io_req_post_cqe | 3
|| io_uring/io_uring.c | io_req_complete_post | 2
|| io_uring/io_uring.c | io_req_defer_failed | 6
|| io_uring/io_uring.c | io_preinit_req | 3
|| io_uring/io_uring.c | __io_alloc_req_refill | 1
|| io_uring/io_uring.c | io_free_req | 2
|| io_uring/io_uring.c | __io_req_find_next_prep | 2
|| io_uring/io_uring.c | io_req_find_next | 3
|| io_uring/io_uring.c | ctx_flush_and_put | 4
|| io_uring/io_uring.c | io_handle_tw_list | 2
|| io_uring/io_uring.c | __io_fallback_tw | 4
|| io_uring/io_uring.c | io_fallback_tw | 3
|| io_uring/io_uring.c | tctx_task_work_run | 2
|| io_uring/io_uring.c | tctx_task_work | 1
|| io_uring/io_uring.c | io_req_local_work_add | 5
|| io_uring/io_uring.c | io_req_normal_work_add | 2
|| io_uring/io_uring.c | __io_req_task_work_add | 1
|| io_uring/io_uring.c | io_req_task_work_add_remote | 1
|| io_uring/io_uring.c | io_move_task_work_from_local | 2
|| io_uring/io_uring.c | io_run_local_work_continue | 3
|| io_uring/io_uring.c | __io_run_local_work_loop | 3
|| io_uring/io_uring.c | __io_run_local_work | 3
|| io_uring/io_uring.c | io_run_local_work_locked | 3
|| io_uring/io_uring.c | io_run_local_work | 5
io-wq.c | io_uring/io-wq.c | create_io_worker | 4
|| io_uring/io-wq.c  | io_wq_dec_running | 4
|| io_uring/io-wq.c  | io_acct_cancel_pending_work | 5
|| io_uring/io-wq.c  | create_worker_cb | 2
|| io_uring/io-wq.c  | io_wq_cancel_tw_create | 4
|| io_uring/io-wq.c  | io_worker_get | 4
|| io_uring/io-wq.c  | io_worker_release | 10
|| io_uring/io-wq.c  | io_get_acct | 4
|| io_uring/io-wq.c  | io_work_get_acct | 4
|| io_uring/io-wq.c  | io_wq_get_acct | 8
|| io_uring/io-wq.c  | io_worker_ref_put| 10
|| io_uring/io-wq.c  | io_wq_worker_stopped | 1
|| io_uring/io-wq.c  | io_worker_cancel_cb | 3
|| io_uring/io-wq.c  | io_task_worker_match | 1
|| io_uring/io-wq.c  | io_worker_exit | 2
|| io_uring/io-wq.c  | __io_acct_run_queue | 3
|| io_uring/io-wq.c  | io_acct_run_queue | 5
|| io_uring/io-wq.c  | io_wq_activate_free_worker | 3
|| io_uring/io-wq.c  | io_wq_create_worker | 2
|| io_uring/io-wq.c  | io_wq_inc_running | 2
|| io_uring/io-wq.c  | create_worker_cb | 2
|| io_uring/io-wq.c  | io_queue_worker_create | 3
|| io_uring/io-wq.c  | io_wq_dec_running | 4
|| io_uring/io-wq.c  | __io_worker_busy | 2
|| io_uring/io-wq.c  | __io_worker_idle | 2
|| io_uring/io-wq.c  | io_get_work_hash | 6
|| io_uring/io-wq.c  | io_wait_on_hash | 2
|| io_uring/io-wq.c  | io_get_next_work | 2
|| io_uring/io-wq.c  | io_assign_current_work | 4
|| io_uring/io-wq.c  | io_worker_handle_work | 3
|| io_uring/io-wq.c  | io_wq_worker | 1
|| io_uring/io-wq.c  | io_wq_worker_running | 1
|| io_uring/io-wq.c  | io_wq_worker_sleeping | 1
|| io_uring/io-wq.c  | io_init_new_worker | 3
|| io_uring/io-wq.c  | io_wq_work_match_all | 1
|| io_uring/io-wq.c  | io_should_retry_thread | 3
|| io_uring/io-wq.c  | queue_create_worker_retry | 3
|| io_uring/io-wq.c  | create_worker_cont | 1
|| io_uring/io-wq.c  | io_workqueue_create | 1
|| io_uring/io-wq.c  | create_io_worker | 4
|| io_uring/io-wq.c  | io_wq_for_each_worker | 4
|| io_uring/io-wq.c  | io_wq_worker_wake | 1
|| io_uring/io-wq.c  | io_run_cancel | 3
|| io_uring/io-wq.c | io_wq_insert_work | 2
|| io_uring/io-wq.c | io_wq_work_match_item | 1
|| io_uring/io-wq.c  | io_wq_enqueue | 1
|| io_uring/io-wq.c  | io_wq_hash_work | 1
|| io_uring/io-wq.c  | __io_wq_worker_cancel | 2
|| io_uring/io-wq.c  | io_wq_worker_cancel | 1
|| io_uring/io-wq.c  | io_wq_remove_pending | 2
|| io_uring/io-wq.c  | io_acct_cancel_pending_work | 5
|| io_uring/io-wq.c  | io_wq_cancel_pending_work | 3
|| io_uring/io-wq.c  | io_wq_cancel_running_work | 2
|| io_uring/io-wq.c  | io_wq_cancel_cb | 1
|| io_uring/io-wq.c  | io_wq_hash_wake | 1
|| io_uring/io-wq.c  | io_wq_create | 1
|| io_uring/io-wq.c  | io_task_work_match | 1
|| io_uring/io-wq.c  | io_wq_exit_start | 1
|| io_uring/io-wq.c  | io_wq_exit_workers | 3
|| io_uring/io-wq.c  | io_wq_destroy | 2
|| io_uring/io-wq.c  | io_wq_put_and_exit | 1
|| io_uring/io-wq.c  | io_wq_worker_affinity | 1
|| io_uring/io-wq.c  | __io_wq_cpu_online | 3
|| io_uring/io-wq.c  | io_wq_cpu_online | 1
|| io_uring/io-wq.c  | io_wq_cpu_offline | 1
|| io_uring/io-wq.c  | io_wq_cpu_affinity | 1
|| io_uring/io-wq.c  | io_wq_max_workers | 2
|| io_uring/io-wq.c  | io_wq_init | 1
kbuf.c | kbuf.c | io_buffer_get_list | 10
|| kbuf.c | io_buffer_add_list | 3
|| kbuf.c | io_kbuf_recycle_legacy | 1
|| kbuf.c | __io_put_kbuf | 1
|| kbuf.c | io_provided_buffer_select | 3
|| kbuf.c | io_ring_buffer_select | 2
|| kbuf.c | io_buffer_select | 1
|| kbuf.c | io_ring_buffers_peek | 3
|| kbuf.c | io_buffers_select | 1
|| kbuf.c | io_buffers_peek | 1
|| kbuf.c | __io_remove_buffers | 3
|| kbuf.c | io_put_bl | 4
|| io_uring.c | io_destroy_buffers | 1
|| kbuf.c | io_destroy_bl | 2
|| kbuf.c | io_remove_buffers_prep | 1
|| kbuf.c | io_remove_buffers | 3
|| kbuf.c | io_provide_buffers_prep | 1
|| kbuf.c | io_refill_buffer_cache | 2
|| kbuf.c | io_add_buffers | 2
|| kbuf.c | io_provide_buffers | 1
|| kbuf.c | io_register_pbuf_ring | 1
|| kbuf.c | io_unregister_pbuf_ring | 1
|| kbuf.c | io_register_pbuf_status | 1
|| kbuf.c | io_pbuf_get_region | 1
memmap.c | memmap.c | io_mem_alloc_compound | 2
|| memmap.c | io_pin_pages | 2
|| memmap.c | io_free_region | 3
|| memmap.c | io_region_init_ptr | 2
|| memmap.c | io_region_pin_pages | 2
|| memmap.c | io_region_allocate_pages | 2
|| io_uring.c | io_create_region | 2
|| io_uring/kbuf.c | io_create_region_mmap_safe | 1
|| io_uring/memmap.c | io_region_validate_mmap | 2
|| io_uring/memmap.c | io_uring_validate_mmap_request | 4
|| io_uring/memmap.c | io_region_mmap | 2
|| io_uring/io_uring.c | io_uring_mmap | 2
|| io_uring/io_uring.c | io_uring_get_unmapped_area | 2
|| io_uring/io_uring.c  | io_uring_nommu_mmap_capabilities | 1
|| io_uring/msg_ring.c | io_double_unlock_ctx | 3
||  io_uring/msg_ring.c | io_double_lock_ctx | 3
||  io_uring/msg_ring.c | io_msg_ring_cleanup | 1
||  io_uring/msg_ring.c | io_msg_need_remote | 3
||  io_uring/msg_ring.c | io_msg_tw_complete | 1
||  io_uring/msg_ring.c | io_msg_remote_post | 2
||  io_uring/msg_ring.c | io_msg_get_kiocb | 2
||  io_uring/msg_ring.c | io_msg_data_remote | 2
||  io_uring/msg_ring.c | __io_msg_ring_data | 3
||  io_uring/msg_ring.c | io_msg_ring_data | 2
||  io_uring/msg_ring.c | io_msg_grab_file | 2
||  io_uring/msg_ring.c | io_msg_install_complete | 3
||  io_uring/msg_ring.c | io_msg_tw_fd_complete | 1
||  io_uring/msg_ring.c | io_msg_fd_remote | 2
||  io_uring/msg_ring.c | io_msg_send_fd | 2
||  io_uring/msg_ring.c | __io_msg_ring_prep | 3
||  io_uring/msg_ring.c | io_msg_ring_prep | 1
||  io_uring/msg_ring.c | io_msg_ring | 1
||  io_uring/msg_ring.c | io_uring_sync_msg_ring | 1
napi.c | io_uring/napi.c | net_to_ktime | 3
|| io_uring/napi.c | __io_napi_add_id | 2
|| io_uring/napi.c | __io_napi_del_id | 2
|| io_uring/napi.c | __io_napi_remove_stale | 2
|| io_uring/napi.c | io_napi_remove_stale | 3
|| io_uring/napi.c | io_napi_busy_loop_timeout | 2
|| io_uring/napi.c | io_napi_busy_loop_should_end | 3
|| io_uring/napi.c | static_tracking_do_busy_loop | 2
|| io_uring/napi.c | __io_napi_do_busy_loop | 3
|| io_uring/napi.c | io_napi_blocking_busy_loop | 2
|| io_uring/napi.c | io_napi_init | 2
|| io_uring/io_uring.c | io_napi_free | 3
|| io_uring/napi.c | io_napi_register_napi | 2
|| io_uring/napi.c | io_register_napi | 1
|| io_uring/napi.c | io_unregister_napi | 1
|| io_uring/napi.c | __io_napi_busy_loop | 2 
|| io_uring/napi.c | io_napi_sqpoll_busy_poll | 2 
net.c | net.c | io_shutdown_prep | 1
|| net.c | io_shutdown | 1
|| net.c | io_net_retry | 7
|| net.c | io_netmsg_iovec_free | 5
|| net.c | io_netmsg_recycle | 2
|| net.c | io_msg_alloc_async | 6
|| net.c | io_net_vec_assign | 3
|| net.c | io_mshot_prep_retry | 3
|| net.c | io_compat_msg_copy_hdr | 3
|| net.c | io_msg_copy_hdr | 3
|| net.c | io_sendmsg_copy_hdr | 2
|| net.c | io_sendmsg_recvmsg_cleanup | 1
|| net.c | io_send_setup | 3
|| net.c | io_sendmsg_setup | 3
|| net.c | io_sendmsg_prep | 1
|| net.c | io_req_msg_cleanup | 7
|| net.c | io_bundle_nbufs | 3
|| net.c | io_send_finish | 2
|| net.c | io_sendmsg | 1
|| net.c | io_send_select_buffer | 2
|| net.c | io_send | 1
|| net.c | io_recvmsg_mshot_prep | 3
|| net.c | io_recvmsg_copy_hdr | 2
|| net.c | io_recvmsg_prep_setup | 2
|| net.c | io_recvmsg_prep | 1
|| net.c | io_recv_finish | 3
|| net.c | io_recvmsg_prep_multishot | 2
|| net.c | io_recvmsg_multishot | 2
|| net.c | io_recv_buf_select| 2
|| net.c | io_recv | 1
|| net.c | io_send_zc_cleanup| 3
|| net.c | io_send_zc_prep | 1
|| net.c | io_sg_from_iter_iovec | 1
|| net.c | io_sg_from_iter | 1
|| net.c | io_send_zc_import | 2
|| net.c | io_send_zc | 1
|| net.c | io_sendmsg_zc | 1
|| net.c | io_sendrecv_fail | 1
|| net.c | io_accept_prep | 1
|| net.c | io_accept | 1
|| net.c | io_socket_prep | 1
|| net.c | io_socket | 1
|| net.c | io_connect_prep | 1
|| net.c | io_connect | 1
|| net.c | io_bind_prep | 1
|| net.c | io_bind | 1
|| net.c | io_listen_prep | 1
|| net.c | io_listen | 1
|| io_uring/io_uring.c | io_netmsg_cache_free | 1
|| drivers/infiniband/sw/rxe/rxe_verbs.h | again | 1
|| include/linux/bvec.h | bvec_iter_advance_single | 1
|| include/linux/overflow.h | check_add_overflow | 1
|| include/linux/compat.h | compat_ptr | 2
|| include/linux/uaccess.h | copy_from_user | 3
|| net/socket.c | __copy_msghdr | 1
|| include/linux/uaccess.h | copy_to_user | 1
|| io_uring/net.c | CQE_F_MASK | 1
|| fs/file.c | fd_install | 2
nop.c | cancel.c | io_file_get_fixed | 1
|| cancel.c | io_file_get_normal | 1
|| advise.c | io_kiocb_to_cmd | 2
|| nop.c | io_nop | 1
|| nop.c | io_nop_prep | 1
|| net.c | io_req_assign_buf_node | 1
|| advise.c | io_req_set_res | 1
|| cancel.c | io_ring_submit_lock | 1
|| cancel.c | io_ring_submit_unlock | 1
|| cancel.c | io_rsrc_node_lookup | 1
|| nop.c | NOP_FLAGS | 1
|| advise.c | READ_ONCE | 4
|| advise.c | req_set_fail | 1
notif.c | msg_ring.c | cmd_to_io_kiocb | 4
|| cancel.c | container_of | 3
|| net.c | io_alloc_notif | 1
|| io_uring.c | io_alloc_req | 1
|| io_uring.c | io_get_task_refs | 1
|| notif.c | io_link_skb | 1
|| net.c | io_notif_to_data | 2
|| notif.c | io_notif_tw_complete | 1
|| futex.c | io_req_task_complete | 1
|| io_uring.c | __io_req_task_work_add | 1
|| notif.c | io_tx_ubuf_complete | 2
|| memmap.c | __io_unaccount_mem | 1
|| io_uring.c | lockdep_assert | 1
|| cancel.c | __must_hold | 1
|| notif.c | net_zcopy_get | 2
|| eventfd.c | refcount_dec_and_test | 1
|| notif.c | refcount_read | 1
|| eventfd.c | refcount_set | 1
|| notif.c | skb_zcopy | 1
|| notif.c | skb_zcopy_init | 1
|| cancel.c | unlikely | 6
|| io_uring.c | WRITE_ONCE | 2
opdef.c | cancel.c | ARRAY_SIZE | 3
|| io_uring.c | BUG_ON | 2
|| io-wq.c | BUILD_BUG_ON | 2
|| advise.c | defined | 22
|| opdef.c | io_eopnotsupp_prep | 1
|| opdef.c | io_no_issue | 1
|| fdinfo.c | io_uring_get_opcode | 1
|| opdef.c | io_uring_op_supported | 1
|| io_uring.c | io_uring_optable_init | 1
|| io_uring.c | prep | 1
|| advise.c | WARN_ON_ONCE | 2
openclose.c | openclose.c | build_open_flags | 1
|| openclose.c | build_open_how | 1
|| openclose.c | copy_struct_from_user | 1
|| openclose.c | do_filp_open | 1
|| io_uring.c | fd_install | 1
|| openclose.c | file_close_fd_locked | 1
|| openclose.c | files_lookup_fd_locked | 1
|| openclose.c | filp_close | 1
|| io_uring.c | flush | 1
|| openclose.c | force_o_largefile | 1
|| fs.c | getname | 1
|| net.c | __get_unused_fd_flags | 1
|| opdef.c | io_close | 1
|| openclose.c | __io_close_fixed | 2
|| openclose.c | io_close_fixed | 2
|| opdef.c | io_close_prep | 1
|| filetable.c | io_fixed_fd_install | 1
|| filetable.c | io_fixed_fd_remove | 1
|| opdef.c | io_install_fixed_fd | 1
|| opdef.c | io_install_fixed_fd_prep | 1
|| filetable.c | io_is_uring_fops | 1
|| advise.c | io_kiocb_to_cmd | 10
|| opdef.c | io_openat | 1
|| opdef.c | io_openat2 | 2
|| opdef.c | io_openat2_prep | 1
|| openclose.c | io_openat_force_async | 3
|| openclose.c | __io_openat_prep | 3
|| opdef.c | io_openat_prep | 1
|| opdef.c | io_open_cleanup | 1
|| advise.c | io_req_set_res | 3
|| cancel.c | io_ring_submit_lock | 1
|| cancel.c | io_ring_submit_unlock | 1
|| eventfd.c | IS_ERR | 2
|| eventfd.c | PTR_ERR | 2
|| fs.c | putname | 2
|| net.c | put_unused_fd | 1
|| advise.c | READ_ONCE | 10
|| openclose.c | receive_fd | 1
|| advise.c | req_set_fail | 3
|| net.c | rlimit | 1
|| cancel.c | spin_lock | 1
|| cancel.c | spin_unlock | 3
|| epoll.c | u64_to_user_ptr | 2
|| cancel.c | unlikely | 2
|| advise.c | WARN_ON_ONCE | 1
poll.c | poll.c | add_wait_queue | 1
|| poll.c | add_wait_queue_exclusive | 1
|| poll.c | aio_poll_complete_work | 1
|| io_uring.c | atomic_andnot | 1
|| poll.c | atomic_cmpxchg | 1
|| poll.c | atomic_fetch_inc | 2
|| eventfd.c | atomic_fetch_or | 1
|| io-wq.c | atomic_or | 1
|| io-wq.c | atomic_read | 2
|| eventfd.c | atomic_set | 1
|| poll.c | atomic_sub_return | 1
|| eventfd.c | BIT | 2
|| cancel.c | container_of | 3
|| poll.c | demangle_poll | 1
|| poll.c | GENMASK | 1
|| poll.c | hash_del | 2
|| poll.c | hash_long | 2
|| futex.c | hlist_add_head | 1
|| futex.c | hlist_del_init | 1
|| fdinfo.c | hlist_for_each_entry | 2
|| futex.c | hlist_for_each_entry_safe | 1
|| poll.c | INIT_HLIST_NODE | 1
|| io-wq.c | INIT_LIST_HEAD | 1
|| io_uring.c | init_waitqueue_func_entry | 1
|| poll.c | __io_arm_poll_handler | 3
|| io_uring.c | io_arm_poll_handler | 1
|| poll.c | IO_ASYNC_POLL_COMMON | 1
|| poll.c | io_async_queue_proc | 1
|| alloc_cache.h | io_cache_alloc | 1
|| cancel.c | io_cancel_match_sequence | 1
|| cancel.c | io_cancel_req_match | 1
|| io_uring.c | io_file_can_poll | 1
|| poll.c | io_init_poll_iocb | 3
|| io_uring.c | io_kbuf_recycle | 3
|| advise.c | io_kiocb_to_cmd | 8
|| futex.c | io_match_task_safe | 1
|| napi.h | io_napi_add | 2
|| opdef.c | io_poll_add | 2
|| poll.c | io_poll_add_hash | 3
|| opdef.c | io_poll_add_prep | 1
|| poll.c | __io_poll_cancel | 2
|| cancel.c | io_poll_cancel | 1
|| poll.c | io_poll_cancel_req | 3
|| poll.c | io_poll_can_finish_inline | 5
|| poll.c | io_poll_check_events | 2
|| poll.c | io_poll_disarm | 2
|| poll.c | io_poll_double_prepare | 2
|| poll.c | __io_poll_execute | 6
|| poll.c | io_poll_execute | 3
|| poll.c | io_poll_file_find | 2
|| poll.c | io_poll_find | 3
|| poll.c | io_pollfree_wake | 2
|| poll.c | io_poll_get_double | 2
|| poll.c | io_poll_get_ownership | 5
|| poll.c | io_poll_get_ownership_slowpath | 2
|| poll.c | io_poll_get_single | 3
|| io_uring.c | io_poll_issue | 1
|| poll.c | io_poll_mark_cancelled | 4
|| poll.c | io_poll_parse_events | 3
|| poll.c | io_poll_queue_proc | 1
|| opdef.c | io_poll_remove | 1
|| io_uring.c | io_poll_remove_all | 1
|| poll.c | io_poll_remove_entries | 6
|| poll.c | io_poll_remove_entry | 3
|| opdef.c | io_poll_remove_prep | 1
|| poll.c | io_poll_req_insert | 2
|| io_uring.c | io_poll_task_func | 1
|| poll.c | IO_POLL_UNMASK | 1
|| poll.c | io_poll_wake | 4
|| poll.c | __io_queue_proc | 3
|| poll.c | io_req_alloc_apoll | 2
|| io_uring.c | io_req_defer_failed | 1
|| io_uring.c | io_req_post_cqe | 1
|| advise.c | io_req_set_res | 6
|| futex.c | io_req_task_complete | 2
|| io_uring.c | io_req_task_submit | 2
|| io_uring.c | __io_req_task_work_add | 1
|| futex.c | io_req_task_work_add | 1
|| cancel.c | io_ring_submit_lock | 3
|| cancel.c | io_ring_submit_unlock | 3
|| io_uring.c | io_should_terminate_tw | 1
|| futex.c | io_tw_lock | 1
|| poll.c | key_to_poll | 1
|| alloc_cache.h | kfree | 2
|| alloc_cache.c | kmalloc | 2
|| io-wq.c | list_del_init | 3
|| futex.c | lockdep_assert_held | 2
|| poll.c | mangle_poll | 2
|| poll.c | poll_refs | 1
|| eventfd.c | rcu_read_lock | 4
|| eventfd.c | rcu_read_unlock | 2
|| advise.c | READ_ONCE | 5
|| advise.c | req_set_fail | 4
|| io_uring.c | smp_load_acquire | 2
|| io_uring.c | smp_store_release | 1
|| io-wq.c | spin_lock_irq | 2
|| io-wq.c | spin_unlock_irq | 2
|| poll.c | swahw32 | 1
|| poll.c | trace_io_uring_poll_arm | 1
|| poll.c | trace_io_uring_task_add | 1
|| cancel.c | unlikely | 9
|| poll.c | vfs_poll | 5
|| cancel.c | wait | 1
|| poll.c | wake_up_pollfree | 2
|| advise.c | WARN_ON_ONCE | 2
|| poll.c | wqe_is_double | 2
|| poll.c | wqe_to_req | 2
register.c | io-wq.c | __acquires | 1
|| io-wq.c | alloc_cpumask_var | 1
|| io_uring.c | array_index_nospec | 2
|| io_uring.c | array_size | 3
|| cancel.c | ARRAY_SIZE | 3
|| io-wq.c | atomic_read | 1
|| eventfd.c | atomic_set | 1
|| io-wq.c | BUILD_BUG_ON | 1
|| register.c | compat_get_bitmap | 1
|| register.c | COPY_FLAGS | 1
|| cancel.c | copy_from_user | 8
|| io-wq.c | Copyright | 1
|| io_uring.c | copy_to_user | 5
|| register.c | cpumask_bits | 1
|| register.c | cpumask_clear | 1
|| register.c | cpumask_size | 2
|| io-wq.c | ERR_PTR | 3
|| cancel.c | fget | 1
|| cancel.c | fput | 3
|| io-wq.c | free_cpumask_var | 2
|| io_uring.c | get_current_cred | 1
|| msg_ring.c | get_file | 1
|| io-wq.c | get_task_struct | 1
|| io_uring.c | in_compat_syscall | 1
|| io_uring.c | io_activate_pollwq | 1
|| kbuf.c | io_create_region_mmap_safe | 3
|| eventfd.c | io_eventfd_register | 2
|| eventfd.c | io_eventfd_unregister | 1
|| io_uring.c | io_free_region | 3
|| filetable.c | io_is_uring_fops | 1
|| register.c | io_parse_restrictions | 2
|| register.c | io_probe | 2
|| register.c | io_put_sq_data | 2
|| io_uring.c | io_region_get_ptr | 3
|| memmap.c | io_region_is_set | 1
|| register.c | io_register_clock | 2
|| register.c | io_register_clone_buffers | 1
|| register.c | io_register_enable_rings | 2
|| filetable.c | io_register_file_alloc_range | 1
|| register.c | io_register_files_update | 1
|| register.c | io_register_free_rings | 6
|| register.c | __io_register_iowq_aff | 3
|| register.c | io_register_iowq_aff | 2
|| register.c | io_register_iowq_max_workers | 2
|| register.c | io_register_mem_region | 2
|| napi.c | io_register_napi | 1
|| kbuf.c | io_register_pbuf_ring | 1
|| kbuf.c | io_register_pbuf_status | 1
|| register.c | io_register_personality | 2
|| register.c | io_register_resize_rings | 2
|| register.c | io_register_restrictions | 2
|| register.c | io_register_rsrc | 2
|| register.c | io_register_rsrc_update | 2
rsrc.c | io_uring.c | array_index_nospec | 1
|| rsrc.c | atomic64_add | 1
|| rsrc.c | atomic64_sub | 1
|| rsrc.c | atomic_long_read | 1
|| rsrc.c | atomic_long_try_cmpxchg | 1
|| io-wq.c | BUILD_BUG_ON | 1
|| io_uring.c | bvec | 1
|| rsrc.c | bvec_set_page | 1
|| filetable.c | check_add_overflow | 5
|| rsrc.c | compound_head | 4
|| cancel.c | copy_from_user | 11
|| io_uring.c | copy_to_user | 1
|| io-wq.c | ERR_PTR | 2
|| cancel.c | fget | 3
|| rsrc.c | folio_nr_pages | 1
|| rsrc.c | folio_page_idx | 2
|| rsrc.c | folio_shift | 1
|| rsrc.c | folio_size | 1
|| cancel.c | fput | 6
|| rsrc.c | headpage_already_acct | 2
|| memmap.c | __io_account_mem | 2
|| rsrc.c | io_account_mem | 2
|| filetable.c | io_alloc_file_tables | 1
|| rsrc.c | io_buffer_account_pin | 2
|| rsrc.c | io_buffer_unmap | 3
|| rsrc.c | io_buffer_validate | 3
|| memmap.c | io_check_coalesce_buffer | 2
|| rsrc.c | io_clone_buffers | 2
|| openclose.c | __io_close_fixed | 1
|| rsrc.c | io_coalesce_buffer | 2
|| filetable.c | io_file_bitmap_clear | 1
|| filetable.c | io_file_bitmap_set | 2
|| opdef.c | io_files_update | 1
|| opdef.c | io_files_update_prep | 1
|| rsrc.c | io_files_update_with_index_alloc | 2
|| filetable.c | io_file_table_set_alloc_range | 2
|| filetable.c | io_fixed_fd_install | 1
|| filetable.c | io_fixed_file_set | 2
|| filetable.c | io_free_file_tables | 1
|| rsrc.c | io_free_rsrc_node | 1
|| net.c | io_import_fixed | 1
|| filetable.c | io_is_uring_fops | 2
|| advise.c | io_kiocb_to_cmd | 3
|| memmap.c | io_pin_pages | 1
|| io_uring.c | io_post_aux_cqe | 1
|| rsrc.c | io_put_rsrc_node | 2
|| register.c | io_register_clone_buffers | 1
|| register.c | io_register_files_update | 1
|| register.c | io_register_rsrc | 1
|| rsrc.c | __io_register_rsrc_update | 4
|| register.c | io_register_rsrc_update | 1
|| advise.c | io_req_set_res | 1
|| filetable.c | io_reset_rsrc_node | 2
|| rsrc.c | IORING_MAX_FIXED_FILES | 1
rw.c | kbuf.c | access_ok | 1
|| rw.c | blkdev_write_iter | 1
|| msg_ring.c | cmd_to_io_kiocb | 2
|| io-wq.c | complete | 1
|| cancel.c | container_of | 5
|| cancel.c | copy_from_user | 2
|| rw.c | DEFINE_IO_COMP_BATCH | 1
|| io_uring.c | destroy_hrtimer_on_stack | 1
|| rw.c | dio_complete | 1
|| io_uring.c | file_inode | 3
|| rw.c | __folio_lock_async | 1
|| rw.c | fsnotify_access | 1
|| rw.c | fsnotify_modify | 1
|| rw.c | get_current_ioprio | 1
|| net.c | __get_user | 1
|| io_uring.c | hrtimer_cancel | 1
|| io_uring.c | hrtimer_set_expires | 1
|| rw.c | hrtimer_setup_sleeper_on_stack | 1
|| rw.c | hrtimer_sleeper_start_expires | 1
|| net.c | __import_iovec | 1
|| net.c | import_ubuf | 2
|| io-wq.c | INIT_LIST_HEAD | 1
|| alloc_cache.h | io_alloc_cache_kasan | 1
|| alloc_cache.h | io_alloc_cache_put | 1
|| rw.c | io_async_buf_func | 1
|| kbuf.c | io_buffer_select | 1
|| rw.c | io_complete_rw | 4
|| rw.c | __io_complete_rw_common | 3
|| rw.c | io_complete_rw_iopoll | 4
|| kbuf.h | io_do_buffer_select | 3
|| io_uring.c | io_do_iopoll | 1
|| io_uring.c | io_file_can_poll | 4
|| filetable.h | io_file_get_flags | 1
|| rw.c | io_file_supports_nowait | 3
|| rw.c | io_fixup_rw_res | 5
|| rw.c | io_hybrid_iopoll_delay | 2
|| net.c | io_import_fixed | 1
|| rw.c | __io_import_iovec | 2
|| rw.c | io_import_iovec | 3
|| rw.c | io_iopoll_complete | 1
|| rw.c | io_iov_buffer_select_prep | 2
|| rw.c | io_iov_compat_buffer_select_prep | 2
|| rw.c | io_iter_do_read | 3
|| io_uring.c | io_kbuf_recycle | 2
|| rw.c | io_kiocb_ppos | 2
|| rw.c | io_kiocb_start_write | 2
|| advise.c | io_kiocb_to_cmd | 20
|| rw.c | io_kiocb_update_pos | 3
|| rw.c | io_meta_restore | 4
|| rw.c | io_meta_save_state | 2
|| io_uring.c | iopoll | 1
|| poll.h | io_poll_multishot_retry | 1
|| opdef.c | io_prep_read | 1
|| opdef.c | io_prep_read_fixed | 1
|| opdef.c | io_prep_readv | 1
|| rw.c | io_prep_rw | 6
|| rw.c | io_prep_rw_fixed | 3
|| rw.c | io_prep_rw_pi | 2
|| rw.c | io_prep_rw_setup | 2
|| rw.c | io_prep_rwv | 3
|| opdef.c | io_prep_write | 1
|| opdef.c | io_prep_write_fixed | 1
|| opdef.c | io_prep_writev | 1
|| rw.c | ioprio_check_cap | 1
|| io_uring.c | io_put_kbuf | 5
|| rw.c | __io_read | 3
|| opdef.c | io_read | 2
|| opdef.c | io_read_mshot | 1
|| opdef.c | io_read_mshot_prep | 1
|| opdef.c | io_readv_writev_cleanup | 1
|| net.c | io_req_assign_buf_node | 1
|| rw.c | io_req_end_write | 5
|| rw.c | io_req_io_end | 3
|| io_uring.c | io_req_post_cqe | 1
|| rw.c | io_req_rw_cleanup | 5
|| io_uring.c | io_req_rw_complete | 1
|| advise.c | io_req_set_res | 5
|| futex.c | io_req_task_complete | 1
|| io_uring.c | io_req_task_queue | 1
|| io_uring.c | __io_req_task_work_add | 1
|| cancel.c | io_rsrc_node_lookup | 1
|| rw.c | io_rw_alloc_async | 2
|| io_uring.c | io_rw_cache_free | 1
|| rw.c | io_rw_done | 2
|| opdef.c | io_rw_fail | 1
|| rw.c | io_rw_init_file | 3
|| rw.c | io_rw_recycle | 3
|| rw.c | io_rw_should_reissue | 3
|| rw.c | io_rw_should_retry | 2
|| rw.c | io_schedule | 1
|| io_uring.c | __io_submit_flush_completions | 1
|| io_uring.h | io_uring_alloc_async_data | 1
|| rw.c | io_uring_classic_poll | 3
|| rw.c | io_uring_hybrid_poll | 2
|| rsrc.c | iov_iter_advance | 2
|| net.c | iov_iter_count | 7
rw.c | kbuf.c | access_ok | 1
|| rw.c | blkdev_write_iter | 1
|| msg_ring.c | cmd_to_io_kiocb | 2
|| io-wq.c | complete | 1
|| cancel.c | container_of | 5
|| cancel.c | copy_from_user | 2
|| rw.c | DEFINE_IO_COMP_BATCH | 1
|| io_uring.c | destroy_hrtimer_on_stack | 1
|| rw.c | dio_complete | 1
|| io_uring.c | file_inode | 3
|| rw.c | __folio_lock_async | 1
|| rw.c | fsnotify_access | 1
|| rw.c | fsnotify_modify | 1
|| rw.c | get_current_ioprio | 1
|| net.c | __get_user | 1
|| io_uring.c | hrtimer_cancel | 1
|| io_uring.c | hrtimer_set_expires | 1
|| rw.c | hrtimer_setup_sleeper_on_stack | 1
|| rw.c | hrtimer_sleeper_start_expires | 1
|| net.c | __import_iovec | 1
|| net.c | import_ubuf | 2
|| io-wq.c | INIT_LIST_HEAD | 1
|| alloc_cache.h | io_alloc_cache_kasan | 1
|| alloc_cache.h | io_alloc_cache_put | 1
|| rw.c | io_async_buf_func | 1
|| kbuf.c | io_buffer_select | 1
|| rw.c | io_complete_rw | 4
|| rw.c | __io_complete_rw_common | 3
|| rw.c | io_complete_rw_iopoll | 4
|| kbuf.h | io_do_buffer_select | 3
|| io_uring.c | io_do_iopoll | 1
|| io_uring.c | io_file_can_poll | 4
|| filetable.h | io_file_get_flags | 1
|| rw.c | io_file_supports_nowait | 3
|| rw.c | io_fixup_rw_res | 5
|| rw.c | io_hybrid_iopoll_delay | 2
|| net.c | io_import_fixed | 1
|| rw.c | __io_import_iovec | 2
|| rw.c | io_import_iovec | 3
|| rw.c | io_iopoll_complete | 1
|| rw.c | io_iov_buffer_select_prep | 2
|| rw.c | io_iov_compat_buffer_select_prep | 2
|| rw.c | io_iter_do_read | 3
|| io_uring.c | io_kbuf_recycle | 2
|| rw.c | io_kiocb_ppos | 2
|| rw.c | io_kiocb_start_write | 2
|| advise.c | io_kiocb_to_cmd | 20
|| rw.c | io_kiocb_update_pos | 3
|| rw.c | io_meta_restore | 4
|| rw.c | io_meta_save_state | 2
|| io_uring.c | iopoll | 1
|| poll.h | io_poll_multishot_retry | 1
|| opdef.c | io_prep_read | 1
|| opdef.c | io_prep_read_fixed | 1
|| opdef.c | io_prep_readv | 1
|| rw.c | io_prep_rw | 6
|| rw.c | io_prep_rw_fixed | 3
|| rw.c | io_prep_rw_pi | 2
|| rw.c | io_prep_rw_setup | 2
|| rw.c | io_prep_rwv | 3
|| opdef.c | io_prep_write | 1
|| opdef.c | io_prep_write_fixed | 1
|| opdef.c | io_prep_writev | 1
|| rw.c | ioprio_check_cap | 1
|| io_uring.c | io_put_kbuf | 5
|| rw.c | __io_read | 3
|| opdef.c | io_read | 2
|| opdef.c | io_read_mshot | 1
|| opdef.c | io_read_mshot_prep | 1
|| opdef.c | io_readv_writev_cleanup | 1
|| net.c | io_req_assign_buf_node | 1
|| rw.c | io_req_end_write | 5
|| rw.c | io_req_io_end | 3
|| io_uring.c | io_req_post_cqe | 1
|| rw.c | io_req_rw_cleanup | 5
|| io_uring.c | io_req_rw_complete | 1
|| advise.c | io_req_set_res | 5
|| futex.c | io_req_task_complete | 1
|| io_uring.c | io_req_task_queue | 1
|| io_uring.c | __io_req_task_work_add | 1
|| cancel.c | io_rsrc_node_lookup | 1
|| rw.c | io_rw_alloc_async | 2
|| io_uring.c | io_rw_cache_free | 1
|| rw.c | io_rw_done | 2
|| opdef.c | io_rw_fail | 1
|| rw.c | io_rw_init_file | 3
|| rw.c | io_rw_recycle | 3
|| rw.c | io_rw_should_reissue | 3
|| rw.c | io_rw_should_retry | 2
|| rw.c | io_schedule | 1
|| io_uring.c | __io_submit_flush_completions | 1
|| io_uring.h | io_uring_alloc_async_data | 1
|| rw.c | io_uring_classic_poll | 3
|| rw.c | io_uring_hybrid_poll | 2
|| rsrc.c | iov_iter_advance | 2
|| net.c | iov_iter_count | 7
spoll.c | io-wq.c | __acquires | 1
|| io-wq.c | alloc_cpumask_var | 1
|| io_uring.c | atomic_andnot | 1
|| spoll.c | atomic_dec_return | 1
|| io-wq.c | atomic_inc | 1
|| io-wq.c | atomic_or | 2
|| io-wq.c | atomic_read | 2
|| eventfd.c | atomic_set | 1
|| io_uring.c | audit_uring_entry | 1
|| io_uring.c | audit_uring_exit | 1
|| msg_ring.c | CLASS | 2
|| io-wq.c | clear_bit | 2
|| io-wq.c | complete | 2
|| io-wq.c | cond_resched | 1
|| spoll.c | cpumask_of | 1
|| io-wq.c | cpumask_test_cpu | 1
|| spoll.c | cpu_online | 1
|| io-wq.c | cpuset_cpus_allowed | 1
|| io-wq.c | create_io_thread | 1
|| io_uring.c | current_cred | 1
|| spoll.c | data_race | 1
|| cancel.c | DEFINE_WAIT | 2
|| io-wq.c | do_exit | 1
|| io-wq.c | ERR_PTR | 5
|| msg_ring.c | fd_empty | 2
|| msg_ring.c | fd_file | 3
|| cancel.c | finish_wait | 2
|| io-wq.c | free_cpumask_var | 2
|| io_uring.c | get_current_cred | 1
|| fdinfo.c | getrusage | 2
|| io-wq.c | get_signal | 1
|| io-wq.c | get_task_struct | 1
|| io-wq.c | init_completion | 1
|| io-wq.c | INIT_LIST_HEAD | 1
|| io_uring.c | init_waitqueue_head | 1
|| spoll.c | io_attach_sq_data | 2
|| io_uring.c | io_do_iopoll | 1
|| spoll.c | io_get_sq_data | 2
|| io_uring.c | io_handle_tw_list | 1
|| filetable.c | io_is_uring_fops | 2
|| napi.h | io_napi | 1
|| napi.c | io_napi_sqpoll_busy_poll | 1
|| register.c | io_put_sq_data | 2
|| io_uring.c | io_ring_exit_work | 1
|| io-wq.c | io_run_task_work | 1
|| spoll.c | io_sqd_events_pending | 3
|| spoll.c | io_sqd_handle_event | 2
|| spoll.c | io_sqd_update_thread_idle | 3
|| io_uring.c | io_sq_offload_create | 1
statx.c | statx.c | do_statx | 1
|| fs.c | getname_uflags | 1
|| advise.c | io_kiocb_to_cmd | 3
|| advise.c | io_req_set_res | 1
|| opdef.c | io_statx | 1
|| opdef.c | io_statx_cleanup | 1
|| opdef.c | io_statx_prep | 1
|| eventfd.c | IS_ERR | 1
|| eventfd.c | PTR_ERR | 1
|| fs.c | putname | 1
|| advise.c | READ_ONCE | 5
|| epoll.c | u64_to_user_ptr | 2
|| advise.c | WARN_ON_ONCE | 1
sync.c | rw.c | fsnotify_modify | 1
|| opdef.c | io_fallocate | 1
|| opdef.c | io_fallocate_prep | 1
|| opdef.c | io_fsync | 1
|| opdef.c | sync.c | 1
|| advise.c | io_kiocb_to_cmd | 6
|| advise.c | io_req_set_res | 3
|| opdef.c | io_sfr_prep | 1
|| opdef.c | io_sync_file_range | 1
|| advise.c | READ_ONCE | 9
|| sync.c | sync_file_range | 1
|| cancel.c | unlikely | 3
|| sync.c | vfs_fallocate | 1
|| sync.c | vfs_fsync_range | 1
|| advise.c | WARN_ON_ONCE | 3
tctx.c | io_uring.c | array_index_nospec | 2
|| eventfd.c | atomic_set | 2
|| io-wq.c | cond_resched | 1
|| cancel.c | copy_from_user | 2
|| io_uring.c | copy_to_user | 1
|| io-wq.c | ERR_PTR | 1
|| cancel.c | fget | 1
|| cancel.c | fput | 5
|| io_uring.c | init_llist_head | 1
|| io-wq.c | init_task_work | 1
|| io_uring.c | init_waitqueue_head | 2
|| tctx.c | io_init_wq_offload | 2
|| filetable.c | io_is_uring_fops | 1
|| tctx.c | io_ring_add_registered_fd | 2
|| io_uring.c | io_ring_add_registered_file | 2
|| register.c | io_ringfd_register | 1
|| register.c | io_ringfd_unregister | 1
|| io_uring.c | __io_uring_add_tctx_node | 3
|| tctx.c | __io_uring_add_tctx_node_from_submit | 1
|| io_uring.h | io_uring_alloc_task_context | 2
|| io_uring.c | io_uring_clean_tctx | 1
|| io_uring.c | io_uring_del_tctx_node | 3
|| io_uring.c | io_uring_enter | 1
|| io_uring.c | __io_uring_free | 1
|| io_uring.c | io_uring_try_cancel_iowq | 1
|| io_uring.c | io_uring_unreg_ringfd | 1
|| io-wq.c | io_wq_create | 1
|| io-wq.c | io_wq_max_workers | 1
|| io-wq.c | io_wq_put_and_exit | 1
|| eventfd.c | IS_ERR | 1
|| alloc_cache.h | kfree | 5
|| alloc_cache.c | kmalloc | 1
|| io-wq.c | kzalloc | 2
|| kbuf.c | list_add | 1
|| io_uring.c | list_del | 1
|| io-wq.c | list_empty | 1
|| fdinfo.c | min | 1
|| cancel.c | mutex_lock | 4
|| cancel.c | mutex_unlock | 5
|| tctx.c | num_online_cpus | 1
|| tctx.c | percpu_counter_destroy | 2
|| tctx.c | percpu_counter_init | 1
timeout.c | io-wq.c | atomic_read | 4
|| eventfd.c | atomic_set | 2
|| msg_ring.c | cmd_to_io_kiocb | 6
|| cancel.c | container_of | 2
|| sqpoll.c | data_race | 1
|| io-wq.c | ERR_PTR | 2
|| io_uring.c | get_timespec64 | 2
|| timeout.c | hrtimer_init | 3
|| timeout.c | hrtimer_start | 5
|| timeout.c | hrtimer_try_to_cancel | 4
|| timeout.c | hweight32 | 2
|| io-wq.c | INIT_LIST_HEAD | 1
|| cancel.c | io_cancel_req_match | 1
|| timeout.c | __io_disarm_linked_timeout | 1
|| timeout.c | io_disarm_linked_timeout | 1
|| io_uring.c | io_disarm_next | 1
|| timeout.c | io_fail_links | 2
|| timeout.c | io_flush_killed_timeouts | 3
|| io_uring.c | io_flush_timeouts | 2
|| io_uring.c | io_for_each_link | 1
|| io_uring.c | io_free_req | 1
|| timeout.c | io_is_timeout_noseq | 4
|| timeout.c | io_kill_timeout | 3
|| io_uring.c | io_kill_timeouts | 1
|| advise.c | io_kiocb_to_cmd | 14
|| timeout.c | io_linked_timeout_update | 2
|| timeout.c | io_link_timeout_fn | 1
|| opdef.c | io_link_timeout_prep | 1
|| io_uring.c | io_match_task | 3
|| timeout.c | io_put_req | 3
|| io_uring.c | io_queue_linked_timeout | 1
|| io_uring.c | io_queue_next | 1
|| timeout.c | io_remove_next_linked | 4
|| io_uring.c | io_req_post_cqe | 1
truncate.c | truncate.c | do_ftruncate | 1
|| opdef.c | io_ftruncate | 1
|| opdef.c | io_ftruncate_prep | 1
|| advise.c | io_kiocb_to_cmd | 2
|| advise.c | io_req_set_res | 1
|| advise.c | READ_ONCE | 1
|| advise.c | WARN_ON_ONCE | 1
uring_cmd.c | msg_ring.c | cmd_to_io_kiocb | 6
|| advise.c | defined | 1
|| uring_cmd.c | do_sock_getsockopt | 1
|| uring_cmd.c | do_sock_setsockopt | 1
|| uring_cmd.c | EXPORT_SYMBOL_GPL | 5
|| futex.c | hlist_add_head | 1
|| uring_cmd.c | hlist_del | 1
|| futex.c | hlist_for_each_entry_safe | 1
|| alloc_cache.h | io_alloc_cache_put | 1
|| uring_cmd.c | ioctl | 2
|| net.c | io_import_fixed | 1
|| io_uring.c | io_iopoll_req_issued | 1
|| advise.c | io_kiocb_to_cmd | 6
|| net.c | io_req_assign_buf_node | 1
|| io_uring.c | io_req_complete_defer | 1
|| io_uring.c | io_req_queue_iowq | 1
|| uring_cmd.c | io_req_set_cqe32_extra | 2
|| advise.c | io_req_set_res | 2
|| io_uring.c | __io_req_task_work_add | 1
|| futex.c | io_req_task_work_add | 1
|| uring_cmd.c | io_req_uring_cleanup | 3
|| cancel.c | io_ring_submit_lock | 2
|| cancel.c | io_ring_submit_unlock | 2
|| cancel.c | io_rsrc_node_lookup | 1
|| io_uring.c | io_should_terminate_tw | 1
|| io_uring.c | io_submit_flush_completions | 1
|| io_uring.h | io_uring_alloc_async_data | 1
|| opdef.c | io_uring_cmd | 1
|| uring_cmd.c | io_uring_cmd_del_cancelable | 2
|| uring_cmd.c | __io_uring_cmd_do_in_task | 1
|| uring_cmd.c | io_uring_cmd_done | 1
|| uring_cmd.c | io_uring_cmd_getsockopt | 2
|| uring_cmd.c | io_uring_cmd_import_fixed | 2
|| uring_cmd.c | io_uring_cmd_issue_blocking | 1
|| uring_cmd.c | io_uring_cmd_mark_cancelable | 1
|| opdef.c | io_uring_cmd_prep | 1
|| uring_cmd.c | io_uring_cmd_prep_setup | 2
|| uring_cmd.c | io_uring_cmd_setsockopt | 2
|| uring_cmd.c | io_uring_cmd_sock | 1
|| uring_cmd.c | io_uring_cmd_work | 1
|| io_uring.c | io_uring_try_cancel_uring_cmd | 2
|| uring_cmd.c | KERNEL_SOCKPTR | 1
|| alloc_cache.h | kfree | 1
|| futex.c | lockdep_assert_held | 1
waitid.c | poll.c | add_wait_queue | 2
|| poll.c | atomic_fetch_inc | 2
|| io-wq.c | atomic_or | 1
|| io-wq.c | atomic_read | 2
|| eventfd.c | atomic_set | 1
|| poll.c | atomic_sub_return | 1
|| eventfd.c | BIT | 1
|| cancel.c | container_of | 2
|| waitid.c | __do_wait | 3
|| poll.c | GENMASK | 1
|| futex.c | hlist_add_head | 1
|| futex.c | hlist_del_init | 3
|| futex.c | hlist_for_each_entry_safe | 2
|| io_uring.c | init_waitqueue_func_entry | 1
|| advise.c | io_kiocb_to_cmd | 8
|| futex.c | io_match_task_safe | 1
|| io_uring.h | io_req_queue_tw_complete | 1
|| advise.c | io_req_set_res | 2
|| futex.c | io_req_task_complete | 1
|| futex.c | io_req_task_work_add | 2
|| cancel.c | io_ring_submit_lock | 2
|| cancel.c | io_ring_submit_unlock | 4
|| futex.c | io_tw_lock | 1
|| io_uring.h | io_uring_alloc_async_data | 1
|| opdef.c | io_waitid | 1
|| waitid.c | __io_waitid_cancel | 3
|| cancel.c | io_waitid_cancel | 1
|| waitid.c | io_waitid_cb | 2
|| waitid.c | io_waitid_compat_copy_si | 2
|| waitid.c | io_waitid_complete | 3
|| waitid.c | io_waitid_copy_si | 2
|| waitid.c | io_waitid_drop_issue_ref | 3
|| waitid.c | io_waitid_finish | 3
|| waitid.c | io_waitid_free | 2
|| opdef.c | io_waitid_prep | 1
|| io_uring.c | io_waitid_remove_all | 1
xattr.c | xattr.c | file_getxattr | 1
|| xattr.c | filename_getxattr | 1
|| xattr.c | filename_setxattr | 1
|| xattr.c | file_setxattr | 1
|| fs.c | getname | 2
|| xattr.c | import_xattr_name | 1
|| opdef.c | io_fgetxattr | 1
|| opdef.c | io_fgetxattr_prep | 1
|| opdef.c | io_fsetxattr | 1
|| opdef.c | io_fsetxattr_prep | 1
|| opdef.c | io_getxattr | 1
|| xattr.c | __io_getxattr_prep | 3
|| opdef.c | io_getxattr_prep | 1
|| advise.c | io_kiocb_to_cmd | 9
|| advise.c | io_req_set_res | 1
|| opdef.c | io_setxattr | 1
|| xattr.c | __io_setxattr_prep | 3
|| opdef.c | io_setxattr_prep | 1
|| opdef.c | io_xattr_cleanup | 2
|| xattr.c | io_xattr_finish | 5
|| eventfd.c | IS_ERR | 2
|| alloc_cache.h | kfree | 3
|| alloc_cache.c | kmalloc | 2
|| alloc_cache.c | kvfree | 1
|| eventfd.c | PTR_ERR | 2
|| fs.c | putname | 1
|| advise.c | READ_ONCE | 10
|| xattr.c | setxattr_copy | 1
|| epoll.c | u64_to_user_ptr | 6
|| cancel.c | unlikely | 2
|| advise.c | WARN_ON_ONCE | 4

# Header .h
Source | Libary | Function utilized | Time Used
-------|--------|--------------| ------------------
alloc_cache.h | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | arch/x86/include/asm/string_64.h| memset | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | linux/mm/slub.c | kfree | 1
| advise.h      | advise.c                             | io_fadvise                    | 1          |
|               |                                      | io_fadvise_prep              | 1          |
|               |                                      | io_madvise                   | 1          |
|               |                                      | io_madvise_prep              | 1          |
| alloc_cache.h | advise.c        | defined                        | 1          |
|               | alloc_cache.c   | io_alloc_cache_free            | 1          |
|               |                 | io_alloc_cache_get             | 2          |
|               |                 | io_alloc_cache_init            | 1          |
|               | alloc_cache.h   | io_alloc_cache_kasan           | 1          |
|               |                 | io_alloc_cache_put             | 1          |
|               |                 | io_cache_alloc                 | 1          |
|               | alloc_cache.c   | io_cache_alloc_new             | 2          |
|               | alloc_cache.h   | IS_ENABLED                     | 1          |
|               |                 | kasan_mempool_poison_object    | 1          |
|               |                 | kasan_mempool_unpoison_object | 1          |
|               |                 | kfree                          | 1          |
|               | alloc_cache.c   | memset                         | 1          |
|               |                 | void                           | 1          |
| cancel.h      | cancel.c        | io_async_cancel                  | 1          |
|               |                 | io_async_cancel_prep             | 1          |
|               |                 | io_cancel_match_sequence         | 1          |
|               |                 | io_cancel_req_match              | 1          |
|               |                 | io_sync_cancel                   | 1          |
|               |                 | io_try_cancel                    | 1          |
| epoll.h       | advise.c        | defined                          | 1          |
|               | epoll.c         | io_epoll_ctl                     | 1          |
|               |                 | io_epoll_ctl_prep                | 1          |
| eventfd.h     | eventfd.c       | io_eventfd_flush_signal          | 1          |
|               |                 | io_eventfd_register              | 1          |
|               |                 | io_eventfd_signal                | 1          |
|               |                 | io_eventfd_unregister            | 1          |
| fdinfo.h      | fdinfo.c        | io_uring_show_fdinfo             | 1          |
| filetable.h   | filetable.h     | __clear_bit                      | 1          |
|               | filetable.c     | io_alloc_file_tables             | 1          |
|               |                 | io_file_bitmap_clear             | 1          |
|               |                 | io_file_bitmap_set               | 1          |
|               | filetable.h     | io_file_get_flags                | 2          |
|               | filetable.c     | io_file_table_set_alloc_range    | 1          |
|               |                 | __io_fixed_fd_install            | 1          |
|               |                 | io_fixed_fd_install              | 1          |
|               |                 | io_fixed_fd_remove               | 1          |
|               |                 | io_fixed_file_set                | 1          |
|               |                 | io_free_file_tables              | 1          |
|               |                 | io_register_file_alloc_range     | 1          |
|               | cancel.c        | io_slot_file                     | 1          |
|               | filetable.h     | io_slot_flags                    | 1          |
|               |                 | __set_bit                        | 1          |
|               |                 | test_bit                         | 2          |
|               | advise.c        | WARN_ON_ONCE                     | 2          |
| fs.h         | fs.h          | io_linkat                       | 1          |
|              | fs.c          | io_linkat_prep                  | 1          |
|              |               | io_link_cleanup                 | 1          |
|              |               | io_mkdirat                      | 1          |
|              |               | io_mkdirat_cleanup              | 1          |
|              |               | io_mkdirat_prep                 | 1          |
|              |               | io_renameat                     | 1          |
|              |               | io_renameat_cleanup             | 1          |
|              |               | io_renameat_prep                | 1          |
|              |               | io_symlinkat                    | 1          |
|              |               | io_symlinkat_prep               | 1          |
|              |               | io_unlinkat                     | 1          |
|              |               | io_unlinkat_cleanup             | 1          |
|              |               | io_unlinkat_prep                | 1          |
| futex.h      | advise.c      | defined                         | 1          |
|              | futex.c       | io_futex_cache_free             | 2          |
|              |               | io_futex_cache_init             | 2          |
|              | cancel.c      | io_futex_cancel                 | 2          |
|              | futex.c       | io_futex_prep                   | 1          |
|              |               | io_futex_remove_all             | 2          |
|              |               | io_futexv_prep                  | 1          |
|              |               | io_futexv_wait                  | 1          |
|              |               | io_futex_wait                   | 1          |
|              |               | io_futex_wake                   | 1          |
| io_uring.h   | io-wq.c       | atomic_read                     | 1          |
|              | io_uring.h    | clear_notify_signal             | 1          |
|              | cancel.c      | container_of                    | 1          |
|              | advise.c      | defined                         | 1          |
|              | io_uring.h    | file_can_poll                   | 1          |
|              | cancel.c      | fput                            | 1          |
|              | io-wq.c       | get_signal                      | 1          |
|              | io-wq.h       | in_task                         | 1          |
|              | io_uring.c    | io_activate_pollwq              | 1          |
|              |               | io_add_aux_cqe                  | 1          |
|              | io_uring.h    | io_alloc_async_data             | 1          |
|              | io_uring.c    | io_alloc_req                    | 1          |
|              |               | __io_alloc_req_refill           | 2          |
|              |               | io_allowed_defer_tw_run         | 1          |
|              |               | io_allowed_run_tw               | 1          |
|              | alloc_cache.h | io_cache_alloc                  | 1          |
|              | io_uring.c    | io_commit_cqring                | 1          |
|              |               | __io_commit_cqring_flush        | 2          |
|              |               | io_commit_cqring_flush          | 1          |
|              |               | io_cqe_cache_refill             | 2          |
|              |               | io_cqring_wake                  | 1          |
|              |               | io_do_iopoll                    | 1          |
|              |               | io_extract_req                  | 2          |
|              |               | io_file_can_poll                | 1          |
|              | cancel.c      | io_file_get_fixed               | 1          |
|              |               | io_file_get_normal              | 1          |
|              | io_uring.c    | io_fill_cqe_req                 | 1          |
|              |               | io_for_each_link                | 1          |
|              |               | io_free_req                     | 1          |
|              |               | io_get_cqe                      | 2          |
|              |               | io_get_cqe_overflow             | 2          |
|              |               | io_get_task_refs                | 1          |
|              |               | io_get_time                     | 1          |
|              |               | io_handle_tw_list               | 1          |
|              |               | io_has_work                     | 1          |
|              |               | io_local_work_pending           | 3          |
|              | io_uring.h    | io_lockdep_assert_cq_locked     | 2          |
|              | futex.c       | io_match_task_safe              | 1          |
|              | io_uring.c    | io_poll_issue                   | 1          |
|              |               | io_poll_wq_wake                 | 1          |
|              |               | io_post_aux_cqe                 | 1          |
|              |               | io_put_file                     | 1          |
|              |               | io_queue_next                   | 1          |
|              |               | io_req_cache_empty              | 2          |
|              |               | io_req_complete_defer           | 1          |
|              |               | io_req_defer_failed             | 1          |
|              |               | io_req_post_cqe                 | 1          |
|              |               | io_req_queue_iowq               | 1          |
|              | io_uring.h    | io_req_queue_tw_complete        | 1          |
|              | advise.c      | io_req_set_res                  | 2          |
|              | futex.c       | io_req_task_complete            | 1          |
|              | io_uring.c    | io_req_task_queue_fail          | 1          |
|              |               | io_req_task_submit              | 1          |
|              |               | __io_req_task_work_add          | 2          |
|              | futex.c       | io_req_task_work_add            | 2          |
|              | io_uring.c    | io_req_task_work_add_remote     | 1          |
|              |               | io_ring_add_registered_file     | 1          |
|              |               | IORING_MAX_CQ_ENTRIES           | 1          |
|              | cancel.c      | io_ring_submit_lock             | 1          |
|              |               | io_ring_submit_unlock           | 1          |
|              | io-wq.c       | io_run_task_work                | 1          |
|              | cancel.c      | io_run_task_work_sig            | 1          |
|              | io_uring.c    | io_should_terminate_tw          | 1          |
|              |               | io_should_wake                  | 2          |
|              |               | io_sqring_entries               | 1          |
|              |               | io_sqring_full                  | 1          |
|              |               | __io_submit_flush_completions   | 2          |
|              |               | io_submit_flush_completions     | 1          |
|              |               | io_submit_sqes                  | 1          |
|              |               | io_task_refs_refill             | 2          |
|              |               | io_task_work_pending            | 1          |
|              | futex.c       | io_tw_lock                      | 1          |
|              | io_uring.h    | io_uring_alloc_async_data       | 1          |
|              |               | io_uring_alloc_task_context     | 1          |
|              | io_uring.c    | io_uring_cancel_generic         | 1          |
|              |               | io_uring_fill_params            | 1          |
|              |               | io_wq_free_work                 | 1          |
|              |               | io_wq_submit_work               | 1          |
|              | alloc_cache.c | kmalloc                         | 1          |
|              | io_uring.h    | ktime_get                       | 1          |
|              |               | ktime_get_with_offset           | 1          |
|              | io-wq.c       | likely                          | 2          |
|              | io_uring.c    | llist_empty                     | 2          |
|              |               | lockdep_assert                  | 2          |
|              | futex.c       | lockdep_assert_held             | 7          |
|              | io_uring.c    | memcpy                          | 2          |
|              | alloc_cache.c | memset                          | 1          |
|              | fdinfo.c      | min                             | 1          |
| io_uring.h     | cancel.c      | __must_hold                        | 1         |
| io_uring.h     | cancel.c      | mutex_lock                         | 1         |
| io_uring.h     | cancel.c      | mutex_unlock                       | 1         |
| io_uring.h     | io_uring.h    | percpu_ref_is_dying                | 1         |
| io_uring.h     | io_uring.h    | poll_to_key                        | 2         |
| io_uring.h     | advise.c      | READ_ONCE                          | 3         |
| io_uring.h     | io_uring.h    | req_has_async_data                 | 1         |
| io_uring.h     | advise.c      | req_set_fail                       | 1         |
| io_uring.h     | io_uring.h    | resume_user_mode_work              | 1         |
| io_uring.h     | io_uring.c    | rings_size                         | 1         |
| io_uring.h     | futex.c       | __set_current_state                | 3         |
| io_uring.h     | io_uring.c    | smp_load_acquire                   | 1         |
| io_uring.h     | io_uring.c    | smp_store_release                  | 1         |
| io_uring.h     | futex.c       | submission                         | 1         |
| io_uring.h     | fdinfo.c      | task_work_pending                  | 2         |
| io_uring.h     | io_uring.h    | task_work_run                      | 1         |
| io_uring.h     | io_uring.c    | tctx_task_work                     | 1         |
| io_uring.h     | io_uring.c    | tctx_task_work_run                 | 2         |
| io_uring.h     | filetable.h   | test_bit                           | 1         |
| io_uring.h     | io_uring.h    | test_thread_flag                   | 2         |
| io_uring.h     | io_uring.c    | trace_io_uring_complete            | 1         |
| io_uring.h     | io_uring.h    | trace_io_uring_complete_enabled    | 1         |
| io_uring.h     | cancel.c      | unlikely                           | 8         |
| io_uring.h     | io_uring.h    | uring_sqe_size                     | 1         |
| io_uring.h     | io_uring.h    | waits                              | 1         |
| io_uring.h     | io_uring.h    | __wake_up                          | 2         |
| io_uring.h     | advise.c      | WARN_ON_ONCE                       | 1         |
| io_uring.h     | io-wq.c       | wq_has_sleeper                     | 2         |
| io_uring.h     | io-wq.c       | wq_list_add_tail                   | 1         |
| io_uring.h     | io-wq.c       | wq_list_empty                      | 1         |
| io_uring.h     | io_uring.h    | wq_stack_extract                   | 1         |
| io-wq.h        | io-wq.c       | atomic_read                        | 1         |
| io-wq.h        | advise.c      | bool                               | 1         |
| io-wq.h        | advise.c      | defined                            | 1         |
| io-wq.h        | io-wq.h       | in_task                            | 1         |
| io-wq.h        | cancel.c      | io_wq_cancel_cb                    | 1         |
| io-wq.h        | io-wq.c       | io_wq_cpu_affinity                 | 1         |
| io-wq.h        | io-wq.c       | io_wq_create                       | 1         |
| io-wq.h        | cancel.c      | io_wq_current_is_worker           | 1         |
| io-wq.h        | io-wq.c       | io_wq_enqueue                      | 1         |
| io-wq.h        | io-wq.c       | io_wq_exit_start                   | 1         |
| io-wq.h        | io-wq.c       | io_wq_hash_work                    | 1         |
| io-wq.h        | io-wq.c       | io_wq_is_hashed                    | 1         |
| io-wq.h        | io-wq.c       | io_wq_max_workers                  | 1         |
| io-wq.h        | io-wq.c       | io_wq_put_and_exit                 | 1         |
| io-wq.h        | io-wq.c       | io_wq_put_hash                     | 1         |
| io-wq.h        | io-wq.c       | io_wq_worker_running               | 2         |
| io-wq.h        | io-wq.c       | io_wq_worker_sleeping              | 2         |
| io-wq.h        | io-wq.c       | io_wq_worker_stopped               | 1         |
| io-wq.h          | alloc_cache.h      | kfree                            | 1      |
| io-wq.h          | eventfd.c          | refcount_dec_and_test            | 1      |
| io-wq.h          | alloc_cache.c      | void                             | 1      |
| kbuf.h           | kbuf.c             | io_buffer_select                 | 1      |
| kbuf.h           | kbuf.c             | io_buffers_peek                  | 1      |
| kbuf.h           | kbuf.c             | io_buffers_select                | 1      |
| kbuf.h           | io_uring.c         | io_destroy_buffers               | 1      |
| kbuf.h           | kbuf.h             | io_do_buffer_select              | 1      |
| kbuf.h           | kbuf.c             | io_kbuf_commit                   | 2      |
| kbuf.h           | io_uring.c         | io_kbuf_drop                     | 1      |
| kbuf.h           | io_uring.c         | io_kbuf_recycle                  | 1      |
| kbuf.h           | kbuf.c             | io_kbuf_recycle_legacy           | 2      |
| kbuf.h           | kbuf.h             | io_kbuf_recycle_ring             | 2      |
| kbuf.h           | kbuf.c             | io_pbuf_get_region               | 1      |
| kbuf.h           | kbuf.c             | io_provide_buffers               | 1      |
| kbuf.h           | kbuf.c             | io_provide_buffers_prep          | 1      |
| kbuf.h           | kbuf.c             | __io_put_kbuf                    | 2      |
| kbuf.h           | io_uring.c         | io_put_kbuf                      | 1      |
| kbuf.h           | kbuf.c             | __io_put_kbuf_list               | 2      |
| kbuf.h           | kbuf.h             | __io_put_kbuf_ring               | 3      |
| kbuf.h           | kbuf.h             | __io_put_kbufs                   | 3      |
| kbuf.h           | kbuf.h             | io_put_kbufs                     | 1      |
| kbuf.h           | kbuf.c             | io_register_pbuf_ring            | 1      |
| kbuf.h           | kbuf.c             | io_register_pbuf_status          | 1      |
| kbuf.h           | kbuf.c             | io_remove_buffers                | 1      |
| kbuf.h           | kbuf.c             | io_remove_buffers_prep           | 1      |
| kbuf.h           | kbuf.c             | io_ring_head_to_buf              | 2      |
| kbuf.h           | kbuf.c             | io_unregister_pbuf_ring          | 1      |
| kbuf.h           | kbuf.c             | list_add                         | 1      |
| kbuf.h           | futex.c            | lockdep_assert_held              | 1      |
| kbuf.h           | cancel.c           | unlikely                         | 2      |
| kbuf.h           | advise.c           | WARN_ON_ONCE                     | 1      |
| memmap.h         | io_uring.c         | io_create_region                 | 1      |
| memmap.h         | kbuf.c             | io_create_region_mmap_safe       | 1      |
| memmap.h         | io_uring.c         | io_free_region                   | 1      |
| memmap.h         | memmap.c           | io_pin_pages                     | 1      |
| memmap.h         | io_uring.c         | io_region_get_ptr                | 1      |
| memmap.h         | memmap.c           | io_region_is_set                 | 1      |
| memmap.h         | io_uring.c         | io_uring_get_unmapped_area       | 1      |
| memmap.h         | io_uring.c         | io_uring_mmap                    | 1      |
| memmap.h         | io_uring.c         | io_uring_nommu_mmap_capabilities | 1      |
| msg_ring.h       | msg_ring.c         | io_msg_ring                      | 1      |
| msg_ring.h       | msg_ring.c         | io_msg_ring_cleanup              | 1      |
| msg_ring.h       | msg_ring.c         | io_msg_ring_prep                 | 1      |
| msg_ring.h       | msg_ring.c         | io_uring_sync_msg_ring           | 1      |
| napi.h           | napi.h             | io_napi                          | 3      |
| napi.h           | napi.h             | io_napi_add                      | 3      |
| napi.h           | napi.c             | __io_napi_add_id                 | 2      |
| napi.h           | napi.c             | __io_napi_busy_loop              | 2      |
| napi.h           | io_uring.c         | io_napi_busy_loop                | 2      |
| napi.h           | io_uring.c         | io_napi_free                     | 2      |
| napi.h           | io_uring.c         | io_napi_init                     | 2      |
| napi.h           | napi.c             | io_napi_sqpoll_busy_poll         | 2      |
| napi.h           | napi.c             | io_register_napi                 | 2      |
| napi.h           | napi.c             | io_unregister_napi               | 2      |
| napi.h           | io-wq.c            | list_empty                       | 1      |
| napi.h           | advise.c           | READ_ONCE                        | 2      |
| napi.h           | napi.h             | sock_from_file                   | 1      |
| net.h            | advise.c           | defined                          | 2      |
| net.h            | net.c              | io_accept                        | 1      |
| net.h            | net.c              | io_accept_prep                   | 1      |
| net.h            | net.c              | io_bind                          | 1      |
| net.h            | net.c              | io_bind_prep                     | 1      |
| net.h            | net.c              | io_connect                       | 1      |
| net.h            | net.c              | io_connect_prep                  | 1      |
| net.h            | net.c              | io_listen                        | 1      |
| net.h            | net.c              | io_listen_prep                   | 1      |
| net.h            | io_uring.c         | io_netmsg_cache_free             | 2      |
| net.h            | net.c              | io_recv                          | 1      |
| net.h            | net.c              | io_recvmsg                       | 1      |
| net.h            | net.c              | io_recvmsg_prep                  | 1      |
| net.h            | net.c              | io_send                          | 1      |
| net.h            | net.c              | io_sendmsg                       | 1      |
| net.h            | net.c              | io_sendmsg_prep                  | 1      |
| net.h            | net.c              | io_sendmsg_recvmsg_cleanup       | 1      |
| net.h            | net.c              | io_sendmsg_zc                    | 1      |
| net.h            | net.c              | io_sendrecv_fail                 | 1      |
| net.h            | net.c              | io_send_zc                       | 1      |
| net.h            | net.c              | io_send_zc_cleanup               | 1      |
| net.h            | net.c              | io_send_zc_prep                  | 1      |
| net.h            | net.c              | io_shutdown                      | 1      |
| net.h            | net.c              | io_shutdown_prep                 | 1      |
| net.h            | net.c              | io_socket                        | 1      |
| net.h            | net.c              | io_socket_prep                   | 1      |
| net.h            | net.h              | struct_group                     | 2      |
| nop.h            | nop.c              | io_nop                           | 1      |
| nop.h            | nop.c              | io_nop_prep                      | 1      |
| notif.h          | memmap.c           | __io_account_mem                 | 1      |
| notif.h          | net.c              | io_alloc_notif                   | 1      |
| notif.h          | advise.c           | io_kiocb_to_cmd                  | 1      |
| notif.h          | net.c              | io_notif_account_mem             | 1      |
| notif.h          | net.c              | io_notif_flush                   | 1      |
| notif.h          | net.c              | io_notif_to_data                 | 3      |
| notif.h          | notif.c            | IO_NOTIF_UBUF_FLAGS              | 1      |
| notif.h          | notif.c            | io_tx_ubuf_complete              | 2      |
| notif.h          | cancel.c           | __must_hold                      | 1      |
| opdef.h         | advise.c         | int                                       | 2      |
| opdef.h         | opdef.c          | io_uring_op_supported                     | 1      |
| opdef.h         | io_uring.c       | io_uring_optable_init                     | 1      |
| opdef.h         | alloc_cache.c    | void                                      | 2      |
| openclose.h     | opdef.c          | io_close                                  | 1      |
| openclose.h     | openclose.c      | __io_close_fixed                          | 1      |
| openclose.h     | opdef.c          | io_close_prep                             | 1      |
| openclose.h     | opdef.c          | io_install_fixed_fd                       | 1      |
| openclose.h     | opdef.c          | io_install_fixed_fd_prep                  | 1      |
| openclose.h     | opdef.c          | io_openat                                 | 1      |
| openclose.h     | opdef.c          | io_openat2                                | 1      |
| openclose.h     | opdef.c          | io_openat2_prep                           | 1      |
| openclose.h     | opdef.c          | io_openat_prep                            | 1      |
| openclose.h     | opdef.c          | io_open_cleanup                           | 1      |
| poll.h          | io-wq.c          | atomic_inc                                | 1      |
| poll.h          | io_uring.c       | io_arm_poll_handler                       | 1      |
| poll.h          | opdef.c          | io_poll_add                               | 1      |
| poll.h          | opdef.c          | io_poll_add_prep                          | 1      |
| poll.h          | cancel.c         | io_poll_cancel                            | 1      |
| poll.h          | poll.h           | io_poll_multishot_retry                   | 1      |
| poll.h          | opdef.c          | io_poll_remove                            | 1      |
| poll.h          | io_uring.c       | io_poll_remove_all                        | 1      |
| poll.h          | opdef.c          | io_poll_remove_prep                       | 1      |
| poll.h          | io_uring.c       | io_poll_task_func                         | 1      |
| refs.h          | io-wq.c          | atomic_dec                                | 1      |
| refs.h          | io-wq.c          | atomic_dec_and_test                       | 1      |
| refs.h          | io-wq.c          | atomic_inc                                | 1      |
| refs.h          | refs.h           | atomic_inc_not_zero                       | 1      |
| refs.h          | io-wq.c          | atomic_read                               | 1      |
| refs.h          | eventfd.c        | atomic_set                                | 1      |
| refs.h          | io_uring.c       | __io_req_set_refcount                     | 2      |
| refs.h          | io_uring.c       | io_req_set_refcount                       | 1      |
| refs.h          | io-wq.c          | likely                                    | 1      |
| refs.h          | io_uring.c       | req_ref_get                               | 1      |
| refs.h          | refs.h           | req_ref_inc_not_zero                      | 1      |
| refs.h          | io_uring.c       | req_ref_put                               | 1      |
| refs.h          | io_uring.c       | req_ref_put_and_test                      | 1      |
| refs.h          | refs.h           | req_ref_zero_or_close_to_overflow         | 4      |
| refs.h          | advise.c         | WARN_ON_ONCE                              | 6      |
| register.h      | eventfd.c        | io_eventfd_unregister                     | 1      |
| register.h      | io_uring.c       | io_unregister_personality                 | 1      |
| register.h      | register.c       | io_uring_register_get_file                | 1      |
| rsrc.h          | io_uring.c       | array_index_nospec                        | 1      |
| rsrc.h          | rsrc.h           | atomic_long_sub                           | 1      |
| rsrc.h          | rsrc.h           | __counted_by                              | 1      |
| rsrc.h          | memmap.c         | __io_account_mem                          | 1      |
| rsrc.h          | memmap.c         | io_check_coalesce_buffer                  | 1      |
| rsrc.h          | opdef.c          | io_files_update                           | 1      |
| rsrc.h          | opdef.c          | io_files_update_prep                      | 1      |
| rsrc.h          | rsrc.c           | io_free_rsrc_node                         | 2      |
| rsrc.h          | net.c            | io_import_fixed                           | 1      |
| rsrc.h          | rsrc.c           | io_put_rsrc_node                          | 4      |
| rsrc.h          | register.c       | io_register_clone_buffers                 | 1      |
| rsrc.h          | register.c       | io_register_files_update                  | 1      |
| rsrc.h          | register.c       | io_register_rsrc                          | 1      |
| rsrc.h          | register.c       | io_register_rsrc_update                   | 1      |
| rsrc.h          | net.c            | io_req_assign_buf_node                    | 1      |
| rsrc.h          | io_uring.c       | io_req_assign_rsrc_node                   | 2      |
| rsrc.h          | io_uring.c       | io_req_put_rsrc_nodes                     | 1      |
| rsrc.h          | filetable.c      | io_reset_rsrc_node                        | 1      |
| rsrc.h          | filetable.c      | io_rsrc_data_alloc                        | 1      |
| rsrc.h          | filetable.c      | io_rsrc_data_free                         | 1      |
| rsrc.h          | filetable.c      | io_rsrc_node_alloc                        | 1      |
| rsrc.h          | cancel.c         | io_rsrc_node_lookup                       | 1      |
| rsrc.h          | register.c       | io_sqe_buffers_register                   | 1      |
| rsrc.h          | io_uring.c       | io_sqe_buffers_unregister                 | 1      |
| rsrc.h          | register.c       | io_sqe_files_register                     | 1      |
| rsrc.h          | io_uring.c       | io_sqe_files_unregister                   | 1      |
| rsrc.h          | memmap.c         | __io_unaccount_mem                        | 1      |
| rsrc.h          | futex.c          | lockdep_assert_held                       | 1      |
| rw.h            | opdef.c          | io_prep_read                              | 1      |
| rw.h            | opdef.c          | io_prep_read_fixed                        | 1      |
| rw.h            | opdef.c          | io_prep_readv                             | 1      |
| rw.h            | opdef.c          | io_prep_write                             | 1      |
| rw.h            | opdef.c          | io_prep_write_fixed                       | 1      |
| rw.h            | opdef.c          | io_prep_writev                            | 1      |
| rw.h            | opdef.c          | io_read                                   | 1      |
| rw.h            | opdef.c          | io_read_mshot                             | 1      |
| rw.h            | opdef.c          | io_read_mshot_prep                        | 1      |
| rw.h            | opdef.c          | io_readv_writev_cleanup                   | 1      |
| rw.h            | io_uring.c       | io_req_rw_complete                        | 1      |
| rw.h            | io_uring.c       | io_rw_cache_free                          | 1      |
| rw.h            | opdef.c          | io_rw_fail                                | 1      |
| rw.h            | opdef.c          | io_write                                  | 1      |
| rw.h            | net.h            | struct_group                              | 1      |
| slist.h         | cancel.c         | container_of                              | 1      |
| slist.h         | io-wq.c          | INIT_WQ_LIST                              | 2      |
| slist.h         | advise.c         | READ_ONCE                                 | 1      |
| slist.h         | io-wq.c          | wq_list_add_after                         | 1      |
| slist.h         | io_uring.c       | wq_list_add_head                          | 1      |
| slist.h         | io-wq.c          | wq_list_add_tail                          | 1      |
| slist.h         | io-wq.c          | wq_list_cut                               | 2      |
| slist.h         | io-wq.c          | wq_list_del                               | 1      |
| slist.h         | io-wq.c          | wq_list_empty                             | 2      |
| slist.h         | io_uring.c       | __wq_list_for_each                        | 1      |
| slist.h         | io-wq.c          | wq_list_for_each                          | 1      |
| slist.h         | rw.c             | wq_list_for_each_resume                   | 1      |
| slist.h         | slist.h          | __wq_list_splice                          | 2      |
| slist.h         | slist.h          | wq_list_splice                            | 1      |
| slist.h         | io-wq.c          | wq_next_work                              | 1      |
| slist.h         | io_uring.c       | wq_stack_add_head                         | 1      |
| slist.h         | io_uring.h       | wq_stack_extract                          | 1      |
| slist.h         | io_uring.c       | WRITE_ONCE                                | 3      |
| splice.h        | opdef.c          | io_splice                                 | 1      |
| splice.h        | opdef.c          | io_splice_cleanup                         | 1      |
| splice.h        | opdef.c          | io_splice_prep                            | 1      |
| splice.h        | opdef.c          | io_tee                                    | 1      |
| splice.h        | opdef.c          | io_tee_prep                               | 1      |
| sqpoll.h      | register.c    | io_put_sq_data                        | 1      |
| sqpoll.h      | io_uring.c    | io_sq_offload_create                  | 1      |
| sqpoll.h      | io_uring.c    | io_sqpoll_wait_sq                     | 1      |
| sqpoll.h      | register.c    | io_sqpoll_wq_cpu_affinity             | 1      |
| sqpoll.h      | io_uring.c    | io_sq_thread_finish                   | 1      |
| sqpoll.h      | io_uring.c    | io_sq_thread_park                     | 1      |
| sqpoll.h      | sqpoll.c      | io_sq_thread_stop                     | 1      |
| sqpoll.h      | io_uring.c    | io_sq_thread_unpark                   | 1      |
| statx.h       | opdef.c       | io_statx                              | 1      |
| statx.h       | opdef.c       | io_statx_cleanup                      | 1      |
| statx.h       | opdef.c       | io_statx_prep                         | 1      |
| sync.h        | opdef.c       | io_fallocate                          | 1      |
| sync.h        | opdef.c       | io_fallocate_prep                     | 1      |
| sync.h        | opdef.c       | io_fsync                              | 1      |
| sync.h        | opdef.c       | io_fsync_prep                         | 1      |
| sync.h        | opdef.c       | io_sfr_prep                           | 1      |
| sync.h        | opdef.c       | io_sync_file_range                    | 1      |
| tctx.h        | register.c    | io_ringfd_register                    | 1      |
| tctx.h        | register.c    | io_ringfd_unregister                  | 1      |
| tctx.h        | io_uring.c    | __io_uring_add_tctx_node              | 1      |
| tctx.h        | io_uring.c    | io_uring_add_tctx_node                | 1      |
| tctx.h        | tctx.c        | __io_uring_add_tctx_node_from_submit | 2      |
| tctx.h        | io_uring.h    | io_uring_alloc_task_context           | 1      |
| tctx.h        | io_uring.c    | io_uring_clean_tctx                   | 1      |
| tctx.h        | io_uring.c    | io_uring_del_tctx_node                | 1      |
| tctx.h        | io_uring.c    | io_uring_unreg_ringfd                 | 1      |
| tctx.h        | io-wq.c       | likely                                | 1      |
| timeout.h     | timeout.c     | __io_disarm_linked_timeout            | 2      |
| timeout.h     | timeout.c     | io_disarm_linked_timeout              | 1      |
| timeout.h     | io_uring.c    | io_disarm_next                        | 1      |
| timeout.h     | io_uring.c    | io_flush_timeouts                     | 1      |
| timeout.h     | io_uring.c    | io_kill_timeouts                      | 1      |
| timeout.h     | opdef.c       | io_link_timeout_prep                  | 1      |
| timeout.h     | io_uring.c    | io_queue_linked_timeout               | 1      |
| timeout.h     | opdef.c       | io_timeout                            | 1      |
| timeout.h     | cancel.c      | io_timeout_cancel                     | 1      |
| timeout.h     | opdef.c       | io_timeout_prep                       | 1      |
| timeout.h     | opdef.c       | io_timeout_remove                     | 1      |
| timeout.h     | opdef.c       | io_timeout_remove_prep                | 1      |
| truncate.h    | opdef.c       | io_ftruncate                          | 1      |
| truncate.h    | opdef.c       | io_ftruncate_prep                     | 1      |
| uring_cmd.h   | opdef.c       | io_uring_cmd                          | 1      |
| uring_cmd.h   | opdef.c       | io_uring_cmd_prep                     | 1      |
| uring_cmd.h   | io_uring.c    | io_uring_try_cancel_uring_cmd         | 1      |
| waitid.h      | opdef.c       | io_waitid                             | 1      |
| waitid.h      | cancel.c      | io_waitid_cancel                      | 1      |
| waitid.h      | opdef.c       | io_waitid_prep                        | 1      |
| waitid.h      | io_uring.c    | io_waitid_remove_all                  | 1      |
| xattr.h       | opdef.c       | io_fgetxattr                          | 1      |
| xattr.h       | opdef.c       | io_fgetxattr_prep                     | 1      |
| xattr.h       | opdef.c       | io_fsetxattr                          | 1      |
| xattr.h       | opdef.c       | io_fsetxattr_prep                     | 1      |
| xattr.h       | opdef.c       | io_getxattr                           | 1      |
| xattr.h       | opdef.c       | io_getxattr_prep                      | 1      |
| xattr.h       | opdef.c       | io_setxattr                           | 1      |
| xattr.h       | opdef.c       | io_setxattr_prep                      | 1      |
| xattr.h       | opdef.c       | io_xattr_cleanup                      | 1      |

Continue with the list untill all functions used in each source are listed.
