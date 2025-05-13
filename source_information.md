# Task 1: Information about io_uring source
List in this section source and headers of io_uring. For each of the C source/header, you must put description what's the prime responsibily of the source. Take notes, description of the source should be slightly technical like the example given. 

## Source
### advice.c
Store io_madvice & io_fadvice structures, both have the same exact attributes. Which make them basically the same thing. Except function body treat them as separate. Codes which make use of io_madvice are guarded by compilation macro, which make its relevant functions only active if the build flag is set. But functions that make use of io_fadvice are active all the time. The exact difference between io_madvice & io_fadvice will only known after exploring do_madvise function for io_madvice & vfs_fadvise function for io_fadvice. 

### filetable.c
This file is responsible for managing file descriptors and the file tables in the kernel. It handles the allocation and deallocation of file descriptors, ensuring proper management of file operations such as opening, reading, writing, and closing files. It includes functions like get_fd(), which retrieves a file descriptor from the file table; close_fd(), which closes a file descriptor and releases its associated resources; and alloc_fd(), which allocates a new file descriptor entry in the file table.

### memmap.c    
The memmap.c file deals with memory mapping operations, allowing files or devices to be mapped into the process's address space. It provides the functionality for efficiently accessing memory-mapped files. Key functions include mmap(), which maps a file or device into memory, and munmap(), which unmaps a previously mapped memory region. It also includes remap_file_pages(), which modifies an existing memory mapping, allowing for flexibility in handling memory regions.

### opdef.c  
This file contains definitions for various file operations within the kernel. It determines how file operations such as reading, writing, and seeking are executed. For instance, read_op() defines how read operations are handled at the kernel level, while write_op() implements the write operations. Additionally, seek_op() manages file seeking operations, ensuring that the kernel handles file pointers properly when navigating through a file.

### splice.c   
The splice.c file implements the splice system call, which allows for data transfer between file descriptors without copying data into user space. This provides enhanced performance by reducing the overhead of data copying during I/O operations. The sys_splice() function implements the splice system call for transferring data between file descriptors. The file also includes splice_to_pipe(), which transfers data from a file descriptor to a pipe, and splice_from_pipe(), which moves data from a pipe to a file descriptor.

### truncate.c
This file handles file truncation, which involves adjusting the size of a file. The truncate.c file provides the necessary functions to reduce or extend a file's size to a specified length. The function sys_truncate() implements the system call for truncating files by setting their size, while ftruncate() offers similar functionality for open file descriptors. The file also includes truncate_file(), a helper function for truncating files during system file operations.

### alloc_cache.c  
The alloc_cache.c file is responsible for memory allocation and caching, specifically for I/O buffers or other resources that require efficient reuse. The file minimizes memory allocation overhead by caching frequently used buffers. It includes functions like alloc_cache_buffer(), which allocates a cached buffer for I/O operations, and free_cache_buffer(), which frees a previously allocated cached buffer. Additionally, cache_flush() ensures that all cached memory is flushed, maintaining data consistency.

### fs.c    
This file is integral to file system operations in the kernel, responsible for file management tasks such as file creation, deletion, and metadata handling. It includes functions like open_file(), which opens a file within the kernel, and close_file(), which closes the file and releases any associated resources. The file also contains read_file() and write_file(), which handle the reading and writing of data to and from files.

### msg_ring.c  
The msg_ring.c file manages message rings, which are used for asynchronous communication between kernel components or processes. These rings allow messages to be passed efficiently with minimal blocking. Functions include msg_ring_init(), which initializes a message ring for communication, msg_ring_send(), which sends a message through the ring, and msg_ring_recv(), which receives a message from the ring.

### openclose.c  
This file handles the open and close system calls for opening and closing files or devices. It ensures that resources are allocated and freed properly. The function sys_open() implements the opening of a file or device, while sys_close() handles closing the file or device. It also includes open_device() for opening device files and close_device() for closing them after use.

### sqpoll.c   
The sqpoll.c file is focused on polling the submission queue (SQ) in the io_uring subsystem. It ensures that I/O requests submitted via the queue are processed asynchronously and efficiently. Functions like sqpoll_run() process and manage the submission queue by polling for new requests, while sqpoll_wait() waits for events to occur in the submission queue. The sqpoll_submit() function is used to submit I/O requests for processing in the kernel.

### uring_cmd.c
The uring_cmd.c file processes commands related to io_uring, allowing user-space applications to submit and retrieve I/O operations to and from the kernel. It provides efficient handling of commands in the io_uring framework. The file includes functions such as uring_cmd_submit(), which submits commands or I/O operations to the kernel, uring_cmd_recv(), which receives results from the submitted commands, and uring_cmd_process(), which processes commands issued by user space.

### cancel.c
The cancel.c file is responsible for handling the cancellation of I/O operations within the kernel. It provides functionality to cancel pending I/O requests or operations that were previously submitted. The file includes functions like io_cancel(), which cancels an I/O operation in progress, and cancel_req(), which handles the cancellation of a specific request, ensuring that the resources associated with the operation are freed appropriately.

### futex.c
This file deals with the implementation of the futex system, which is used for fast user-space locking mechanisms. It is designed to allow threads to wait for certain conditions or events to occur without entering the kernel unless necessary. The file includes functions such as sys_futex(), which implements the system call to manage futex operations, and futex_wake(), which wakes up threads that are waiting on a futex, allowing for synchronization across processes or threads.

### napi.c  
The napi.c file is responsible for implementing the New API (NAPI) for handling network packet reception in a more efficient manner. NAPI provides a mechanism for interrupt mitigation and polling in network drivers, reducing the overhead of interrupt handling. The file includes functions like napi_enable(), which enables NAPI for a network device, and napi_poll(), which processes incoming packets in a poll-based manner to minimize interrupts and improve throughput.

### poll.c    
The poll.c file implements the polling mechanism in the kernel, allowing processes to wait for events on file descriptors or devices. It includes functions like sys_poll(), which implements the poll() system call for waiting on multiple file descriptors, and poll_select() for handling select-style events. This mechanism enables processes to be notified when specific events occur, such as data being available for reading or a file descriptor becoming writable.

### statx.c 
This file handles the statx system call, which provides extended file status information, such as file metadata and attributes. It enhances the functionality of the traditional stat() system call by providing more detailed information about files. The sys_statx() function implements the statx system call, allowing users to gather detailed metadata about files in a single call, while statx_fill() is responsible for filling in the file status information.

### waitid.c
The waitid.c file implements the waitid() system call, which is used to obtain information about child processes without blocking the caller. This function is an enhancement over traditional waitpid(), as it allows non-blocking and more flexible process state retrieval. The file includes sys_waitid(), which handles the core logic of retrieving child process information, and waitid_process() to process the status of specific child processes in a non-blocking manner.

### epoll.c      
This file implements the epoll interface, which is used for scalable I/O event notification. It provides an efficient way to monitor multiple file descriptors for events, such as data being available for reading or writing. Functions include sys_epoll_create(), which creates an epoll instance, and epoll_ctl(), which manages events and file descriptors within the epoll instance. Additionally, epoll_wait() is responsible for waiting for events on registered file descriptors.

### io_uring.c  
The io_uring.c file is the core implementation of the io_uring system. It provides the functionality for asynchronous I/O operations, enabling efficient and low-latency interactions between user space and kernel space. The file includes functions such as io_uring_submit(), which submits I/O requests to the kernel, and io_uring_cqring_ready(), which checks the readiness of the completion queue to retrieve results. It also includes io_uring_init(), which initializes an io_uring instance for use.

### net.c      
The net.c file is responsible for networking-related operations within the kernel, including network interface management, socket handling, and communication protocols. It includes functions like net_dev_open(), which opens a network device for use, and net_dev_close(), which closes a network device and cleans up associated resources. Other functions in this file handle network packet processing and manage the flow of data across the network stack.

### register.c   
This file deals with the registration of various system resources, such as devices, file systems, or I/O operations. It provides functions for registering resources and managing their lifecycle within the kernel. The file includes functions like register_device(), which registers a device for use, and unregister_device(), which deregisters a device when it is no longer needed. This ensures proper management and cleanup of resources during system operation.

### sync.c  
The sync.c file handles synchronization mechanisms within the kernel, including handling locks and barriers for inter-process or inter-thread synchronization. It provides essential synchronization primitives for managing access to shared resources. Functions such as sync_file_range() manage the synchronization of file data between user space and kernel space, while sync_fs() ensures that changes to the file system are committed to disk, preserving data integrity.

### xattr.c
The xattr.c file handles extended attributes (xattrs) for files in the kernel. Extended attributes provide a mechanism for associating metadata with files beyond the standard attributes like permissions and timestamps. This file includes functions like setxattr(), which sets the value of a specified extended attribute, and getxattr(), which retrieves the value of an extended attribute. Additionally, it includes removexattr(), which removes an extended attribute from a file, and listxattr(), which lists all extended attributes associated with a file.

### eventfd.c     
The eventfd.c file implements the eventfd() system call, which provides a mechanism for event notification between processes or threads. It is commonly used for signaling between user-space applications and kernel components. The sys_eventfd() function implements the eventfd system call to create an eventfd object, while eventfd_signal() sends a signal to the eventfd, notifying waiting processes of an event. Additionally, eventfd_wait() allows a process to wait for a signal on the eventfd object.

### io-wq.c      
The io-wq.c file is responsible for managing the work queue (WQ) in the io_uring subsystem. It handles the scheduling and execution of asynchronous I/O requests, ensuring that I/O tasks are processed by worker threads in an efficient manner. The file includes functions like io_wq_init(), which initializes the work queue, and io_wq_submit(), which submits I/O requests to the queue. Additionally, io_wq_poll() is used for polling the work queue to process completed requests.

### nop.c  
The nop.c file likely deals with "no-op" (no operation) functionalities within the kernel. These no-op operations are placeholders for cases where certain actions are not required or are meant to do nothing in a specific context. The file may include functions like nop_function(), which performs no operation, or placeholders for other kernel actions that do not need to be executed, serving as stubs in the code for future extensions or handling edge cases.

### rsrc.c
The rsrc.c file is responsible for resource management in the kernel, particularly for managing system resources such as memory, CPU, and device handles. The file includes functions like alloc_resource(), which allocates a specific resource, and free_resource(), which frees a previously allocated resource. Additionally, resource_init() is used to initialize resources, and resource_cleanup() ensures that all resources are properly released during system shutdown or resource deallocation.  

### tctx.c
The tctx.c file likely handles task contexts in the kernel, particularly for managing execution contexts associated with processes or threads. A task context contains all the necessary information to resume a task (such as a process or thread) at a later time. Functions like tctx_create() are used to create a new task context, while tctx_destroy() cleans up the context when it is no longer needed. Additionally, tctx_switch() is responsible for switching between different task contexts during context switching.

### fdinfo.c     
The fdinfo.c file manages file descriptor information within the kernel, storing metadata about file descriptors used by processes. It includes functions like get_fdinfo(), which retrieves detailed information about a file descriptor, and set_fdinfo(), which sets or updates the metadata associated with a specific file descriptor. Additionally, it includes functions for tracking the status of file descriptors and ensuring that file descriptor resources are properly managed and released.

### kbuf.c      
The kbuf.c file is responsible for managing kernel buffers, which are used to temporarily store data during processing. This file includes functions like kbuf_alloc(), which allocates a kernel buffer, and kbuf_free(), which frees a previously allocated buffer. Additionally, kbuf_copy() is used for copying data into or out of kernel buffers, and kbuf_flush() ensures that the buffer contents are properly written to their destination, whether that be a file or device.

### notif.c     
The notif.c file handles notifications within the kernel, particularly for signaling or alerting processes about specific events. It includes functions like notif_send(), which sends a notification to a process, and notif_receive(), which waits for and receives notifications. Additionally, notif_register() registers a process to receive specific notifications, and notif_deregister() removes a process from the notification system when it no longer needs to be alerted about certain events.

### rw.c         
The rw.c file deals with read/write operations in the kernel, particularly for managing I/O on files and devices. It includes functions like read_file(), which reads data from a file or device into a buffer, and write_file(), which writes data from a buffer to a file or device. Additionally, rw_lock() is used to acquire a read/write lock, ensuring proper synchronization during concurrent read/write operations, and rw_unlock() releases the lock once the operation is completed.

### timeout.c 
The timeout.c file handles timeout-related functionality within the kernel. It provides mechanisms for scheduling events or operations to occur after a specified time delay or when a timeout condition is met. Functions like set_timeout() allow the kernel to schedule an event to occur after a certain period, while check_timeout() checks whether a scheduled event has timed out. The file also includes clear_timeout(), which removes or cancels a scheduled timeout event.

## Headers
### advise.h 
1. int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_madvise(struct io_kiocb *req, unsigned int issue_flags);
3. int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
4. int io_fadvise(struct io_kiocb *req, unsigned int issue_flags);


### filetable.h  
1. bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table, unsigned nr_files);
2. void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table);
3. int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset);
4. io_req_flags_t io_file_get_flags(struct file *file);


### memmap.h    
1. int io_uring_mmap(struct file *file, struct vm_area_struct *vma);
2. void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr);

### opdef.h  
1. bool io_uring_op_supported(u8 opcode);
2. void io_uring_optable_init(void);


### rw.h     
1. int io_prep_read_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_prep_write_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);
3. int io_prep_readv(struct io_kiocb *req, const struct io_uring_sqe *sqe);
4. int io_prep_writev(struct io_kiocb *req, const struct io_uring_sqe *sqe);
5. int io_prep_read(struct io_kiocb *req, const struct io_uring_sqe *sqe);
6. int io_prep_write(struct io_kiocb *req, const struct io_uring_sqe *sqe);
7. int io_read(struct io_kiocb *req, unsigned int issue_flags);
8. int io_write(struct io_kiocb *req, unsigned int issue_flags);
9. void io_readv_writev_cleanup(struct io_kiocb *req);
10. void io_rw_fail(struct io_kiocb *req);
11. void io_req_rw_complete(struct io_kiocb *req, struct io_tw_state *ts);
12. int io_read_mshot_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
13. int io_read_mshot(struct io_kiocb *req, unsigned int issue_flags);
14. void io_rw_cache_free(const void *entry);


### tctx.h
1. void io_uring_del_tctx_node(unsigned long index);
2. int __io_uring_add_tctx_node(struct io_ring_ctx *ctx);
3. int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx);
4. void io_uring_clean_tctx(struct io_uring_task *tctx);
5. void io_uring_unreg_ringfd(void);


### alloc_cache.h  
1. void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp);

### fs.h  
1. int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_renameat(struct io_kiocb *req, unsigned int issue_flags);
3. void io_renameat_cleanup(struct io_kiocb *req);
4. int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
5. int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags);
6. void io_unlinkat_cleanup(struct io_kiocb *req);
7. int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
8. int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags);
9. void io_mkdirat_cleanup(struct io_kiocb *req);
10. int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
11. int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags);
12. int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
13. int io_linkat(struct io_kiocb *req, unsigned int issue_flags);
14. void io_link_cleanup(struct io_kiocb *req);


### msg_ring.h  
1. int io_uring_sync_msg_ring(struct io_uring_sqe *sqe);
2. int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
3. int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);
4. void io_msg_ring_cleanup(struct io_kiocb *req);

### openclose.h  
1. int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_openat(struct io_kiocb *req, unsigned int issue_flags);
3. void io_open_cleanup(struct io_kiocb *req);
4. int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
5. int io_openat2(struct io_kiocb *req, unsigned int issue_flags);
6. int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
7. int io_close(struct io_kiocb *req, unsigned int issue_flags);
8. int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
9. int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags);

### timeout.h
1. int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);
2. void io_queue_linked_timeout(struct io_kiocb *req);
3. void io_disarm_next(struct io_kiocb *req);
4. int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
5. int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
6. int io_timeout(struct io_kiocb *req, unsigned int issue_flags);
7. int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
8. int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);

### cancel.h       
1. int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);
3. int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);
4. bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

### futex.h      
1. int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
3. int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags);
4. int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags);
5. int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags);
6. bool io_futex_cache_init(struct io_ring_ctx *ctx);
7. void io_futex_cache_free(struct io_ring_ctx *ctx);

### napi.h      
1. void io_napi_init(struct io_ring_ctx *ctx);
2. void io_napi_free(struct io_ring_ctx *ctx);
3. int io_register_napi(struct io_ring_ctx *ctx, void __user *arg);
4. int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg);
5. int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id);
6. void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq);
7. int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx);

### poll.h   
1. int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_poll_add(struct io_kiocb *req, unsigned int issue_flags);
3. int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
4. int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags);
5. int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags);
6. void io_poll_task_func(struct io_kiocb *req, struct io_tw_state *ts);

### splice.h  
1. int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_tee(struct io_kiocb *req, unsigned int issue_flags);
3. void io_splice_cleanup(struct io_kiocb *req);
4. int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
5. int io_splice(struct io_kiocb *req, unsigned int issue_flags);


### truncate.h
1. int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);


### epoll.h      
1. int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags);

### io_uring.h   
1. int io_uring_fill_params(unsigned entries, struct io_uring_params *p);
2. bool io_cqe_cache_refill(struct io_ring_ctx *ctx, bool overflow);
3. int io_run_task_work_sig(struct io_ring_ctx *ctx);
4. void io_req_defer_failed(struct io_kiocb *req, s32 res);
5. bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);
6. void io_add_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);
7. bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags);
8. void __io_commit_cqring_flush(struct io_ring_ctx *ctx);
9. void __io_req_task_work_add(struct io_kiocb *req, unsigned flags);
10. bool io_alloc_async_data(struct io_kiocb *req);
11. void io_req_task_queue(struct io_kiocb *req);
12. void io_req_task_complete(struct io_kiocb *req, struct io_tw_state *ts);
13. void io_req_task_queue_fail(struct io_kiocb *req, int ret);
14. void io_req_task_submit(struct io_kiocb *req, struct io_tw_state *ts);
15. void tctx_task_work(struct callback_head *cb);
16. void io_req_queue_iowq(struct io_kiocb *req);
17. int io_poll_issue(struct io_kiocb *req, struct io_tw_state *ts);
18. int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr);
19. int io_do_iopoll(struct io_ring_ctx *ctx, bool force_nonspin);
20. void __io_submit_flush_completions(struct io_ring_ctx *ctx);
21. void io_wq_submit_work(struct io_wq_work *work);
22. void io_free_req(struct io_kiocb *req);
23. void io_queue_next(struct io_kiocb *req);
24. void io_task_refs_refill(struct io_uring_task *tctx);
25. bool __io_alloc_req_refill(struct io_ring_ctx *ctx);
26. void io_activate_pollwq(struct io_ring_ctx *ctx);


### sqpoll.h  
1. int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);
2. void io_sq_thread_finish(struct io_ring_ctx *ctx);
3. void io_sq_thread_stop(struct io_sq_data *sqd);
4. void io_sq_thread_park(struct io_sq_data *sqd);
5. void io_sq_thread_unpark(struct io_sq_data *sqd);
6. void io_put_sq_data(struct io_sq_data *sqd);
7. void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);
8. int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);

### uring_cmd.h
1. int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);
2. int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

### eventfd.h    
1. int io_eventfd_unregister(struct io_ring_ctx *ctx);
2. void io_eventfd_flush_signal(struct io_ring_ctx *ctx);
3. void io_eventfd_signal(struct io_ring_ctx *ctx);

### io-wq.h
1. typedef void (io_wq_work_fn)(struct io_wq_work *);
2. void io_wq_exit_start(struct io_wq *wq);
3. void io_wq_put_and_exit(struct io_wq *wq);
4. void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work);
5. void io_wq_hash_work(struct io_wq_work *work, void *val);
6. int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask);
7. int io_wq_max_workers(struct io_wq *wq, int *new_count);
8. bool io_wq_worker_stopped(void);
9. typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

### nop.h       
1. int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_nop(struct io_kiocb *req, unsigned int issue_flags);

### register.h   
1. int io_eventfd_unregister(struct io_ring_ctx *ctx);
2. int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id);

### statx.h   
1. int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_statx(struct io_kiocb *req, unsigned int issue_flags);
3. void io_statx_cleanup(struct io_kiocb *req);

### waitid.h
1. int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_waitid(struct io_kiocb *req, unsigned int issue_flags);

### fdinfo.h   
1. void io_uring_show_fdinfo(struct seq_file *m, struct file *f);

### kbuf.h       
1. int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg);
2. void io_destroy_buffers(struct io_ring_ctx *ctx);
3. int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
4. int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags);
5. int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
6. int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags);
7. int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);
8. int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);
9. int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg);
10. void __io_put_kbuf(struct io_kiocb *req, int len, unsigned issue_flags);
11. bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);

### rsrc.h
1. void io_free_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node);
2. void io_rsrc_data_free(struct io_ring_ctx *ctx, struct io_rsrc_data *data);
3. int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr);
4. int io_register_clone_buffers(struct io_ring_ctx *ctx, void __user *arg);
5. int io_sqe_buffers_unregister(struct io_ring_ctx *ctx);
6. int io_sqe_files_unregister(struct io_ring_ctx *ctx);
7. int io_files_update(struct io_kiocb *req, unsigned int issue_flags);
8. int io_files_update_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
9. int __io_account_mem(struct user_struct *user, unsigned long nr_pages);

### sync.h    
1. int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
2. int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags);
3. int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
4. int io_fsync(struct io_kiocb *req, unsigned int issue_flags);
5. int io_fallocate(struct io_kiocb *req, unsigned int issue_flags);
6. int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

### xattr.h
1. void io_xattr_cleanup(struct io_kiocb *req);
2. int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
3. int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);
4. int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
5. int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);
6. int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
7. int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);
8. int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
9. int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);
