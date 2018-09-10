/* -*- linux-c -*- 
 * Syscall compatibility defines.
 * Copyright (C) 2013-2014 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _COMPAT_UNISTD_H_
#define _COMPAT_UNISTD_H_

// Older kernels (like RHEL5) supported __NR_sendfile64. For newer
// kernels, we'll just define __NR_sendfile64 in terms of
// __NR_sendfile.
#ifndef __NR_sendfile64
#define __NR_sendfile64 __NR_sendfile
#endif

#ifndef __NR_syscall_max
#define __NR_syscall_max 0xffff
#endif
#ifndef __NR_syscall_compat_max
#define __NR_syscall_compat_max 0xffff
#endif

#ifndef __NR__llseek
#define __NR__llseek (__NR_syscall_max + 1)
#endif
#ifndef __NR__newselect
#define __NR__newselect (__NR_syscall_max + 1)
#endif
#ifndef __NR_accept
#define __NR_accept (__NR_syscall_max + 1)
#endif
#ifndef __NR_accept4
#define __NR_accept4 (__NR_syscall_max + 1)
#endif
#ifndef __NR_bind
#define __NR_bind (__NR_syscall_max + 1)
#endif
#ifndef __NR_bpf
#define __NR_bpf (__NR_syscall_max + 1)
#endif
#ifndef __NR_connect
#define __NR_connect (__NR_syscall_max + 1)
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range (__NR_syscall_max + 1)
#endif
#ifndef __NR_epoll_wait
#define __NR_epoll_wait (__NR_syscall_max + 1)
#endif
#ifndef __NR_execveat
#define __NR_execveat (__NR_syscall_max + 1)
#endif
#ifndef __NR_fadvise64_64
#define __NR_fadvise64_64 (__NR_syscall_max + 1)
#endif
#ifndef __NR_fcntl64
#define __NR_fcntl64 (__NR_syscall_max + 1)
#endif
#ifndef __NR_fstat64
#define __NR_fstat64 (__NR_syscall_max + 1)
#endif
#ifndef __NR_ftruncate
#define __NR_ftruncate (__NR_syscall_max + 1)
#endif
#ifndef __NR_futimesat
#define __NR_futimesat (__NR_syscall_max + 1)
#endif
#ifndef __NR_getcpu
#define __NR_getcpu (__NR_syscall_max + 1)
#endif
#ifndef __NR_getgroups32
#define __NR_getgroups32 (__NR_syscall_max + 1)
#endif
#ifndef __NR_getpeername
#define __NR_getpeername (__NR_syscall_max + 1)
#endif
#ifndef __NR_getrandom
#define __NR_getrandom (__NR_syscall_max + 1)
#endif
#ifndef __NR_getsockname
#define __NR_getsockname (__NR_syscall_max + 1)
#endif
#ifndef __NR_getsockopt
#define __NR_getsockopt (__NR_syscall_max + 1)
#endif
#ifndef __NR_io_pgetevents
#define __NR_io_pgetevents (__NR_syscall_max + 1)
#endif
#ifndef __NR_ipc
#define __NR_ipc (__NR_syscall_max + 1)
#endif
#ifndef __NR_kcmp
#define __NR_kcmp (__NR_syscall_max + 1)
#endif
#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load (__NR_syscall_max + 1)
#endif
#ifndef __NR_listen
#define __NR_listen (__NR_syscall_max + 1)
#endif
#ifndef __NR_membarrier
#define __NR_membarrier (__NR_syscall_max + 1)
#endif
#ifndef __NR_mlock2
#define __NR_mlock2 (__NR_syscall_max + 1)
#endif
#ifndef __NR_mmap2
#define __NR_mmap2 (__NR_syscall_max + 1)
#endif
#ifndef __NR_move_pages
#define __NR_move_pages (__NR_syscall_max + 1)
#endif
#ifndef __NR_msgctl
#define __NR_msgctl (__NR_syscall_max + 1)
#endif
#ifndef __NR_msgget
#define __NR_msgget (__NR_syscall_max + 1)
#endif
#ifndef __NR_msgrcv
#define __NR_msgrcv (__NR_syscall_max + 1)
#endif
#ifndef __NR_msgsnd
#define __NR_msgsnd (__NR_syscall_max + 1)
#endif
#ifndef __NR_nfsservctl
#define __NR_nfsservctl (__NR_syscall_max + 1)
#endif
#ifndef __NR_nice
#define __NR_nice (__NR_syscall_max + 1)
#endif
#ifndef __NR_open
#define __NR_open (__NR_syscall_max + 1)
#endif
#ifndef __NR_preadv2
#define __NR_preadv2 (__NR_syscall_max + 1)
#endif
#ifndef __NR_pselect7
#define __NR_pselect7 (__NR_syscall_max + 1)
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2 (__NR_syscall_max + 1)
#endif
#ifndef __NR_readdir
#define __NR_readdir (__NR_syscall_max + 1)
#endif
#ifndef __NR_recv
#define __NR_recv (__NR_syscall_max + 1)
#endif
#ifndef __NR_recvfrom
#define __NR_recvfrom (__NR_syscall_max + 1)
#endif
#ifndef __NR_recvmsg
#define __NR_recvmsg (__NR_syscall_max + 1)
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 (__NR_syscall_max + 1)
#endif
#ifndef __NR_rseq
#define __NR_rseq (__NR_syscall_max + 1)
#endif
#ifndef __NR_semtimedop
#define __NR_semtimedop (__NR_syscall_max + 1)
#endif
#ifndef __NR_send
#define __NR_send (__NR_syscall_max + 1)
#endif
#ifndef __NR_sendmmsg
#define __NR_sendmmsg (__NR_syscall_max + 1)
#endif
#ifndef __NR_sendmsg
#define __NR_sendmsg (__NR_syscall_max + 1)
#endif
#ifndef __NR_sendto
#define __NR_sendto (__NR_syscall_max + 1)
#endif
#ifndef __NR_setsockopt
#define __NR_setsockopt (__NR_syscall_max + 1)
#endif
#ifndef __NR_shmctl
#define __NR_shmctl (__NR_syscall_max + 1)
#endif
#ifndef __NR_shutdown
#define __NR_shutdown (__NR_syscall_max + 1)
#endif
#ifndef __NR_sigprocmask
#define __NR_sigprocmask (__NR_syscall_max + 1)
#endif
#ifndef __NR_socket
#define __NR_socket (__NR_syscall_max + 1)
#endif
#ifndef __NR_socketcall
#define __NR_socketcall (__NR_syscall_max + 1)
#endif
#ifndef __NR_socketpair
#define __NR_socketpair (__NR_syscall_max + 1)
#endif
#ifndef __NR_statx
#define __NR_statx (__NR_syscall_max + 1)
#endif
#ifndef __NR_stime
#define __NR_stime (__NR_syscall_max + 1)
#endif
#ifndef __NR_truncate
#define __NR_truncate (__NR_syscall_max + 1)
#endif
#ifndef __NR_ugetrlimit
#define __NR_ugetrlimit (__NR_syscall_max + 1)
#endif
#ifndef __NR_umount
#define __NR_umount (__NR_syscall_max + 1)
#endif

#if defined(__x86_64__)

// On older kernels (like RHEL5), we have to define our own 32-bit
// syscall numbers.
#ifndef __NR_ia32__llseek
#define __NR_ia32__llseek 140
#endif
#ifndef __NR_ia32__newselect
#define __NR_ia32__newselect 142
#endif
#ifndef __NR_ia32_access
#define __NR_ia32_access 33
#endif
#ifndef __NR_ia32_acct
#define __NR_ia32_acct 51
#endif
#ifndef __NR_ia32_add_key
#define __NR_ia32_add_key 286
#endif
#ifndef __NR_ia32_adjtimex
#define __NR_ia32_adjtimex 124
#endif
#ifndef __NR_ia32_alarm
#define __NR_ia32_alarm 27
#endif
#ifndef __NR_ia32_arch_prctl
#define __NR_ia32_arch_prctl 384
#endif
#ifndef __NR_ia32_brk
#define __NR_ia32_brk 45
#endif
#ifndef __NR_ia32_bpf
#define __NR_ia32_bpf 357
#endif
#ifndef __NR_ia32_capget
#define __NR_ia32_capget 184
#endif
#ifndef __NR_ia32_capset
#define __NR_ia32_capset 185
#endif
#ifndef __NR_ia32_chdir
#define __NR_ia32_chdir 12
#endif
#ifndef __NR_ia32_chmod
#define __NR_ia32_chmod 15
#endif
#ifndef __NR_ia32_chown
#define __NR_ia32_chown 182
#endif
#ifndef __NR_ia32_chown32
#define __NR_ia32_chown32 212
#endif
#ifndef __NR_ia32_chroot
#define __NR_ia32_chroot 61
#endif
#ifndef __NR_ia32_clock_adjtime
#define __NR_ia32_clock_adjtime 343
#endif
#ifndef __NR_ia32_clock_gettime
#define __NR_ia32_clock_gettime 265
#endif
#ifndef __NR_ia32_clock_getres
#define __NR_ia32_clock_getres 266
#endif
#ifndef __NR_ia32_clock_nanosleep
#define __NR_ia32_clock_nanosleep 267
#endif
#ifndef __NR_ia32_clock_settime
#define __NR_ia32_clock_settime 264
#endif
#ifndef __NR_ia32_clone
#define __NR_ia32_clone 120
#endif
#ifndef __NR_ia32_close
#define __NR_ia32_close 6
#endif
#ifndef __NR_ia32_copy_file_range
#define __NR_ia32_copy_file_range 377
#endif 
#ifndef __NR_ia32_creat
#define __NR_ia32_creat 8
#endif
#ifndef __NR_ia32_delete_module
#define __NR_ia32_delete_module 129
#endif
#ifndef __NR_ia32_dup
#define __NR_ia32_dup 41
#endif
#ifndef __NR_ia32_dup2
#define __NR_ia32_dup2 63
#endif
#ifndef __NR_ia32_dup3
#define __NR_ia32_dup3 330
#endif
#ifndef __NR_ia32_epoll_create
#define __NR_ia32_epoll_create 254
#endif
#ifndef __NR_ia32_epoll_create1
#define __NR_ia32_epoll_create1 329
#endif
#ifndef __NR_ia32_epoll_ctl
#define __NR_ia32_epoll_ctl 255
#endif
#ifndef __NR_ia32_epoll_pwait
#define __NR_ia32_epoll_pwait 319
#endif
#ifndef __NR_ia32_epoll_wait
#define __NR_ia32_epoll_wait 256
#endif
#ifndef __NR_ia32_eventfd
#define __NR_ia32_eventfd 323
#endif
#ifndef __NR_ia32_eventfd2
#define __NR_ia32_eventfd2 328
#endif
#ifndef __NR_ia32_execve
#define __NR_ia32_execve 11
#endif
#ifndef __NR_ia32_execveat
#define __NR_ia32_execveat 358
#endif 
#ifndef __NR_ia32_exit
#define __NR_ia32_exit 1
#endif
#ifndef __NR_ia32_exit_group
#define __NR_ia32_exit_group 252
#endif
#ifndef __NR_ia32_faccessat
#define __NR_ia32_faccessat 307
#endif
#ifndef __NR_ia32_fadvise64
#define __NR_ia32_fadvise64 250
#endif
#ifndef __NR_ia32_fadvise64_64
#define __NR_ia32_fadvise64_64 272
#endif
#ifndef __NR_ia32_fallocate
#define __NR_ia32_fallocate 324
#endif
#ifndef __NR_ia32_fanotify_init
#define __NR_ia32_fanotify_init 338
#endif
#ifndef __NR_ia32_fanotify_mark
#define __NR_ia32_fanotify_mark 339
#endif
#ifndef __NR_ia32_fchdir
#define __NR_ia32_fchdir 133
#endif
#ifndef __NR_ia32_fchmod
#define __NR_ia32_fchmod 94
#endif 
#ifndef __NR_ia32_fchmodat
#define __NR_ia32_fchmodat 306
#endif
#ifndef __NR_ia32_fchown
#define __NR_ia32_fchown 95
#endif
#ifndef __NR_ia32_fchown32
#define __NR_ia32_fchown32 207
#endif
#ifndef __NR_ia32_fchownat
#define __NR_ia32_fchownat 298
#endif
#ifndef __NR_ia32_fcntl
#define __NR_ia32_fcntl 55
#endif
#ifndef __NR_ia32_fcntl64
#define __NR_ia32_fcntl64 221
#endif
#ifndef __NR_ia32_fgetxattr
#define __NR_ia32_fgetxattr 231
#endif
#ifndef __NR_ia32_finit_module
#define __NR_ia32_finit_module 350
#endif
#ifndef __NR_ia32_flistxattr
#define __NR_ia32_flistxattr 234
#endif
#ifndef __NR_ia32_flock
#define __NR_ia32_flock 143
#endif
#ifndef __NR_ia32_fork
#define __NR_ia32_fork 2
#endif
#ifndef __NR_ia32_fremovexattr
#define __NR_ia32_fremovexattr 237
#endif
#ifndef __NR_ia32_fsetxattr
#define __NR_ia32_fsetxattr 228
#endif
#ifndef __NR_ia32_fstat
#define __NR_ia32_fstat 108
#endif
#ifndef __NR_ia32_fstat64
#define __NR_ia32_fstat64 197
#endif
#ifndef __NR_ia32_ftruncate
#define __NR_ia32_ftruncate 93
#endif
#ifndef __NR_ia32_futimesat
#define __NR_ia32_futimesat 299
#endif
#ifndef __NR_ia32_futex
#define __NR_ia32_futex 240
#endif
#ifndef __NR_ia32_get_mempolicy
#define __NR_ia32_get_mempolicy 275
#endif
#ifndef __NR_ia32_get_robust_list
#define __NR_ia32_get_robust_list 311
#endif
#ifndef __NR_ia32_getcpu
#define __NR_ia32_getcpu 318
#endif
#ifndef __NR_ia32_getdents
#define __NR_ia32_getdents 141
#endif
#ifndef __NR_ia32_getdents64
#define __NR_ia32_getdents64 220
#endif  
#ifndef __NR_ia32_getgroups
#define __NR_ia32_getgroups 80
#endif
#ifndef __NR_ia32_getgroups32
#define __NR_ia32_getgroups32 205
#endif
#ifndef __NR_ia32_getitimer
#define __NR_ia32_getitimer 105
#endif
#ifndef __NR_ia32_getpgid
#define __NR_ia32_getpgid 132
#endif
#ifndef __NR_ia32_getpgrp
#define __NR_ia32_getpgrp 65
#endif
#ifndef __NR_ia32_getpid
#define __NR_ia32_getpid 20 
#endif
#ifndef __NR_ia32_getppid
#define __NR_ia32_getppid 64
#endif
#ifndef __NR_ia32_getpriority
#define __NR_ia32_getpriority 96
#endif
#ifndef __NR_ia32_getrandom
#define __NR_ia32_getrandom 355
#endif 
#ifndef __NR_ia32_getrlimit
#define __NR_ia32_getrlimit 76
#endif
#ifndef __NR_ia32_getrusage
#define __NR_ia32_getrusage 77
#endif 
#ifndef __NR_ia32_getsid
#define __NR_ia32_getsid 147
#endif
#ifndef __NR_ia32_gettid
#define __NR_ia32_gettid 224
#endif
#ifndef __NR_ia32_gettimeofday
#define __NR_ia32_gettimeofday 78
#endif
#ifndef __NR_ia32_init_module
#define __NR_ia32_init_module 128
#endif
#ifndef __NR_ia32_inotify_add_watch
#define __NR_ia32_inotify_add_watch 292
#endif
#ifndef __NR_ia32_inotify_init
#define __NR_ia32_inotify_init 291
#endif
#ifndef __NR_ia32_inotify_init1
#define __NR_ia32_inotify_init1 332
#endif
#ifndef __NR_ia32_inotify_rm_watch
#define __NR_ia32_inotify_rm_watch 293
#endif
#ifndef __NR_ia32_io_cancel
#define __NR_ia32_io_cancel 249
#endif
#ifndef __NR_ia32_io_destroy
#define __NR_ia32_io_destroy 246
#endif
#ifndef __NR_ia32_io_getevents
#define __NR_ia32_io_getevents 247
#endif
#ifndef __NR_ia32_io_setup
#define __NR_ia32_io_setup 245
#endif
#ifndef __NR_ia32_io_submit
#define __NR_ia32_io_submit 248
#endif
#ifndef __NR_ia32_ioctl
#define __NR_ia32_ioctl 54
#endif
#ifndef __NR_ia32_ioperm
#define __NR_ia32_ioperm 101
#endif
#ifndef __NR_ia32_ioprio_get
#define __NR_ia32_ioprio_get 290
#endif
#ifndef __NR_ia32_ioprio_set
#define __NR_ia32_ioprio_set 289
#endif
#ifndef __NR_ia32_ipc
#define __NR_ia32_ipc 117
#endif
#ifndef __NR_ia32_kcmp
#define __NR_ia32_kcmp 349 
#endif
#ifndef __NR_ia32_kexec_file_load
// x86_64 doesn't have kexec_file_load for 32-bit, just use
// __NR_syscall_compat_max for __NR_ia32_kexec_file_load
#define __NR_ia32_kexec_file_load (__NR_syscall_compat_max + 1)
#endif
#ifndef __NR_ia32_kexec_load
#define __NR_ia32_kexec_load 283
#endif
#ifndef __NR_ia32_keyctl
#define __NR_ia32_keyctl 288
#endif
#ifndef __NR_ia32_kill
#define __NR_ia32_kill 37
#endif
#ifndef __NR_ia32_lchown
#define __NR_ia32_lchown 16
#endif
#ifndef __NR_ia32_lchown32
#define __NR_ia32_lchown32 198
#endif
#ifndef __NR_ia32_lgetxattr
#define __NR_ia32_lgetxattr 230
#endif
#ifndef __NR_ia32_link
#define __NR_ia32_link 9
#endif
#ifndef __NR_ia32_linkat
#define __NR_ia32_linkat 303
#endif
#ifndef __NR_ia32_llistxattr
#define __NR_ia32_llistxattr 233
#endif
#ifndef __NR_ia32_lookup_dcookie
#define __NR_ia32_lookup_dcookie 253
#endif
#ifndef __NR_ia32_lremovexattr
#define __NR_ia32_lremovexattr 236
#endif
#ifndef __NR_ia32_lseek
#define __NR_ia32_lseek 19
#endif
#ifndef __NR_ia32_lsetxattr
#define __NR_ia32_lsetxattr 227
#endif
#ifndef __NR_ia32_madvise
#define __NR_ia32_madvise 219
#endif
#ifndef __NR_ia32_membarrier
#define __NR_ia32_membarrier 375
#endif
#ifndef __NR_ia32_memfd_create
#define __NR_ia32_memfd_create 356
#endif
#ifndef __NR_ia32_mincore
#define __NR_ia32_mincore 218
#endif
#ifndef __NR_ia32_mkdir
#define __NR_ia32_mkdir 39
#endif
#ifndef __NR_ia32_mkdirat
#define __NR_ia32_mkdirat 296
#endif
#ifndef __NR_ia32_mknod
#define __NR_ia32_mknod 14
#endif
#ifndef __NR_ia32_mknodat
#define __NR_ia32_mknodat 297
#endif
#ifndef __NR_ia32_mlock
#define __NR_ia32_mlock 150
#endif
#ifndef __NR_ia32_mlock2
#define __NR_ia32_mlock2 376
#endif
#ifndef __NR_ia32_mlockall
#define __NR_ia32_mlockall 152
#endif
#ifndef __NR_ia32_mmap2
#define __NR_ia32_mmap2 192
#endif
#ifndef __NR_ia32_modify_ldt
#define __NR_ia32_modify_ldt 123
#endif
#ifndef __NR_ia32_mount
#define __NR_ia32_mount 21
#endif
#ifndef __NR_ia32_mprotect
#define __NR_ia32_mprotect 125
#endif 
#ifndef __NR_ia32_mq_getsetattr
#define __NR_ia32_mq_getsetattr 282
#endif
#ifndef __NR_ia32_mq_notify
#define __NR_ia32_mq_notify 281
#endif
#ifndef __NR_ia32_mq_open
#define __NR_ia32_mq_open 277
#endif
#ifndef __NR_ia32_mq_timedreceive
#define __NR_ia32_mq_timedreceive 280
#endif
#ifndef __NR_ia32_mq_timedsend
#define __NR_ia32_mq_timedsend 279
#endif
#ifndef __NR_ia32_mq_unlink
#define __NR_ia32_mq_unlink 278
#endif
#ifndef __NR_ia32_mremap
#define __NR_ia32_mremap 163
#endif
#ifndef __NR_ia32_msync
#define __NR_ia32_msync 144
#endif
#ifndef __NR_ia32_munlock
#define __NR_ia32_munlock 151
#endif 
#ifndef __NR_ia32_munlockall
#define __NR_ia32_munlockall 153
#endif 
#ifndef __NR_ia32_munmap
#define __NR_ia32_munmap 91
#endif
#ifndef __NR_ia32_name_to_handle_at
#define __NR_ia32_name_to_handle_at 341
#endif
#ifndef __NR_ia32_nanosleep
#define __NR_ia32_nanosleep 162
#endif
#ifndef __NR_ia32_nfsservctl
#define __NR_ia32_nfsservctl 169
#endif
#ifndef __NR_ia32_nice
#define __NR_ia32_nice 34
#endif
#ifndef __NR_ia32_open
#define __NR_ia32_open 5
#endif
#ifndef __NR_ia32_open_by_handle_at
#define __NR_ia32_open_by_handle_at 342
#endif
#ifndef __NR_ia32_openat
#define __NR_ia32_openat 295
#endif
#ifndef __NR_ia32_pause
#define __NR_ia32_pause 29
#endif
#ifndef __NR_ia32_perf_event_open
#define __NR_ia32_perf_event_open 336
#endif
#ifndef __NR_ia32_personality
#define __NR_ia32_personality 136
#endif
#ifndef __NR_ia32_pipe
#define __NR_ia32_pipe 42
#endif
#ifndef __NR_ia32_pipe2
#define __NR_ia32_pipe2 331
#endif
#ifndef __NR_ia32_pivot_root
#define __NR_ia32_pivot_root 217
#endif
#ifndef __NR_ia32_poll
#define __NR_ia32_poll 168
#endif
#ifndef __NR_ia32_ppoll
#define __NR_ia32_ppoll 309
#endif
#ifndef __NR_ia32_prctl
#define __NR_ia32_prctl 172
#endif
#ifndef __NR_ia32_pread64
#define __NR_ia32_pread64 180
#endif
#ifndef __NR_ia32_preadv
#define __NR_ia32_preadv 333
#endif
#ifndef __NR_ia32_preadv2
#define __NR_ia32_preadv2 378
#endif
#ifndef __NR_ia32_prlimit64
#define __NR_ia32_prlimit64 340
#endif
#ifndef __NR_ia32_process_vm_readv
#define __NR_ia32_process_vm_readv 347
#endif
#ifndef __NR_ia32_process_vm_writev
#define __NR_ia32_process_vm_writev 348
#endif
#ifndef __NR_ia32_pselect6
#define __NR_ia32_pselect6 308
#endif
#ifndef __NR_ia32_pselect7
// Since a kernel that had a pselect7 syscall can't be found, just use
// __NR_syscall_compat_max for __NR_ia32_pselect7.
#define __NR_ia32_pselect7 (__NR_syscall_compat_max + 1)
#endif
#ifndef __NR_ia32_ptrace
#define __NR_ia32_ptrace 26
#endif
#ifndef __NR_ia32_pwrite64
#define __NR_ia32_pwrite64 181
#endif
#ifndef __NR_ia32_pwritev
#define __NR_ia32_pwritev 334
#endif
#ifndef __NR_ia32_pwritev2
#define __NR_ia32_pwritev2 379
#endif
#ifndef __NR_ia32_quotactl
#define __NR_ia32_quotactl 131
#endif
#ifndef __NR_ia32_read
#define __NR_ia32_read 3
#endif
#ifndef __NR_ia32_readdir
#define __NR_ia32_readdir 89
#endif
#ifndef __NR_ia32_readlink
#define __NR_ia32_readlink 85 
#endif
#ifndef __NR_ia32_readlinkat
#define __NR_ia32_readlinkat 305
#endif
#ifndef __NR_ia32_readv
#define __NR_ia32_readv 145
#endif
#ifndef __NR_ia32_reboot
#define __NR_ia32_reboot 88
#endif
#ifndef __NR_ia32_recvmmsg
#define __NR_ia32_recvmmsg 337
#endif
#ifndef __NR_ia32_remap_file_pages
#define __NR_ia32_remap_file_pages 257
#endif
#ifndef __NR_ia32_rename
#define __NR_ia32_rename 38
#endif
#ifndef __NR_ia32_renameat
#define __NR_ia32_renameat 302
#endif
#ifndef __NR_ia32_renameat2
#define __NR_ia32_renameat2 353
#endif
#ifndef __NR_ia32_request_key
#define __NR_ia32_request_key 287
#endif
#ifndef __NR_ia32_restart_syscall
#define __NR_ia32_restart_syscall 0
#endif
#ifndef __NR_ia32_rmdir
#define __NR_ia32_rmdir 40
#endif
#ifndef __NR_ia32_rt_sigaction
#define __NR_ia32_rt_sigaction 174
#endif
#ifndef __NR_ia32_rt_sigpending
#define __NR_ia32_rt_sigpending 176
#endif
#ifndef __NR_ia32_rt_sigprocmask
#define __NR_ia32_rt_sigprocmask 175
#endif
#ifndef __NR_ia32_rt_sigqueueinfo
#define __NR_ia32_rt_sigqueueinfo 178
#endif
#ifndef __NR_ia32_rt_sigsuspend
#define __NR_ia32_rt_sigsuspend 179
#endif
#ifndef __NR_ia32_rt_sigtimedwait
#define __NR_ia32_rt_sigtimedwait 177
#endif
#ifndef __NR_ia32_rt_tgsigqueueinfo
#define __NR_ia32_rt_tgsigqueueinfo 335
#endif
#ifndef __NR_ia32_sendmmsg
#define __NR_ia32_sendmmsg 345
#endif
#ifndef __NR_ia32_set_mempolicy
#define __NR_ia32_set_mempolicy 276
#endif
#ifndef __NR_ia32_set_robust_list
#define __NR_ia32_set_robust_list 312
#endif
#ifndef __NR_ia32_setdomainname
#define __NR_ia32_setdomainname 121
#endif
#ifndef __NR_ia32_setfsgid32
#define __NR_ia32_setfsgid32 216
#endif
#ifndef __NR_ia32_setfsuid32
#define __NR_ia32_setfsuid32 215
#endif
#ifndef __NR_ia32_setgid32
#define __NR_ia32_setgid32 214
#endif
#ifndef __NR_ia32_sethostname
#define __NR_ia32_sethostname 74
#endif
#ifndef __NR_ia32_setitimer
#define __NR_ia32_setitimer 104
#endif
#ifndef __NR_ia32_setpgid
#define __NR_ia32_setpgid 57
#endif
#ifndef __NR_ia32_setresgid32
#define __NR_ia32_setresgid32 210
#endif
#ifndef __NR_ia32_setresuid32
#define __NR_ia32_setresuid32 208
#endif
#ifndef __NR_ia32_setregid32
#define __NR_ia32_setregid32 204
#endif
#ifndef __NR_ia32_setreuid32
#define __NR_ia32_setreuid32 203
#endif
#ifndef __NR_ia32_setrlimit
#define __NR_ia32_setrlimit 75
#endif
#ifndef __NR_ia32_settimeofday
#define __NR_ia32_settimeofday 79
#endif
#ifndef __NR_ia32_setuid32
#define __NR_ia32_setuid32 213
#endif
// Since a kernel that had a 32-bit shmctl syscall can't be found
// (they all used __NR_ipc), just use __NR_syscall_compat_max.
#ifndef __NR_ia32_shmctl
#define __NR_ia32_shmctl (__NR_syscall_compat_max + 1)
#endif
#ifndef __NR_ia32_socketcall
#define __NR_ia32_socketcall 102
#endif
#ifndef __NR_ia32_stime
#define __NR_ia32_stime 25
#endif
#ifndef __NR_ia32_symlink
#define __NR_ia32_symlink 83
#endif
#ifndef __NR_ia32_symlinkat
#define __NR_ia32_symlinkat 304
#endif
#ifndef __NR_ia32_time
#define __NR_ia32_time 13
#endif
#ifndef __NR_ia32_truncate
#define __NR_ia32_truncate 92
#endif
#ifndef __NR_ia32_ugetrlimit
#define __NR_ia32_ugetrlimit 191
#endif 
#ifndef __NR_ia32_umount
#define __NR_ia32_umount 22
#endif
#ifndef __NR_ia32_umount2
#define __NR_ia32_umount2 52
#endif
#ifndef __NR_ia32_uname
#define __NR_ia32_uname 109
#endif
#ifndef __NR_ia32_utime
#define __NR_ia32_utime 30 
#endif
#ifndef __NR_ia32_utimensat
#define __NR_ia32_utimensat 320
#endif 
#ifndef __NR_ia32_utimes
#define __NR_ia32_utimes 271
#endif 
#ifndef __NR_ia32_wait4
#define __NR_ia32_wait4 114
#endif
#ifndef __NR_ia32_write
#define __NR_ia32_write 4
#endif

#define __NR_compat__llseek		__NR_ia32__llseek
#define __NR_compat__newselect		__NR_ia32__newselect
#define __NR_compat_access		__NR_ia32_access
#define __NR_compat_acct		__NR_ia32_acct
#define __NR_compat_add_key		__NR_ia32_add_key
#define __NR_compat_adjtimex		__NR_ia32_adjtimex
#define __NR_compat_alarm		__NR_ia32_alarm
#define __NR_compat_brk			__NR_ia32_brk
#define __NR_compat_bpf			__NR_ia32_bpf
#define __NR_compat_capget		__NR_ia32_capget
#define __NR_compat_capset		__NR_ia32_capset
#define __NR_compat_chdir		__NR_ia32_chdir
#define __NR_compat_chmod		__NR_ia32_chmod
#define __NR_compat_chown		__NR_ia32_chown
#define __NR_compat_chown32		__NR_ia32_chown32
#define __NR_compat_chroot		__NR_ia32_chroot
#define __NR_compat_clock_adjtime	__NR_ia32_clock_adjtime
#define __NR_compat_clock_gettime	__NR_ia32_clock_gettime
#define __NR_compat_clock_getres	__NR_ia32_clock_getres
#define __NR_compat_clock_nanosleep	__NR_ia32_clock_nanosleep
#define __NR_compat_clock_settime	__NR_ia32_clock_settime
#define __NR_compat_clone		__NR_ia32_clone
#define __NR_compat_close		__NR_ia32_close
#define __NR_compat_copy_file_range	__NR_ia32_copy_file_range
#define __NR_compat_creat		__NR_ia32_creat
#define __NR_compat_delete_module	__NR_ia32_delete_module
#define __NR_compat_dup			__NR_ia32_dup
#define __NR_compat_dup2		__NR_ia32_dup2
#define __NR_compat_dup3		__NR_ia32_dup3
#define __NR_compat_epoll_create	__NR_ia32_epoll_create
#define __NR_compat_epoll_create1	__NR_ia32_epoll_create1
#define __NR_compat_epoll_ctl		__NR_ia32_epoll_ctl
#define __NR_compat_epoll_pwait		__NR_ia32_epoll_pwait
#define __NR_compat_epoll_wait		__NR_ia32_epoll_wait
#define __NR_compat_eventfd		__NR_ia32_eventfd
#define __NR_compat_eventfd2		__NR_ia32_eventfd2
#define __NR_compat_execve		__NR_ia32_execve
#define __NR_compat_execveat		__NR_ia32_execveat
#define __NR_compat_exit		__NR_ia32_exit
#define __NR_compat_exit_group		__NR_ia32_exit_group
#define __NR_compat_faccessat		__NR_ia32_faccessat
#define __NR_compat_fanotify_init	__NR_ia32_fanotify_init
#define __NR_compat_fanotify_mark	__NR_ia32_fanotify_mark
#define __NR_compat_fchdir		__NR_ia32_fchdir
#define __NR_compat_fchmod		__NR_ia32_fchmod
#define __NR_compat_fchmodat		__NR_ia32_fchmodat
#define __NR_compat_fchown		__NR_ia32_fchown
#define __NR_compat_fchown32		__NR_ia32_fchown32
#define __NR_compat_fchownat		__NR_ia32_fchownat
#define __NR_compat_fcntl		__NR_ia32_fcntl
#define __NR_compat_fcntl64		__NR_ia32_fcntl64
#define __NR_compat_fgetxattr		__NR_ia32_fgetxattr
#define __NR_compat_finit_module	__NR_ia32_finit_module
#define __NR_compat_flistxattr		__NR_ia32_flistxattr
#define __NR_compat_flock		__NR_ia32_flock
#define __NR_compat_fork		__NR_ia32_fork
#define __NR_compat_fremovexattr	__NR_ia32_fremovexattr
#define __NR_compat_fsetxattr		__NR_ia32_fsetxattr
#define __NR_compat_fstat		__NR_ia32_fstat
#define __NR_compat_fstat64		__NR_ia32_fstat64
#define __NR_compat_ftruncate		__NR_ia32_ftruncate
#define __NR_compat_futimesat		__NR_ia32_futimesat
#define __NR_compat_futex		__NR_ia32_futex
#define __NR_compat_get_mempolicy	__NR_ia32_get_mempolicy
#define __NR_compat_get_robust_list	__NR_ia32_get_robust_list
#define __NR_compat_getcpu		__NR_ia32_getcpu
#define __NR_compat_getdents		__NR_ia32_getdents
#define __NR_compat_getdents64		__NR_ia32_getdents64
#define __NR_compat_getgroups		__NR_ia32_getgroups
#define __NR_compat_getgroups32		__NR_ia32_getgroups32
#define __NR_compat_getitimer		__NR_ia32_getitimer
#define __NR_compat_getpgid		__NR_ia32_getpgid
#define __NR_compat_getpgrp		__NR_ia32_getpgrp
#define __NR_compat_getpid		__NR_ia32_getpid
#define __NR_compat_getppid		__NR_ia32_getppid
#define __NR_compat_getpriority		__NR_ia32_getpriority
#define __NR_compat_getrandom		__NR_ia32_getrandom
#define __NR_compat_getrlimit		__NR_ia32_getrlimit
#define __NR_compat_getrusage		__NR_ia32_getrusage
#define __NR_compat_getsid		__NR_ia32_getsid
#define __NR_compat_gettid		__NR_ia32_gettid
#define __NR_compat_gettimeofday	__NR_ia32_gettimeofday
#define __NR_compat_init_module		__NR_ia32_init_module
#define __NR_compat_inotify_add_watch	__NR_ia32_inotify_add_watch
#define __NR_compat_inotify_init	__NR_ia32_inotify_init
#define __NR_compat_inotify_init1	__NR_ia32_inotify_init1
#define __NR_compat_inotify_rm_watch	__NR_ia32_inotify_rm_watch
#define __NR_compat_io_cancel		__NR_ia32_io_cancel
#define __NR_compat_io_destroy		__NR_ia32_io_destroy
#define __NR_compat_io_getevents	__NR_ia32_io_getevents
#define __NR_compat_io_setup		__NR_ia32_io_setup
#define __NR_compat_io_submit		__NR_ia32_io_submit
#define __NR_compat_ioctl		__NR_ia32_ioctl
#define __NR_compat_ioperm		__NR_ia32_ioperm
#define __NR_compat_ioprio_get		__NR_ia32_ioprio_get
#define __NR_compat_ioprio_set		__NR_ia32_ioprio_set
#define __NR_compat_ipc			__NR_ia32_ipc
#define __NR_compat_kcmp		__NR_ia32_kcmp
#define __NR_compat_kexec_file_load	__NR_ia32_kexec_file_load
#define __NR_compat_kexec_load		__NR_ia32_kexec_load
#define __NR_compat_keyctl		__NR_ia32_keyctl
#define __NR_compat_kill		__NR_ia32_kill
#define __NR_compat_lchown		__NR_ia32_lchown
#define __NR_compat_lchown32		__NR_ia32_lchown32
#define __NR_compat_lgetxattr		__NR_ia32_lgetxattr
#define __NR_compat_link		__NR_ia32_link
#define __NR_compat_linkat		__NR_ia32_linkat
#define __NR_compat_llistxattr		__NR_ia32_llistxattr
#define __NR_compat_lremovexattr	__NR_ia32_lremovexattr
#define __NR_compat_lseek		__NR_ia32_lseek
#define __NR_compat_lsetxattr		__NR_ia32_lsetxattr
#define __NR_compat_madvise		__NR_ia32_madvise
#define __NR_compat_membarrier		__NR_ia32_membarrier
#define __NR_compat_memfd_create	__NR_ia32_memfd_create
#define __NR_compat_mincore		__NR_ia32_mincore
#define __NR_compat_mkdir		__NR_ia32_mkdir
#define __NR_compat_mkdirat		__NR_ia32_mkdirat
#define __NR_compat_mknod		__NR_ia32_mknod
#define __NR_compat_mknodat		__NR_ia32_mknodat
#define __NR_compat_mlock		__NR_ia32_mlock
#define __NR_compat_mlock2		__NR_ia32_mlock2
#define __NR_compat_mlockall		__NR_ia32_mlockall
#define __NR_compat_mmap2		__NR_ia32_mmap2
#define __NR_compat_modify_ldt		__NR_ia32_modify_ldt
#define __NR_compat_mount		__NR_ia32_mount
#define __NR_compat_mprotect		__NR_ia32_mprotect
#define __NR_compat_mq_getsetattr	__NR_ia32_mq_getsetattr
#define __NR_compat_mq_notify		__NR_ia32_mq_notify
#define __NR_compat_mq_open		__NR_ia32_mq_open
#define __NR_compat_mq_timedreceive	__NR_ia32_mq_timedreceive
#define __NR_compat_mq_timedsend	__NR_ia32_mq_timedsend
#define __NR_compat_mq_unlink		__NR_ia32_mq_unlink
#define __NR_compat_mremap		__NR_ia32_mremap
#define __NR_compat_msync		__NR_ia32_msync
#define __NR_compat_munlock		__NR_ia32_munlock
#define __NR_compat_munlockall		__NR_ia32_munlockall
#define __NR_compat_munmap		__NR_ia32_munmap
#define __NR_compat_name_to_handle_at	__NR_ia32_name_to_handle_at
#define __NR_compat_nanosleep		__NR_ia32_nanosleep
#define __NR_compat_nfsservctl		__NR_ia32_nfsservctl
#define __NR_compat_nice		__NR_ia32_nice
#define __NR_compat_open		__NR_ia32_open
#define __NR_compat_open_by_handle_at	__NR_ia32_open_by_handle_at
#define __NR_compat_openat		__NR_ia32_openat
#define __NR_compat_pause		__NR_ia32_pause
#define __NR_compat_perf_event_open	__NR_ia32_perf_event_open
#define __NR_compat_personality		__NR_ia32_personality
#define __NR_compat_pipe		__NR_ia32_pipe
#define __NR_compat_pipe2		__NR_ia32_pipe2
#define __NR_compat_pivot_root		__NR_ia32_pivot_root
#define __NR_compat_poll		__NR_ia32_poll
#define __NR_compat_ppoll		__NR_ia32_ppoll
#define __NR_compat_prctl		__NR_ia32_prctl
#define __NR_compat_pread64		__NR_ia32_pread64
#define __NR_compat_preadv		__NR_ia32_preadv
#define __NR_compat_preadv2		__NR_ia32_preadv2
#define __NR_compat_prlimit64		__NR_ia32_prlimit64
#define __NR_compat_process_vm_readv	__NR_ia32_process_vm_readv
#define __NR_compat_process_vm_writev	__NR_ia32_process_vm_writev
#define __NR_compat_pselect6		__NR_ia32_pselect6
#define __NR_compat_pselect7		__NR_ia32_pselect7
#define __NR_compat_ptrace		__NR_ia32_ptrace
#define __NR_compat_pwrite64		__NR_ia32_pwrite64
#define __NR_compat_pwritev		__NR_ia32_pwritev
#define __NR_compat_pwritev2		__NR_ia32_pwritev2
#define __NR_compat_quotactl		__NR_ia32_quotactl
#define __NR_compat_read		__NR_ia32_read
#define __NR_compat_readdir		__NR_ia32_readdir
#define __NR_compat_readlink		__NR_ia32_readlink
#define __NR_compat_readlinkat		__NR_ia32_readlinkat
#define __NR_compat_readv		__NR_ia32_readv
#define __NR_compat_reboot		__NR_ia32_reboot
#define __NR_compat_recvmmsg		__NR_ia32_recvmmsg
#define __NR_compat_remap_file_pages	__NR_ia32_remap_file_pages
#define __NR_compat_rename		__NR_ia32_rename
#define __NR_compat_renameat		__NR_ia32_renameat
#define __NR_compat_renameat2		__NR_ia32_renameat2
#define __NR_compat_request_key		__NR_ia32_request_key
#define __NR_compat_restart_syscall	__NR_ia32_restart_syscall
#define __NR_compat_rmdir		__NR_ia32_rmdir
#define __NR_compat_rt_sigaction	__NR_ia32_rt_sigaction
#define __NR_compat_rt_sigpending	__NR_ia32_rt_sigpending
#define __NR_compat_rt_sigprocmask	__NR_ia32_rt_sigprocmask
#define __NR_compat_rt_sigqueueinfo	__NR_ia32_rt_sigqueueinfo
#define __NR_compat_rt_sigsuspend	__NR_ia32_rt_sigsuspend
#define __NR_compat_rt_sigtimedwait	__NR_ia32_rt_sigtimedwait
#define __NR_compat_rt_tgsigqueueinfo	__NR_ia32_rt_tgsigqueueinfo
#define __NR_compat_sendmmsg		__NR_ia32_sendmmsg
#define __NR_compat_set_mempolicy	__NR_ia32_set_mempolicy
#define __NR_compat_set_robust_list	__NR_ia32_set_robust_list
#define __NR_compat_setdomainname	__NR_ia32_setdomainname
#define __NR_compat_sethostname		__NR_ia32_sethostname
#define __NR_compat_setitimer		__NR_ia32_setitimer
#define __NR_compat_setpgid		__NR_ia32_setpgid
#define __NR_compat_setrlimit		__NR_ia32_setrlimit
#define __NR_compat_settimeofday	__NR_ia32_settimeofday
#define __NR_compat_shmctl		__NR_ia32_shmctl
#define __NR_compat_socketcall		__NR_ia32_socketcall
#define __NR_compat_stime		__NR_ia32_stime
#define __NR_compat_symlink		__NR_ia32_symlink
#define __NR_compat_symlinkat		__NR_ia32_symlinkat
#define __NR_compat_time		__NR_ia32_time
#define __NR_compat_truncate		__NR_ia32_truncate
#define __NR_compat_ugetrlimit		__NR_ia32_ugetrlimit
#define __NR_compat_umount		__NR_ia32_umount
#define __NR_compat_umount2		__NR_ia32_umount2
#define __NR_compat_uname		__NR_ia32_uname
#define __NR_compat_utime		__NR_ia32_utime
#define __NR_compat_utimensat		__NR_ia32_utimensat
#define __NR_compat_utimes		__NR_ia32_utimes
#define __NR_compat_wait4		__NR_ia32_wait4
#define __NR_compat_write		__NR_ia32_write

#endif	/* __x86_64__ */

#if defined(__powerpc64__) || defined (__s390x__) || defined(__aarch64__)

// On the ppc64 and s390x, the 32-bit syscalls use the same number
// as the 64-bit syscalls.
//
// On arm64, the 32-bit syscall *can* use different numbers than the
// 64-bit syscalls, but the majority do not. The following syscalls
// use the same number.

#define __NR_compat__llseek		__NR__llseek
#define __NR_compat__newselect		__NR__newselect
#define __NR_compat_access		__NR_access
#define __NR_compat_acct		__NR_acct
#define __NR_compat_add_key		__NR_add_key
#define __NR_compat_adjtimex		__NR_adjtimex
#define __NR_compat_alarm		__NR_alarm
#define __NR_compat_brk			__NR_brk
#define __NR_compat_bpf			__NR_bpf
#define __NR_compat_capget		__NR_capget
#define __NR_compat_capset		__NR_capset
#define __NR_compat_chdir		__NR_chdir
#define __NR_compat_chmod		__NR_chmod
#define __NR_compat_chown		__NR_chown
#define __NR_compat_chown32		__NR_chown32
#define __NR_compat_chroot		__NR_chroot
#define __NR_compat_clock_adjtime	__NR_clock_adjtime
#define __NR_compat_clock_gettime	__NR_clock_gettime
#define __NR_compat_clock_getres	__NR_clock_getres
#define __NR_compat_clock_nanosleep	__NR_clock_nanosleep
#define __NR_compat_clock_settime	__NR_clock_settime
#define __NR_compat_clone		__NR_clone
#define __NR_compat_close		__NR_close
#define __NR_compat_copy_file_range	__NR_copy_file_range
#define __NR_compat_creat		__NR_creat
#define __NR_compat_delete_module	__NR_delete_module
#define __NR_compat_dup			__NR_dup
#define __NR_compat_dup2		__NR_dup2
#define __NR_compat_dup3		__NR_dup3
#define __NR_compat_epoll_create	__NR_epoll_create
#define __NR_compat_epoll_create1	__NR_epoll_create1
#define __NR_compat_epoll_ctl		__NR_epoll_ctl
#define __NR_compat_epoll_pwait		__NR_epoll_pwait
#define __NR_compat_epoll_wait		__NR_epoll_wait
#define __NR_compat_eventfd		__NR_eventfd
#define __NR_compat_eventfd2		__NR_eventfd2
#define __NR_compat_execve		__NR_execve
#define __NR_compat_execveat		__NR_execveat
#define __NR_compat_exit		__NR_exit
#define __NR_compat_exit_group		__NR_exit_group
#define __NR_compat_faccessat		__NR_faccessat
#define __NR_compat_fanotify_init	__NR_fanotify_init
#define __NR_compat_fanotify_mark	__NR_fanotify_mark
#define __NR_compat_fchdir		__NR_fchdir
#define __NR_compat_fchmod		__NR_fchmod
#define __NR_compat_fchmodat		__NR_fchmodat
#define __NR_compat_fchown		__NR_fchown
#define __NR_compat_fchown32		__NR_fchown32
#define __NR_compat_fchownat		__NR_fchownat
#define __NR_compat_fcntl		__NR_fcntl
#define __NR_compat_fcntl64		__NR_fcntl64
#define __NR_compat_fgetxattr		__NR_fgetxattr
#define __NR_compat_finit_module	__NR_finit_module
#define __NR_compat_flistxattr		__NR_flistxattr
#define __NR_compat_flock		__NR_flock
#define __NR_compat_fork		__NR_fork
#define __NR_compat_fremovexattr	__NR_fremovexattr
#define __NR_compat_fsetxattr		__NR_fsetxattr
#define __NR_compat_fstat		__NR_fstat
#define __NR_compat_fstat64		__NR_fstat64
#define __NR_compat_ftruncate		__NR_ftruncate
#define __NR_compat_futimesat		__NR_futimesat
#define __NR_compat_futex		__NR_futex
#define __NR_compat_get_mempolicy	__NR_get_mempolicy
#define __NR_compat_get_robust_list	__NR_get_robust_list
#define __NR_compat_getcpu		__NR_getcpu
#define __NR_compat_getdents		__NR_getdents
#define __NR_compat_getdents64		__NR_getdents64
#define __NR_compat_getgroups		__NR_getgroups
#define __NR_compat_getgroups32		__NR_getgroups32
#define __NR_compat_getitimer		__NR_getitimer
#define __NR_compat_getpgid		__NR_getpgid
#define __NR_compat_getpgrp		__NR_getpgrp
#define __NR_compat_getpid		__NR_getpid
#define __NR_compat_getppid		__NR_getppid
#define __NR_compat_getpriority		__NR_getpriority
#define __NR_compat_getrandom		__NR_getrandom
#define __NR_compat_getrlimit		__NR_getrlimit
#define __NR_comapt_getrusage		__NR_getrusage
#define __NR_compat_getsid		__NR_getsid
#define __NR_compat_gettid		__NR_gettid
#define __NR_compat_gettimeofday	__NR_gettimeofday
#define __NR_compat_init_module		__NR_init_module
#define __NR_compat_inotify_add_watch	__NR_inotify_add_watch
#define __NR_compat_inotify_init	__NR_inotify_init
#define __NR_compat_inotify_init1	__NR_inotify_init1
#define __NR_compat_inotify_rm_watch	__NR_inotify_rm_watch
#define __NR_compat_io_cancel		__NR_io_cancel
#define __NR_compat_io_destroy		__NR_io_destroy
#define __NR_compat_io_getevents	__NR_io_getevents
#define __NR_compat_io_setup		__NR_io_setup
#define __NR_compat_io_submit		__NR_io_submit
#define __NR_compat_ioctl		__NR_ioctl
#define __NR_compat_ioperm		__NR_ioperm
#define __NR_compat_ioprio_get		__NR_ioprio_get
#define __NR_compat_ioprio_set		__NR_ioprio_set
#define __NR_compat_ipc			__NR_ipc
#define __NR_compat_kcmp		__NR_kcmp
#define __NR_compat_kexec_file_load	__NR_kexec_file_load
#define __NR_compat_kexec_load		__NR_kexec_load
#define __NR_compat_keyctl		__NT_keyctl
#define __NR_compat_kill		__NR_kill
#define __NR_compat_lgetxattr		__NR_lgetxattr
#define __NR_compat_link		__NR_link
#define __NR_compat_linkat		__NR_linkat
#define __NR_compat_llistxattr		__NR_llistxattr
#define __NR_compat_lremovexattr	__NR_lremovexattr
#define __NR_compat_lseek		__NR_lseek
#define __NR_compat_lsetxattr		__NR_lsetxattr
#define __NR_compat_madvise		__NR_madvise
#define __NR_compat_membarrier		__NR_membarrier
#define __NR_compat_memfd_create	__NR_memfd_create
#define __NR_compat_mincore		__NR_mincore
#define __NR_compat_mkdir		__NR_mkdir
#define __NR_compat_mkdirat		__NR_mkdirat
#define __NR_compat_mknod		__NR_mknod
#define __NR_compat_mknodat		__NR_mknodat
#define __NR_compat_mlock		__NR_mlock
#define __NR_compat_mlock2		__NR_mlock2
#define __NR_compat_mlockall		__NR_mlockall
#define __NR_compat_mmap2		__NR_mmap2
#define __NR_compat_modify_ldt		__NR_modify_ldt
#define __NR_compat_mount		__NR_mount
#define __NR_compat_mprotect		__NR_mprotect
#define __NR_compat_mq_getsetattr	__NR_mq_getsetattr
#define __NR_compat_mq_notify		__NR_mq_notify
#define __NR_compat_mq_open		__NR_mq_open
#define __NR_compat_mq_timedreceive	__NR_mq_timedreceive
#define __NR_compat_mq_timedsend	__NR_mq_timedsend
#define __NR_compat_mq_unlink		__NR_mq_unlink
#define __NR_compat_mremap		__NR_mremap
#define __NR_compat_msync		__NR_msync
#define __NR_copmat_munlock		__NR_munlock
#define __NR_compat_munlockall		__NR_munlockall
#define __NR_compat_munmap		__NR_munmap
#define __NR_compat_name_to_handle_at	__NR_name_to_handle_at
#define __NR_compat_nanosleep		__NR_nanosleep
#define __NR_compat_nfsservctl		__NR_nfsservctl
#define __NR_compat_nice		__NR_nice
#define __NR_compat_open		__NR_open
#define __NR_compat_open_by_handle_at	__NR_open_by_handle_at
#define __NR_compat_openat		__NR_openat
#define __NR_compat_pause		__NR_pause
#define __NR_compat_perf_event_open	__NR_perf_event_open
#define __NR_compat_personality		__NR_personality
#define __NR_compat_pipe		__NR_pipe
#define __NR_compat_pipe2		__NR_pipe2
#define __NR_compat_pivot_root		__NR_pivot_root
#define __NR_compat_poll		__NR_poll
#define __NR_compat_ppoll		__NR_ppoll
#define __NR_compat_prctl		__NR_prctl
#define __NR_compat_pread64		__NR_pread64
#define __NR_compat_preadv		__NR_preadv
#define __NR_compat_preadv2		__NR_preadv2
#define __NR_compat_prlimit64		__NR_prlimit64
#define __NR_compat_process_vm_readv	__NR_process_vm_readv
#define __NR_compat_process_vm_writev	__NR_process_vm_writev
#define __NR_compat_pselect6		__NR_pselect6
#define __NR_compat_pselect7		__NR_pselect7
#define __NR_compat_ptrace		__NR_ptrace
#define __NR_compat_pwrite64		__NR_pwrite64
#define __NR_compat_pwritev		__NR_pwritev
#define __NR_compat_pwritev2		__NR_pwritev2
#define __NR_compat_quotactl		__NR_quoactl
#define __NR_compat_read		__NR_read
#define __NR_compat_readdir		__NR_readdir
#define __NR_compat_readlink		__NR_readlink
#define __NR_compat_readlinkat		__NR_readlinkat
#define __NR_compat_readv		__NR_readv
#define __NR_compat_reboot		__NR_reboot
#define __NR_compat_recvmmsg		__NR_recvmmsg
#define __NR_compat_remap_file_pages	__NR_remap_file_pages
#define __NR_compat_rename		__NR_rename
#define __NR_compat_renameat		__NR_renameat
#define __NR_compat_renameat2		__NR_renameat2
#define __NR_compat_request_key		__NR_request_key
#define __NR_compat_restart_syscall	__NR_restart_syscall
#define __NR_compat_rmdir		__NR_rmdir
#define __NR_compat_rt_sigaction	__NR_rt_sigaction
#define __NR_compat_rt_sigpending	__NR_rt_sigpending
#define __NR_compat_rt_sigprocmask	__NR_rt_sigprocmask
#define __NR_compat_rt_sigqueue		__NR_rt_sigqueue
#define __NR_compat_rt_sigsuspend	__NR_rt_sigsuspend
#define __NR_compat_rt_sigtimedwait	__NR_rt_sigtimedwait
#define __NR_compat_rt_tgsigqueueinfo	__NR_rt_tgsigqueueinfo
#define __NR_compat_sendmmsg		__NR_sendmmsg
#define __NR_compat_set_mempolicy	__NR_set_mempolicy
#define __NR_compat_set_robust_list	__NR_set_robust_list
#define __NR_compat_setdomainname	__NR_setdomainname
#define __NR_compat_sethostname		__NR_sethostname
#define __NR_compat_setitimer		__NR_setitimer
#define __NR_compat_setpgid		__NR_setpgid
#define __NR_compat_setrlimit		__NR_setrlimit
#define __NR_compat_settimeofday	__NR_settimeofday
#define __NR_compat_shmctl		__NR_shmctl
#define __NR_compat_socketcall		__NR_socketcall
#define __NR_compat_stime		__NR_stime
#define __NR_compat_symlink		__NR_symlink
#define __NR_compat_symlinkat		__NR_symlinkat
#define __NR_compat_time		__NR_time
#define __NR_compat_truncate		__NR_truncate
#define __NR_compat_ugetrlimit		__NR_ugetrlimit
#define __NR_comapt_umount		__NR_umount
#define __NR_compat_umount2		__NR_umount2
#define __NR_compat_uname		__NR_uname
#define __NR_compat_utime		__NR_utime
#define __NR_compat_utimensat		__NR_utimensat
#define __NR_compat_utimes		__NR_utimes
#define __NR_compat_wait4		__NR_wait4
#define __NR_compat_write		__NR_write

#endif	/* __powerpc64__ || __s390x__ || __aarch64__ */

#if defined(__ia64__)

// On RHEL5 ia64, __NR_umount2 doesn't exist. So, define it in terms
// of __NR_umount.

#ifndef __NR_umount2
#define __NR_umount2 __NR_umount
#endif

#endif	/* __ia64__ */

#endif /* _COMPAT_UNISTD_H_ */
