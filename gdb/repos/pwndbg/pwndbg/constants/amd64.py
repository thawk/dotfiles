from __future__ import annotations

from .constant import Constant

__NR_read = Constant("__NR_read", 0)
__NR_write = Constant("__NR_write", 1)
__NR_open = Constant("__NR_open", 2)
__NR_close = Constant("__NR_close", 3)
__NR_stat = Constant("__NR_stat", 4)
__NR_fstat = Constant("__NR_fstat", 5)
__NR_lstat = Constant("__NR_lstat", 6)
__NR_poll = Constant("__NR_poll", 7)
__NR_lseek = Constant("__NR_lseek", 8)
__NR_mmap = Constant("__NR_mmap", 9)
__NR_mprotect = Constant("__NR_mprotect", 10)
__NR_munmap = Constant("__NR_munmap", 11)
__NR_brk = Constant("__NR_brk", 12)
__NR_rt_sigaction = Constant("__NR_rt_sigaction", 13)
__NR_rt_sigprocmask = Constant("__NR_rt_sigprocmask", 14)
__NR_rt_sigreturn = Constant("__NR_rt_sigreturn", 15)
__NR_ioctl = Constant("__NR_ioctl", 16)
__NR_pread = Constant("__NR_pread", 17)
__NR_pwrite = Constant("__NR_pwrite", 18)
__NR_readv = Constant("__NR_readv", 19)
__NR_writev = Constant("__NR_writev", 20)
__NR_access = Constant("__NR_access", 21)
__NR_pipe = Constant("__NR_pipe", 22)
__NR_select = Constant("__NR_select", 23)
__NR_sched_yield = Constant("__NR_sched_yield", 24)
__NR_mremap = Constant("__NR_mremap", 25)
__NR_msync = Constant("__NR_msync", 26)
__NR_mincore = Constant("__NR_mincore", 27)
__NR_madvise = Constant("__NR_madvise", 28)
__NR_shmget = Constant("__NR_shmget", 29)
__NR_shmat = Constant("__NR_shmat", 30)
__NR_shmctl = Constant("__NR_shmctl", 31)
__NR_dup = Constant("__NR_dup", 32)
__NR_dup2 = Constant("__NR_dup2", 33)
__NR_pause = Constant("__NR_pause", 34)
__NR_nanosleep = Constant("__NR_nanosleep", 35)
__NR_getitimer = Constant("__NR_getitimer", 36)
__NR_alarm = Constant("__NR_alarm", 37)
__NR_setitimer = Constant("__NR_setitimer", 38)
__NR_getpid = Constant("__NR_getpid", 39)
__NR_sendfile = Constant("__NR_sendfile", 40)
__NR_socket = Constant("__NR_socket", 41)
__NR_connect = Constant("__NR_connect", 42)
__NR_accept = Constant("__NR_accept", 43)
__NR_sendto = Constant("__NR_sendto", 44)
__NR_recvfrom = Constant("__NR_recvfrom", 45)
__NR_sendmsg = Constant("__NR_sendmsg", 46)
__NR_recvmsg = Constant("__NR_recvmsg", 47)
__NR_shutdown = Constant("__NR_shutdown", 48)
__NR_bind = Constant("__NR_bind", 49)
__NR_listen = Constant("__NR_listen", 50)
__NR_getsockname = Constant("__NR_getsockname", 51)
__NR_getpeername = Constant("__NR_getpeername", 52)
__NR_socketpair = Constant("__NR_socketpair", 53)
__NR_setsockopt = Constant("__NR_setsockopt", 54)
__NR_getsockopt = Constant("__NR_getsockopt", 55)
__NR_clone = Constant("__NR_clone", 56)
__NR_fork = Constant("__NR_fork", 57)
__NR_vfork = Constant("__NR_vfork", 58)
__NR_execve = Constant("__NR_execve", 59)
__NR_exit = Constant("__NR_exit", 60)
__NR_wait4 = Constant("__NR_wait4", 61)
__NR_kill = Constant("__NR_kill", 62)
__NR_uname = Constant("__NR_uname", 63)
__NR_semget = Constant("__NR_semget", 64)
__NR_semop = Constant("__NR_semop", 65)
__NR_semctl = Constant("__NR_semctl", 66)
__NR_shmdt = Constant("__NR_shmdt", 67)
__NR_msgget = Constant("__NR_msgget", 68)
__NR_msgsnd = Constant("__NR_msgsnd", 69)
__NR_msgrcv = Constant("__NR_msgrcv", 70)
__NR_msgctl = Constant("__NR_msgctl", 71)
__NR_fcntl = Constant("__NR_fcntl", 72)
__NR_flock = Constant("__NR_flock", 73)
__NR_fsync = Constant("__NR_fsync", 74)
__NR_fdatasync = Constant("__NR_fdatasync", 75)
__NR_truncate = Constant("__NR_truncate", 76)
__NR_ftruncate = Constant("__NR_ftruncate", 77)
__NR_getdents = Constant("__NR_getdents", 78)
__NR_getcwd = Constant("__NR_getcwd", 79)
__NR_chdir = Constant("__NR_chdir", 80)
__NR_fchdir = Constant("__NR_fchdir", 81)
__NR_rename = Constant("__NR_rename", 82)
__NR_mkdir = Constant("__NR_mkdir", 83)
__NR_rmdir = Constant("__NR_rmdir", 84)
__NR_creat = Constant("__NR_creat", 85)
__NR_link = Constant("__NR_link", 86)
__NR_unlink = Constant("__NR_unlink", 87)
__NR_symlink = Constant("__NR_symlink", 88)
__NR_readlink = Constant("__NR_readlink", 89)
__NR_chmod = Constant("__NR_chmod", 90)
__NR_fchmod = Constant("__NR_fchmod", 91)
__NR_chown = Constant("__NR_chown", 92)
__NR_fchown = Constant("__NR_fchown", 93)
__NR_lchown = Constant("__NR_lchown", 94)
__NR_umask = Constant("__NR_umask", 95)
__NR_gettimeofday = Constant("__NR_gettimeofday", 96)
__NR_getrlimit = Constant("__NR_getrlimit", 97)
__NR_getrusage = Constant("__NR_getrusage", 98)
__NR_sysinfo = Constant("__NR_sysinfo", 99)
__NR_times = Constant("__NR_times", 100)
__NR_ptrace = Constant("__NR_ptrace", 101)
__NR_getuid = Constant("__NR_getuid", 102)
__NR_syslog = Constant("__NR_syslog", 103)
__NR_getgid = Constant("__NR_getgid", 104)
__NR_setuid = Constant("__NR_setuid", 105)
__NR_setgid = Constant("__NR_setgid", 106)
__NR_geteuid = Constant("__NR_geteuid", 107)
__NR_getegid = Constant("__NR_getegid", 108)
__NR_setpgid = Constant("__NR_setpgid", 109)
__NR_getppid = Constant("__NR_getppid", 110)
__NR_getpgrp = Constant("__NR_getpgrp", 111)
__NR_setsid = Constant("__NR_setsid", 112)
__NR_setreuid = Constant("__NR_setreuid", 113)
__NR_setregid = Constant("__NR_setregid", 114)
__NR_getgroups = Constant("__NR_getgroups", 115)
__NR_setgroups = Constant("__NR_setgroups", 116)
__NR_setresuid = Constant("__NR_setresuid", 117)
__NR_getresuid = Constant("__NR_getresuid", 118)
__NR_setresgid = Constant("__NR_setresgid", 119)
__NR_getresgid = Constant("__NR_getresgid", 120)
__NR_getpgid = Constant("__NR_getpgid", 121)
__NR_setfsuid = Constant("__NR_setfsuid", 122)
__NR_setfsgid = Constant("__NR_setfsgid", 123)
__NR_getsid = Constant("__NR_getsid", 124)
__NR_capget = Constant("__NR_capget", 125)
__NR_capset = Constant("__NR_capset", 126)
__NR_rt_sigpending = Constant("__NR_rt_sigpending", 127)
__NR_rt_sigtimedwait = Constant("__NR_rt_sigtimedwait", 128)
__NR_rt_sigqueueinfo = Constant("__NR_rt_sigqueueinfo", 129)
__NR_rt_sigsuspend = Constant("__NR_rt_sigsuspend", 130)
__NR_sigaltstack = Constant("__NR_sigaltstack", 131)
__NR_utime = Constant("__NR_utime", 132)
__NR_mknod = Constant("__NR_mknod", 133)
__NR_uselib = Constant("__NR_uselib", 134)
__NR_personality = Constant("__NR_personality", 135)
__NR_ustat = Constant("__NR_ustat", 136)
__NR_statfs = Constant("__NR_statfs", 137)
__NR_fstatfs = Constant("__NR_fstatfs", 138)
__NR_sysfs = Constant("__NR_sysfs", 139)
__NR_getpriority = Constant("__NR_getpriority", 140)
__NR_setpriority = Constant("__NR_setpriority", 141)
__NR_sched_setparam = Constant("__NR_sched_setparam", 142)
__NR_sched_getparam = Constant("__NR_sched_getparam", 143)
__NR_sched_setscheduler = Constant("__NR_sched_setscheduler", 144)
__NR_sched_getscheduler = Constant("__NR_sched_getscheduler", 145)
__NR_sched_get_priority_max = Constant("__NR_sched_get_priority_max", 146)
__NR_sched_get_priority_min = Constant("__NR_sched_get_priority_min", 147)
__NR_sched_rr_get_interval = Constant("__NR_sched_rr_get_interval", 148)
__NR_mlock = Constant("__NR_mlock", 149)
__NR_munlock = Constant("__NR_munlock", 150)
__NR_mlockall = Constant("__NR_mlockall", 151)
__NR_munlockall = Constant("__NR_munlockall", 152)
__NR_vhangup = Constant("__NR_vhangup", 153)
__NR_modify_ldt = Constant("__NR_modify_ldt", 154)
__NR_pivot_root = Constant("__NR_pivot_root", 155)
__NR__sysctl = Constant("__NR__sysctl", 156)
__NR_prctl = Constant("__NR_prctl", 157)
__NR_arch_prctl = Constant("__NR_arch_prctl", 158)
__NR_adjtimex = Constant("__NR_adjtimex", 159)
__NR_setrlimit = Constant("__NR_setrlimit", 160)
__NR_chroot = Constant("__NR_chroot", 161)
__NR_sync = Constant("__NR_sync", 162)
__NR_acct = Constant("__NR_acct", 163)
__NR_settimeofday = Constant("__NR_settimeofday", 164)
__NR_mount = Constant("__NR_mount", 165)
__NR_umount2 = Constant("__NR_umount2", 166)
__NR_swapon = Constant("__NR_swapon", 167)
__NR_swapoff = Constant("__NR_swapoff", 168)
__NR_reboot = Constant("__NR_reboot", 169)
__NR_sethostname = Constant("__NR_sethostname", 170)
__NR_setdomainname = Constant("__NR_setdomainname", 171)
__NR_iopl = Constant("__NR_iopl", 172)
__NR_ioperm = Constant("__NR_ioperm", 173)
__NR_create_module = Constant("__NR_create_module", 174)
__NR_init_module = Constant("__NR_init_module", 175)
__NR_delete_module = Constant("__NR_delete_module", 176)
__NR_get_kernel_syms = Constant("__NR_get_kernel_syms", 177)
__NR_query_module = Constant("__NR_query_module", 178)
__NR_quotactl = Constant("__NR_quotactl", 179)
__NR_nfsservctl = Constant("__NR_nfsservctl", 180)
__NR_getpmsg = Constant("__NR_getpmsg", 181)
__NR_putpmsg = Constant("__NR_putpmsg", 182)
__NR_afs_syscall = Constant("__NR_afs_syscall", 183)
__NR_tuxcall = Constant("__NR_tuxcall", 184)
__NR_security = Constant("__NR_security", 185)
__NR_gettid = Constant("__NR_gettid", 186)
__NR_readahead = Constant("__NR_readahead", 187)
__NR_setxattr = Constant("__NR_setxattr", 188)
__NR_lsetxattr = Constant("__NR_lsetxattr", 189)
__NR_fsetxattr = Constant("__NR_fsetxattr", 190)
__NR_getxattr = Constant("__NR_getxattr", 191)
__NR_lgetxattr = Constant("__NR_lgetxattr", 192)
__NR_fgetxattr = Constant("__NR_fgetxattr", 193)
__NR_listxattr = Constant("__NR_listxattr", 194)
__NR_llistxattr = Constant("__NR_llistxattr", 195)
__NR_flistxattr = Constant("__NR_flistxattr", 196)
__NR_removexattr = Constant("__NR_removexattr", 197)
__NR_lremovexattr = Constant("__NR_lremovexattr", 198)
__NR_fremovexattr = Constant("__NR_fremovexattr", 199)
__NR_tkill = Constant("__NR_tkill", 200)
__NR_time = Constant("__NR_time", 201)
__NR_futex = Constant("__NR_futex", 202)
__NR_sched_setaffinity = Constant("__NR_sched_setaffinity", 203)
__NR_sched_getaffinity = Constant("__NR_sched_getaffinity", 204)
__NR_set_thread_area = Constant("__NR_set_thread_area", 205)
__NR_io_setup = Constant("__NR_io_setup", 206)
__NR_io_destroy = Constant("__NR_io_destroy", 207)
__NR_io_getevents = Constant("__NR_io_getevents", 208)
__NR_io_submit = Constant("__NR_io_submit", 209)
__NR_io_cancel = Constant("__NR_io_cancel", 210)
__NR_get_thread_area = Constant("__NR_get_thread_area", 211)
__NR_lookup_dcookie = Constant("__NR_lookup_dcookie", 212)
__NR_epoll_create = Constant("__NR_epoll_create", 213)
__NR_epoll_ctl_old = Constant("__NR_epoll_ctl_old", 214)
__NR_epoll_wait_old = Constant("__NR_epoll_wait_old", 215)
__NR_remap_file_pages = Constant("__NR_remap_file_pages", 216)
__NR_getdents64 = Constant("__NR_getdents64", 217)
__NR_set_tid_address = Constant("__NR_set_tid_address", 218)
__NR_restart_syscall = Constant("__NR_restart_syscall", 219)
__NR_semtimedop = Constant("__NR_semtimedop", 220)
__NR_fadvise64 = Constant("__NR_fadvise64", 221)
__NR_timer_create = Constant("__NR_timer_create", 222)
__NR_timer_settime = Constant("__NR_timer_settime", 223)
__NR_timer_gettime = Constant("__NR_timer_gettime", 224)
__NR_timer_getoverrun = Constant("__NR_timer_getoverrun", 225)
__NR_timer_delete = Constant("__NR_timer_delete", 226)
__NR_clock_settime = Constant("__NR_clock_settime", 227)
__NR_clock_gettime = Constant("__NR_clock_gettime", 228)
__NR_clock_getres = Constant("__NR_clock_getres", 229)
__NR_clock_nanosleep = Constant("__NR_clock_nanosleep", 230)
__NR_exit_group = Constant("__NR_exit_group", 231)
__NR_epoll_wait = Constant("__NR_epoll_wait", 232)
__NR_epoll_ctl = Constant("__NR_epoll_ctl", 233)
__NR_tgkill = Constant("__NR_tgkill", 234)
__NR_utimes = Constant("__NR_utimes", 235)
__NR_vserver = Constant("__NR_vserver", 236)
__NR_mbind = Constant("__NR_mbind", 237)
__NR_set_mempolicy = Constant("__NR_set_mempolicy", 238)
__NR_get_mempolicy = Constant("__NR_get_mempolicy", 239)
__NR_mq_open = Constant("__NR_mq_open", 240)
__NR_mq_unlink = Constant("__NR_mq_unlink", 241)
__NR_mq_timedsend = Constant("__NR_mq_timedsend", 242)
__NR_mq_timedreceive = Constant("__NR_mq_timedreceive", 243)
__NR_mq_notify = Constant("__NR_mq_notify", 244)
__NR_mq_getsetattr = Constant("__NR_mq_getsetattr", 245)
__NR_kexec_load = Constant("__NR_kexec_load", 246)
__NR_waitid = Constant("__NR_waitid", 247)
__NR_add_key = Constant("__NR_add_key", 248)
__NR_request_key = Constant("__NR_request_key", 249)
__NR_keyctl = Constant("__NR_keyctl", 250)
__NR_ioprio_set = Constant("__NR_ioprio_set", 251)
__NR_ioprio_get = Constant("__NR_ioprio_get", 252)
__NR_inotify_init = Constant("__NR_inotify_init", 253)
__NR_inotify_add_watch = Constant("__NR_inotify_add_watch", 254)
__NR_inotify_rm_watch = Constant("__NR_inotify_rm_watch", 255)
__NR_migrate_pages = Constant("__NR_migrate_pages", 256)
__NR_openat = Constant("__NR_openat", 257)
__NR_mkdirat = Constant("__NR_mkdirat", 258)
__NR_mknodat = Constant("__NR_mknodat", 259)
__NR_fchownat = Constant("__NR_fchownat", 260)
__NR_futimesat = Constant("__NR_futimesat", 261)
__NR_newfstatat = Constant("__NR_newfstatat", 262)
__NR_unlinkat = Constant("__NR_unlinkat", 263)
__NR_renameat = Constant("__NR_renameat", 264)
__NR_linkat = Constant("__NR_linkat", 265)
__NR_symlinkat = Constant("__NR_symlinkat", 266)
__NR_readlinkat = Constant("__NR_readlinkat", 267)
__NR_fchmodat = Constant("__NR_fchmodat", 268)
__NR_faccessat = Constant("__NR_faccessat", 269)
__NR_pselect6 = Constant("__NR_pselect6", 270)
__NR_ppoll = Constant("__NR_ppoll", 271)
__NR_unshare = Constant("__NR_unshare", 272)
__NR_set_robust_list = Constant("__NR_set_robust_list", 273)
__NR_get_robust_list = Constant("__NR_get_robust_list", 274)
__NR_splice = Constant("__NR_splice", 275)
__NR_tee = Constant("__NR_tee", 276)
__NR_sync_file_range = Constant("__NR_sync_file_range", 277)
__NR_vmsplice = Constant("__NR_vmsplice", 278)
__NR_move_pages = Constant("__NR_move_pages", 279)
__NR_utimensat = Constant("__NR_utimensat", 280)
__NR_epoll_pwait = Constant("__NR_epoll_pwait", 281)
__NR_signalfd = Constant("__NR_signalfd", 282)
__NR_timerfd = Constant("__NR_timerfd", 283)
__NR_eventfd = Constant("__NR_eventfd", 284)
__NR_fallocate = Constant("__NR_fallocate", 285)
__NR_timerfd_settime = Constant("__NR_timerfd_settime", 286)
__NR_timerfd_gettime = Constant("__NR_timerfd_gettime", 287)
__NR_accept4 = Constant("__NR_accept4", 288)
__NR_signalfd4 = Constant("__NR_signalfd4", 289)
__NR_eventfd2 = Constant("__NR_eventfd2", 290)
__NR_epoll_create1 = Constant("__NR_epoll_create1", 291)
__NR_dup3 = Constant("__NR_dup3", 292)
__NR_pipe2 = Constant("__NR_pipe2", 293)
__NR_inotify_init1 = Constant("__NR_inotify_init1", 294)
__NR_preadv = Constant("__NR_preadv", 295)
__NR_pwritev = Constant("__NR_pwritev", 296)
__NR_rt_tgsigqueueinfo = Constant("__NR_rt_tgsigqueueinfo", 297)
__NR_perf_event_open = Constant("__NR_perf_event_open", 298)
__NR_recvmmsg = Constant("__NR_recvmmsg", 299)
__NR_fanotify_init = Constant("__NR_fanotify_init", 300)
__NR_fanotify_mark = Constant("__NR_fanotify_mark", 301)
__NR_prlimit64 = Constant("__NR_prlimit64", 302)
__NR_name_to_handle_at = Constant("__NR_name_to_handle_at", 303)
__NR_open_by_handle_at = Constant("__NR_open_by_handle_at", 304)
__NR_clock_adjtime = Constant("__NR_clock_adjtime", 305)
__NR_syncfs = Constant("__NR_syncfs", 306)
__NR_sendmmsg = Constant("__NR_sendmmsg", 307)
__NR_setns = Constant("__NR_setns", 308)
__NR_getcpu = Constant("__NR_getcpu", 309)
__NR_process_vm_readv = Constant("__NR_process_vm_readv", 310)
__NR_process_vm_writev = Constant("__NR_process_vm_writev", 311)
__NR_kcmp = Constant("__NR_kcmp", 312)
__NR_finit_module = Constant("__NR_finit_module", 313)
__NR_sched_setattr = Constant("__NR_sched_setattr", 314)
__NR_sched_getattr = Constant("__NR_sched_getattr", 315)
__NR_renameat2 = Constant("__NR_renameat2", 316)
__NR_seccomp = Constant("__NR_seccomp", 317)
__NR_getrandom = Constant("__NR_getrandom", 318)
__NR_memfd_create = Constant("__NR_memfd_create", 319)
__NR_kexec_file_load = Constant("__NR_kexec_file_load", 320)
__NR_bpf = Constant("__NR_bpf", 321)
__NR_execveat = Constant("__NR_execveat", 322)
__NR_userfaultfd = Constant("__NR_userfaultfd", 323)
__NR_membarrier = Constant("__NR_membarrier", 324)
__NR_mlock2 = Constant("__NR_mlock2", 325)
__NR_copy_file_range = Constant("__NR_copy_file_range", 326)
__NR_preadv2 = Constant("__NR_preadv2", 327)
__NR_pwritev2 = Constant("__NR_pwritev2", 328)
__NR_pkey_mprotect = Constant("__NR_pkey_mprotect", 329)
__NR_pkey_alloc = Constant("__NR_pkey_alloc", 330)
__NR_pkey_free = Constant("__NR_pkey_free", 331)
__NR_statx = Constant("__NR_statx", 332)

__SYS_NERR = Constant("__SYS_NERR", ((129) + 1))
_SYS_TIME_H = Constant("_SYS_TIME_H", 1)
SYS_accept = Constant("SYS_accept", 43)
SYS_accept4 = Constant("SYS_accept4", 288)
SYS_access = Constant("SYS_access", 21)
SYS_acct = Constant("SYS_acct", 163)
SYS_add_key = Constant("SYS_add_key", 248)
SYS_adjtimex = Constant("SYS_adjtimex", 159)
SYS_afs_syscall = Constant("SYS_afs_syscall", 183)
SYS_alarm = Constant("SYS_alarm", 37)
SYS_arch_prctl = Constant("SYS_arch_prctl", 158)
SYS_bind = Constant("SYS_bind", 49)
SYS_brk = Constant("SYS_brk", 12)
SYS_capget = Constant("SYS_capget", 125)
SYS_capset = Constant("SYS_capset", 126)
SYS_chdir = Constant("SYS_chdir", 80)
SYS_chmod = Constant("SYS_chmod", 90)
SYS_chown = Constant("SYS_chown", 92)
SYS_chroot = Constant("SYS_chroot", 161)
SYS_clock_getres = Constant("SYS_clock_getres", 229)
SYS_clock_gettime = Constant("SYS_clock_gettime", 228)
SYS_clock_nanosleep = Constant("SYS_clock_nanosleep", 230)
SYS_clock_settime = Constant("SYS_clock_settime", 227)
SYS_clone = Constant("SYS_clone", 56)
SYS_close = Constant("SYS_close", 3)
SYS_connect = Constant("SYS_connect", 42)
SYS_creat = Constant("SYS_creat", 85)
SYS_create_module = Constant("SYS_create_module", 174)
SYS_delete_module = Constant("SYS_delete_module", 176)
SYS_dup = Constant("SYS_dup", 32)
SYS_dup2 = Constant("SYS_dup2", 33)
SYS_dup3 = Constant("SYS_dup3", 292)
SYS_epoll_create = Constant("SYS_epoll_create", 213)
SYS_epoll_create1 = Constant("SYS_epoll_create1", 291)
SYS_epoll_ctl = Constant("SYS_epoll_ctl", 233)
SYS_epoll_ctl_old = Constant("SYS_epoll_ctl_old", 214)
SYS_epoll_pwait = Constant("SYS_epoll_pwait", 281)
SYS_epoll_wait = Constant("SYS_epoll_wait", 232)
SYS_epoll_wait_old = Constant("SYS_epoll_wait_old", 215)
SYS_eventfd = Constant("SYS_eventfd", 284)
SYS_eventfd2 = Constant("SYS_eventfd2", 290)
SYS_execve = Constant("SYS_execve", 59)
SYS_exit = Constant("SYS_exit", 60)
SYS_exit_group = Constant("SYS_exit_group", 231)
SYS_faccessat = Constant("SYS_faccessat", 269)
SYS_fadvise64 = Constant("SYS_fadvise64", 221)
SYS_fallocate = Constant("SYS_fallocate", 285)
SYS_fanotify_init = Constant("SYS_fanotify_init", 300)
SYS_fanotify_mark = Constant("SYS_fanotify_mark", 301)
SYS_fchdir = Constant("SYS_fchdir", 81)
SYS_fchmod = Constant("SYS_fchmod", 91)
SYS_fchmodat = Constant("SYS_fchmodat", 268)
SYS_fchown = Constant("SYS_fchown", 93)
SYS_fchownat = Constant("SYS_fchownat", 260)
SYS_fcntl = Constant("SYS_fcntl", 72)
SYS_fdatasync = Constant("SYS_fdatasync", 75)
SYS_fgetxattr = Constant("SYS_fgetxattr", 193)
SYS_flistxattr = Constant("SYS_flistxattr", 196)
SYS_flock = Constant("SYS_flock", 73)
SYS_fork = Constant("SYS_fork", 57)
SYS_fremovexattr = Constant("SYS_fremovexattr", 199)
SYS_fsetxattr = Constant("SYS_fsetxattr", 190)
SYS_fstat = Constant("SYS_fstat", 5)
SYS_fstatfs = Constant("SYS_fstatfs", 138)
SYS_fsync = Constant("SYS_fsync", 74)
SYS_ftruncate = Constant("SYS_ftruncate", 77)
SYS_futex = Constant("SYS_futex", 202)
SYS_futimesat = Constant("SYS_futimesat", 261)
SYS_getcwd = Constant("SYS_getcwd", 79)
SYS_getdents = Constant("SYS_getdents", 78)
SYS_getdents64 = Constant("SYS_getdents64", 217)
SYS_getegid = Constant("SYS_getegid", 108)
SYS_geteuid = Constant("SYS_geteuid", 107)
SYS_getgid = Constant("SYS_getgid", 104)
SYS_getgroups = Constant("SYS_getgroups", 115)
SYS_getitimer = Constant("SYS_getitimer", 36)
SYS_get_kernel_syms = Constant("SYS_get_kernel_syms", 177)
SYS_get_mempolicy = Constant("SYS_get_mempolicy", 239)
SYS_getpeername = Constant("SYS_getpeername", 52)
SYS_getpgid = Constant("SYS_getpgid", 121)
SYS_getpgrp = Constant("SYS_getpgrp", 111)
SYS_getpid = Constant("SYS_getpid", 39)
SYS_getpmsg = Constant("SYS_getpmsg", 181)
SYS_getppid = Constant("SYS_getppid", 110)
SYS_getpriority = Constant("SYS_getpriority", 140)
SYS_getresgid = Constant("SYS_getresgid", 120)
SYS_getresuid = Constant("SYS_getresuid", 118)
SYS_getrlimit = Constant("SYS_getrlimit", 97)
SYS_get_robust_list = Constant("SYS_get_robust_list", 274)
SYS_getrusage = Constant("SYS_getrusage", 98)
SYS_getsid = Constant("SYS_getsid", 124)
SYS_getsockname = Constant("SYS_getsockname", 51)
SYS_getsockopt = Constant("SYS_getsockopt", 55)
SYS_get_thread_area = Constant("SYS_get_thread_area", 211)
SYS_gettid = Constant("SYS_gettid", 186)
SYS_gettimeofday = Constant("SYS_gettimeofday", 96)
SYS_getuid = Constant("SYS_getuid", 102)
SYS_getxattr = Constant("SYS_getxattr", 191)
SYS_init_module = Constant("SYS_init_module", 175)
SYS_inotify_add_watch = Constant("SYS_inotify_add_watch", 254)
SYS_inotify_init = Constant("SYS_inotify_init", 253)
SYS_inotify_init1 = Constant("SYS_inotify_init1", 294)
SYS_inotify_rm_watch = Constant("SYS_inotify_rm_watch", 255)
SYS_io_cancel = Constant("SYS_io_cancel", 210)
SYS_ioctl = Constant("SYS_ioctl", 16)
SYS_io_destroy = Constant("SYS_io_destroy", 207)
SYS_io_getevents = Constant("SYS_io_getevents", 208)
SYS_ioperm = Constant("SYS_ioperm", 173)
SYS_iopl = Constant("SYS_iopl", 172)
SYS_ioprio_get = Constant("SYS_ioprio_get", 252)
SYS_ioprio_set = Constant("SYS_ioprio_set", 251)
SYS_io_setup = Constant("SYS_io_setup", 206)
SYS_io_submit = Constant("SYS_io_submit", 209)
SYS_kexec_load = Constant("SYS_kexec_load", 246)
SYS_keyctl = Constant("SYS_keyctl", 250)
SYS_kill = Constant("SYS_kill", 62)
SYS_lchown = Constant("SYS_lchown", 94)
SYS_lgetxattr = Constant("SYS_lgetxattr", 192)
SYS_link = Constant("SYS_link", 86)
SYS_linkat = Constant("SYS_linkat", 265)
SYS_listen = Constant("SYS_listen", 50)
SYS_listxattr = Constant("SYS_listxattr", 194)
SYS_llistxattr = Constant("SYS_llistxattr", 195)
SYS_lookup_dcookie = Constant("SYS_lookup_dcookie", 212)
SYS_lremovexattr = Constant("SYS_lremovexattr", 198)
SYS_lseek = Constant("SYS_lseek", 8)
SYS_lsetxattr = Constant("SYS_lsetxattr", 189)
SYS_lstat = Constant("SYS_lstat", 6)
SYS_madvise = Constant("SYS_madvise", 28)
SYS_mbind = Constant("SYS_mbind", 237)
SYS_migrate_pages = Constant("SYS_migrate_pages", 256)
SYS_mincore = Constant("SYS_mincore", 27)
SYS_mkdir = Constant("SYS_mkdir", 83)
SYS_mkdirat = Constant("SYS_mkdirat", 258)
SYS_mknod = Constant("SYS_mknod", 133)
SYS_mknodat = Constant("SYS_mknodat", 259)
SYS_mlock = Constant("SYS_mlock", 149)
SYS_mlockall = Constant("SYS_mlockall", 151)
SYS_mmap = Constant("SYS_mmap", 9)
SYS_modify_ldt = Constant("SYS_modify_ldt", 154)
SYS_mount = Constant("SYS_mount", 165)
SYS_move_pages = Constant("SYS_move_pages", 279)
SYS_mprotect = Constant("SYS_mprotect", 10)
SYS_mq_getsetattr = Constant("SYS_mq_getsetattr", 245)
SYS_mq_notify = Constant("SYS_mq_notify", 244)
SYS_mq_open = Constant("SYS_mq_open", 240)
SYS_mq_timedreceive = Constant("SYS_mq_timedreceive", 243)
SYS_mq_timedsend = Constant("SYS_mq_timedsend", 242)
SYS_mq_unlink = Constant("SYS_mq_unlink", 241)
SYS_mremap = Constant("SYS_mremap", 25)
SYS_msgctl = Constant("SYS_msgctl", 71)
SYS_msgget = Constant("SYS_msgget", 68)
SYS_msgrcv = Constant("SYS_msgrcv", 70)
SYS_msgsnd = Constant("SYS_msgsnd", 69)
SYS_msync = Constant("SYS_msync", 26)
SYS_munlock = Constant("SYS_munlock", 150)
SYS_munlockall = Constant("SYS_munlockall", 152)
SYS_munmap = Constant("SYS_munmap", 11)
SYS_nanosleep = Constant("SYS_nanosleep", 35)
SYS_newfstatat = Constant("SYS_newfstatat", 262)
SYS_nfsservctl = Constant("SYS_nfsservctl", 180)
SYS_open = Constant("SYS_open", 2)
SYS_openat = Constant("SYS_openat", 257)
SYS_pause = Constant("SYS_pause", 34)
SYS_perf_event_open = Constant("SYS_perf_event_open", 298)
SYS_personality = Constant("SYS_personality", 135)
SYS_pipe = Constant("SYS_pipe", 22)
SYS_pipe2 = Constant("SYS_pipe2", 293)
SYS_pivot_root = Constant("SYS_pivot_root", 155)
SYS_poll = Constant("SYS_poll", 7)
SYS_ppoll = Constant("SYS_ppoll", 271)
SYS_prctl = Constant("SYS_prctl", 157)
SYS_pread = Constant("SYS_pread", 17)
SYS_preadv = Constant("SYS_preadv", 295)
SYS_prlimit64 = Constant("SYS_prlimit64", 302)
SYS_pselect6 = Constant("SYS_pselect6", 270)
SYS_ptrace = Constant("SYS_ptrace", 101)
SYS_putpmsg = Constant("SYS_putpmsg", 182)
SYS_pwrite = Constant("SYS_pwrite", 18)
SYS_pwritev = Constant("SYS_pwritev", 296)
SYS_query_module = Constant("SYS_query_module", 178)
SYS_quotactl = Constant("SYS_quotactl", 179)
SYS_read = Constant("SYS_read", 0)
SYS_readahead = Constant("SYS_readahead", 187)
SYS_readlink = Constant("SYS_readlink", 89)
SYS_readlinkat = Constant("SYS_readlinkat", 267)
SYS_readv = Constant("SYS_readv", 19)
SYS_reboot = Constant("SYS_reboot", 169)
SYS_recvfrom = Constant("SYS_recvfrom", 45)
SYS_recvmmsg = Constant("SYS_recvmmsg", 299)
SYS_recvmsg = Constant("SYS_recvmsg", 47)
SYS_remap_file_pages = Constant("SYS_remap_file_pages", 216)
SYS_removexattr = Constant("SYS_removexattr", 197)
SYS_rename = Constant("SYS_rename", 82)
SYS_renameat = Constant("SYS_renameat", 264)
SYS_request_key = Constant("SYS_request_key", 249)
SYS_restart_syscall = Constant("SYS_restart_syscall", 219)
SYS_rmdir = Constant("SYS_rmdir", 84)
SYS_rt_sigaction = Constant("SYS_rt_sigaction", 13)
SYS_rt_sigpending = Constant("SYS_rt_sigpending", 127)
SYS_rt_sigprocmask = Constant("SYS_rt_sigprocmask", 14)
SYS_rt_sigqueueinfo = Constant("SYS_rt_sigqueueinfo", 129)
SYS_rt_sigreturn = Constant("SYS_rt_sigreturn", 15)
SYS_rt_sigsuspend = Constant("SYS_rt_sigsuspend", 130)
SYS_rt_sigtimedwait = Constant("SYS_rt_sigtimedwait", 128)
SYS_rt_tgsigqueueinfo = Constant("SYS_rt_tgsigqueueinfo", 297)
SYS_sched_getaffinity = Constant("SYS_sched_getaffinity", 204)
SYS_sched_getparam = Constant("SYS_sched_getparam", 143)
SYS_sched_get_priority_max = Constant("SYS_sched_get_priority_max", 146)
SYS_sched_get_priority_min = Constant("SYS_sched_get_priority_min", 147)
SYS_sched_getscheduler = Constant("SYS_sched_getscheduler", 145)
SYS_sched_rr_get_interval = Constant("SYS_sched_rr_get_interval", 148)
SYS_sched_setaffinity = Constant("SYS_sched_setaffinity", 203)
SYS_sched_setparam = Constant("SYS_sched_setparam", 142)
SYS_sched_setscheduler = Constant("SYS_sched_setscheduler", 144)
SYS_sched_yield = Constant("SYS_sched_yield", 24)
SYS_security = Constant("SYS_security", 185)
SYS_select = Constant("SYS_select", 23)
SYS_semctl = Constant("SYS_semctl", 66)
SYS_semget = Constant("SYS_semget", 64)
SYS_semop = Constant("SYS_semop", 65)
SYS_semtimedop = Constant("SYS_semtimedop", 220)
SYS_sendfile = Constant("SYS_sendfile", 40)
SYS_sendmsg = Constant("SYS_sendmsg", 46)
SYS_sendto = Constant("SYS_sendto", 44)
SYS_setdomainname = Constant("SYS_setdomainname", 171)
SYS_setfsgid = Constant("SYS_setfsgid", 123)
SYS_setfsuid = Constant("SYS_setfsuid", 122)
SYS_setgid = Constant("SYS_setgid", 106)
SYS_setgroups = Constant("SYS_setgroups", 116)
SYS_sethostname = Constant("SYS_sethostname", 170)
SYS_setitimer = Constant("SYS_setitimer", 38)
SYS_set_mempolicy = Constant("SYS_set_mempolicy", 238)
SYS_setpgid = Constant("SYS_setpgid", 109)
SYS_setpriority = Constant("SYS_setpriority", 141)
SYS_setregid = Constant("SYS_setregid", 114)
SYS_setresgid = Constant("SYS_setresgid", 119)
SYS_setresuid = Constant("SYS_setresuid", 117)
SYS_setreuid = Constant("SYS_setreuid", 113)
SYS_setrlimit = Constant("SYS_setrlimit", 160)
SYS_set_robust_list = Constant("SYS_set_robust_list", 273)
SYS_setsid = Constant("SYS_setsid", 112)
SYS_setsockopt = Constant("SYS_setsockopt", 54)
SYS_set_thread_area = Constant("SYS_set_thread_area", 205)
SYS_set_tid_address = Constant("SYS_set_tid_address", 218)
SYS_settimeofday = Constant("SYS_settimeofday", 164)
SYS_setuid = Constant("SYS_setuid", 105)
SYS_setxattr = Constant("SYS_setxattr", 188)
SYS_shmat = Constant("SYS_shmat", 30)
SYS_shmctl = Constant("SYS_shmctl", 31)
SYS_shmdt = Constant("SYS_shmdt", 67)
SYS_shmget = Constant("SYS_shmget", 29)
SYS_shutdown = Constant("SYS_shutdown", 48)
SYS_sigaltstack = Constant("SYS_sigaltstack", 131)
SYS_signalfd = Constant("SYS_signalfd", 282)
SYS_signalfd4 = Constant("SYS_signalfd4", 289)
SYS_socket = Constant("SYS_socket", 41)
SYS_socketpair = Constant("SYS_socketpair", 53)
SYS_splice = Constant("SYS_splice", 275)
SYS_stat = Constant("SYS_stat", 4)
SYS_statfs = Constant("SYS_statfs", 137)
SYS_swapoff = Constant("SYS_swapoff", 168)
SYS_swapon = Constant("SYS_swapon", 167)
SYS_symlink = Constant("SYS_symlink", 88)
SYS_symlinkat = Constant("SYS_symlinkat", 266)
SYS_sync = Constant("SYS_sync", 162)
SYS_sync_file_range = Constant("SYS_sync_file_range", 277)
SYS__sysctl = Constant("SYS__sysctl", 156)
SYS_sysfs = Constant("SYS_sysfs", 139)
SYS_sysinfo = Constant("SYS_sysinfo", 99)
SYS_syslog = Constant("SYS_syslog", 103)
SYS_tee = Constant("SYS_tee", 276)
SYS_tgkill = Constant("SYS_tgkill", 234)
SYS_time = Constant("SYS_time", 201)
SYS_timer_create = Constant("SYS_timer_create", 222)
SYS_timer_delete = Constant("SYS_timer_delete", 226)
SYS_timerfd = Constant("SYS_timerfd", 283)
SYS_timerfd_gettime = Constant("SYS_timerfd_gettime", 287)
SYS_timerfd_settime = Constant("SYS_timerfd_settime", 286)
SYS_timer_getoverrun = Constant("SYS_timer_getoverrun", 225)
SYS_timer_gettime = Constant("SYS_timer_gettime", 224)
SYS_timer_settime = Constant("SYS_timer_settime", 223)
SYS_times = Constant("SYS_times", 100)
SYS_tkill = Constant("SYS_tkill", 200)
SYS_truncate = Constant("SYS_truncate", 76)
SYS_tuxcall = Constant("SYS_tuxcall", 184)
SYS_umask = Constant("SYS_umask", 95)
SYS_umount2 = Constant("SYS_umount2", 166)
SYS_uname = Constant("SYS_uname", 63)
SYS_unlink = Constant("SYS_unlink", 87)
SYS_unlinkat = Constant("SYS_unlinkat", 263)
SYS_unshare = Constant("SYS_unshare", 272)
SYS_uselib = Constant("SYS_uselib", 134)
SYS_ustat = Constant("SYS_ustat", 136)
SYS_utime = Constant("SYS_utime", 132)
SYS_utimensat = Constant("SYS_utimensat", 280)
SYS_utimes = Constant("SYS_utimes", 235)
SYS_vfork = Constant("SYS_vfork", 58)
SYS_vhangup = Constant("SYS_vhangup", 153)
SYS_vmsplice = Constant("SYS_vmsplice", 278)
SYS_vserver = Constant("SYS_vserver", 236)
SYS_wait4 = Constant("SYS_wait4", 61)
SYS_waitid = Constant("SYS_waitid", 247)
SYS_write = Constant("SYS_write", 1)
SYS_writev = Constant("SYS_writev", 20)
