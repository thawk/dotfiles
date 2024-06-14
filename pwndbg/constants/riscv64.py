from __future__ import annotations

from .constant import Constant

__NR_io_setup = Constant("__NR_io_setup", 0)
__NR_io_destroy = Constant("__NR_io_destroy", 1)
__NR_io_submit = Constant("__NR_io_submit", 2)
__NR_io_cancel = Constant("__NR_io_cancel", 3)
__NR_io_getevents = Constant("__NR_io_getevents", 4)
__NR_setxattr = Constant("__NR_setxattr", 5)
__NR_lsetxattr = Constant("__NR_lsetxattr", 6)
__NR_getxattr = Constant("__NR_getxattr", 8)
__NR_lgetxattr = Constant("__NR_lgetxattr", 9)
__NR_listxattr = Constant("__NR_listxattr", 11)
__NR_llistxattr = Constant("__NR_llistxattr", 12)
__NR_removexattr = Constant("__NR_removexattr", 14)
__NR_lremovexattr = Constant("__NR_lremovexattr", 15)
__NR_getcwd = Constant("__NR_getcwd", 17)
__NR_lookup_dcookie = Constant("__NR_lookup_dcookie", 18)
__NR_inotify_init1 = Constant("__NR_inotify_init1", 26)
__NR_inotify_add_watch = Constant("__NR_inotify_add_watch", 27)
__NR_inotify_rm_watch = Constant("__NR_inotify_rm_watch", 28)
__NR_ioctl = Constant("__NR_ioctl", 29)
__NR_ioprio_set = Constant("__NR_ioprio_set", 30)
__NR_ioprio_get = Constant("__NR_ioprio_get", 31)
__NR_mknodat = Constant("__NR_mknodat", 33)
__NR_mkdirat = Constant("__NR_mkdirat", 34)
__NR_unlinkat = Constant("__NR_unlinkat", 35)
__NR_symlinkat = Constant("__NR_symlinkat", 36)
__NR_linkat = Constant("__NR_linkat", 37)
__NR_umount2 = Constant("__NR_umount2", 39)
__NR_mount = Constant("__NR_mount", 40)
__NR_pivot_root = Constant("__NR_pivot_root", 41)
__NR_nfsservctl = Constant("__NR_nfsservctl", 42)
__NR_statfs = Constant("__NR_statfs", 43)
__NR_fstatfs = Constant("__NR_fstatfs", 44)
__NR_truncate = Constant("__NR_truncate", 45)
__NR_ftruncate = Constant("__NR_ftruncate", 46)
__NR_openat = Constant("__NR_openat", 56)
__NR_vhangup = Constant("__NR_vhangup", 58)
__NR_pipe2 = Constant("__NR_pipe2", 59)
__NR_quotactl = Constant("__NR_quotactl", 60)
__NR_getdents64 = Constant("__NR_getdents64", 61)
__NR_lseek = Constant("__NR_lseek", 62)
__NR_read = Constant("__NR_read", 63)
__NR_write = Constant("__NR_write", 64)
__NR_readv = Constant("__NR_readv", 65)
__NR_writev = Constant("__NR_writev", 66)
__NR_pread64 = Constant("__NR_pread64", 67)
__NR_pwrite64 = Constant("__NR_pwrite64", 68)
__NR_preadv = Constant("__NR_preadv", 69)
__NR_pwritev = Constant("__NR_pwritev", 70)
__NR_sendfile = Constant("__NR_sendfile", 71)
__NR_pselect6 = Constant("__NR_pselect6", 72)
__NR_ppoll = Constant("__NR_ppoll", 73)
__NR_signalfd4 = Constant("__NR_signalfd4", 74)
__NR_vmsplice = Constant("__NR_vmsplice", 75)
__NR_splice = Constant("__NR_splice", 76)
__NR_tee = Constant("__NR_tee", 77)
__NR_readlinkat = Constant("__NR_readlinkat", 78)
__NR_newfstatat = Constant("__NR_newfstatat", 79)
__NR_sync = Constant("__NR_sync", 81)
__NR_fsync = Constant("__NR_fsync", 82)
__NR_sync_file_range = Constant("__NR_sync_file_range", 84)
__NR_timerfd_create = Constant("__NR_timerfd_create", 85)
__NR_timerfd_settime = Constant("__NR_timerfd_settime", 86)
__NR_timerfd_gettime = Constant("__NR_timerfd_gettime", 87)
__NR_utimensat = Constant("__NR_utimensat", 88)
__NR_personality = Constant("__NR_personality", 92)
__NR_waitid = Constant("__NR_waitid", 95)
__NR_set_tid_address = Constant("__NR_set_tid_address", 96)
__NR_unshare = Constant("__NR_unshare", 97)
__NR_futex = Constant("__NR_futex", 98)
__NR_set_robust_list = Constant("__NR_set_robust_list", 99)
__NR_get_robust_list = Constant("__NR_get_robust_list", 100)
__NR_nanosleep = Constant("__NR_nanosleep", 101)
__NR_getitimer = Constant("__NR_getitimer", 102)
__NR_setitimer = Constant("__NR_setitimer", 103)
__NR_kexec_load = Constant("__NR_kexec_load", 104)
__NR_init_module = Constant("__NR_init_module", 105)
__NR_timer_create = Constant("__NR_timer_create", 107)
__NR_timer_gettime = Constant("__NR_timer_gettime", 108)
__NR_timer_getoverrun = Constant("__NR_timer_getoverrun", 109)
__NR_timer_settime = Constant("__NR_timer_settime", 110)
__NR_timer_delete = Constant("__NR_timer_delete", 111)
__NR_syslog = Constant("__NR_syslog", 116)
__NR_ptrace = Constant("__NR_ptrace", 117)
__NR_sched_setparam = Constant("__NR_sched_setparam", 118)
__NR_sched_setscheduler = Constant("__NR_sched_setscheduler", 119)
__NR_sched_getscheduler = Constant("__NR_sched_getscheduler", 120)
__NR_sched_getparam = Constant("__NR_sched_getparam", 121)
__NR_sched_setaffinity = Constant("__NR_sched_setaffinity", 122)
__NR_sched_getaffinity = Constant("__NR_sched_getaffinity", 123)
__NR_sched_yield = Constant("__NR_sched_yield", 124)
__NR_sched_get_priority_max = Constant("__NR_sched_get_priority_max", 125)
__NR_sched_get_priority_min = Constant("__NR_sched_get_priority_min", 126)
__NR_sched_rr_get_interval = Constant("__NR_sched_rr_get_interval", 127)
__NR_restart_syscall = Constant("__NR_restart_syscall", 128)
__NR_kill = Constant("__NR_kill", 129)
__NR_tkill = Constant("__NR_tkill", 130)
__NR_tgkill = Constant("__NR_tgkill", 131)
__NR_sigaltstack = Constant("__NR_sigaltstack", 132)
__NR_rt_sigsuspend = Constant("__NR_rt_sigsuspend", 133)
__NR_rt_sigaction = Constant("__NR_rt_sigaction", 134)
__NR_rt_sigprocmask = Constant("__NR_rt_sigprocmask", 135)
__NR_rt_sigpending = Constant("__NR_rt_sigpending", 136)
__NR_rt_sigtimedwait = Constant("__NR_rt_sigtimedwait", 137)
__NR_rt_sigqueueinfo = Constant("__NR_rt_sigqueueinfo", 138)
__NR_rt_sigreturn = Constant("__NR_rt_sigreturn", 139)
__NR_setpriority = Constant("__NR_setpriority", 140)
__NR_getpriority = Constant("__NR_getpriority", 141)
__NR_reboot = Constant("__NR_reboot", 142)
__NR_setregid = Constant("__NR_setregid", 143)
__NR_setgid = Constant("__NR_setgid", 144)
__NR_setreuid = Constant("__NR_setreuid", 145)
__NR_setuid = Constant("__NR_setuid", 146)
__NR_setresuid = Constant("__NR_setresuid", 147)
__NR_getresuid = Constant("__NR_getresuid", 148)
__NR_setresgid = Constant("__NR_setresgid", 149)
__NR_getresgid = Constant("__NR_getresgid", 150)
__NR_setfsuid = Constant("__NR_setfsuid", 151)
__NR_setfsgid = Constant("__NR_setfsgid", 152)
__NR_times = Constant("__NR_times", 153)
__NR_setpgid = Constant("__NR_setpgid", 154)
__NR_getpgid = Constant("__NR_getpgid", 155)
__NR_getsid = Constant("__NR_getsid", 156)
__NR_setsid = Constant("__NR_setsid", 157)
__NR_getgroups = Constant("__NR_getgroups", 158)
__NR_setgroups = Constant("__NR_setgroups", 159)
__NR_uname = Constant("__NR_uname", 160)
__NR_sethostname = Constant("__NR_sethostname", 161)
__NR_setdomainname = Constant("__NR_setdomainname", 162)
__NR_getrlimit = Constant("__NR_getrlimit", 163)
__NR_setrlimit = Constant("__NR_setrlimit", 164)
__NR_getrusage = Constant("__NR_getrusage", 165)
__NR_umask = Constant("__NR_umask", 166)
__NR_prctl = Constant("__NR_prctl", 167)
__NR_getcpu = Constant("__NR_getcpu", 168)
__NR_gettimeofday = Constant("__NR_gettimeofday", 169)
__NR_settimeofday = Constant("__NR_settimeofday", 170)
__NR_getpid = Constant("__NR_getpid", 172)
__NR_getppid = Constant("__NR_getppid", 173)
__NR_getuid = Constant("__NR_getuid", 174)
__NR_geteuid = Constant("__NR_geteuid", 175)
__NR_getgid = Constant("__NR_getgid", 176)
__NR_getegid = Constant("__NR_getegid", 177)
__NR_gettid = Constant("__NR_gettid", 178)
__NR_sysinfo = Constant("__NR_sysinfo", 179)
__NR_mq_open = Constant("__NR_mq_open", 180)
__NR_mq_unlink = Constant("__NR_mq_unlink", 181)
__NR_mq_timedsend = Constant("__NR_mq_timedsend", 182)
__NR_mq_timedreceive = Constant("__NR_mq_timedreceive", 183)
__NR_mq_notify = Constant("__NR_mq_notify", 184)
__NR_mq_getsetattr = Constant("__NR_mq_getsetattr", 185)
__NR_msgget = Constant("__NR_msgget", 186)
__NR_msgctl = Constant("__NR_msgctl", 187)
__NR_msgrcv = Constant("__NR_msgrcv", 188)
__NR_msgsnd = Constant("__NR_msgsnd", 189)
__NR_semget = Constant("__NR_semget", 190)
__NR_semctl = Constant("__NR_semctl", 191)
__NR_semtimedop = Constant("__NR_semtimedop", 192)
__NR_semop = Constant("__NR_semop", 193)
__NR_shmget = Constant("__NR_shmget", 194)
__NR_shmctl = Constant("__NR_shmctl", 195)
__NR_shmat = Constant("__NR_shmat", 196)
__NR_shmdt = Constant("__NR_shmdt", 197)
__NR_socket = Constant("__NR_socket", 198)
__NR_socketpair = Constant("__NR_socketpair", 199)
__NR_listen = Constant("__NR_listen", 201)
__NR_getsockname = Constant("__NR_getsockname", 204)
__NR_getpeername = Constant("__NR_getpeername", 205)
__NR_sendto = Constant("__NR_sendto", 206)
__NR_recvfrom = Constant("__NR_recvfrom", 207)
__NR_setsockopt = Constant("__NR_setsockopt", 208)
__NR_getsockopt = Constant("__NR_getsockopt", 209)
__NR_shutdown = Constant("__NR_shutdown", 210)
__NR_sendmsg = Constant("__NR_sendmsg", 211)
__NR_recvmsg = Constant("__NR_recvmsg", 212)
__NR_readahead = Constant("__NR_readahead", 213)
__NR_munmap = Constant("__NR_munmap", 215)
__NR_mremap = Constant("__NR_mremap", 216)
__NR_request_key = Constant("__NR_request_key", 218)
__NR_keyctl = Constant("__NR_keyctl", 219)
__NR_mmap = Constant("__NR_mmap", 222)
__NR_swapon = Constant("__NR_swapon", 224)
__NR_swapoff = Constant("__NR_swapoff", 225)
__NR_mprotect = Constant("__NR_mprotect", 226)
__NR_msync = Constant("__NR_msync", 227)
__NR_mlock = Constant("__NR_mlock", 228)
__NR_munlock = Constant("__NR_munlock", 229)
__NR_mlockall = Constant("__NR_mlockall", 230)
__NR_munlockall = Constant("__NR_munlockall", 231)
__NR_mincore = Constant("__NR_mincore", 232)
__NR_madvise = Constant("__NR_madvise", 233)
__NR_remap_file_pages = Constant("__NR_remap_file_pages", 234)
__NR_mbind = Constant("__NR_mbind", 235)
__NR_get_mempolicy = Constant("__NR_get_mempolicy", 236)
__NR_set_mempolicy = Constant("__NR_set_mempolicy", 237)
__NR_migrate_pages = Constant("__NR_migrate_pages", 238)
__NR_move_pages = Constant("__NR_move_pages", 239)
__NR_rt_tgsigqueueinfo = Constant("__NR_rt_tgsigqueueinfo", 240)
__NR_perf_event_open = Constant("__NR_perf_event_open", 241)
__NR_recvmmsg = Constant("__NR_recvmmsg", 243)
__NR_riscv_flush_icache = Constant("__NR_riscv_flush_icache", 259)
__NR_wait4 = Constant("__NR_wait4", 260)
__NR_prlimit64 = Constant("__NR_prlimit64", 261)
__NR_name_to_handle_at = Constant("__NR_name_to_handle_at", 264)
__NR_open_by_handle_at = Constant("__NR_open_by_handle_at", 265)
__NR_syncfs = Constant("__NR_syncfs", 267)
__NR_setns = Constant("__NR_setns", 268)
__NR_sendmmsg = Constant("__NR_sendmmsg", 269)
__NR_process_vm_readv = Constant("__NR_process_vm_readv", 270)
__NR_process_vm_writev = Constant("__NR_process_vm_writev", 271)
__NR_kcmp = Constant("__NR_kcmp", 272)
__NR_sched_setattr = Constant("__NR_sched_setattr", 274)
__NR_sched_getattr = Constant("__NR_sched_getattr", 275)
__NR_renameat2 = Constant("__NR_renameat2", 276)
__NR_seccomp = Constant("__NR_seccomp", 277)
__NR_getrandom = Constant("__NR_getrandom", 278)
__NR_memfd_create = Constant("__NR_memfd_create", 279)
__NR_userfaultfd = Constant("__NR_userfaultfd", 282)
__NR_membarrier = Constant("__NR_membarrier", 283)
__NR_mlock2 = Constant("__NR_mlock2", 284)
__NR_preadv2 = Constant("__NR_preadv2", 286)
__NR_pwritev2 = Constant("__NR_pwritev2", 287)
__NR_pkey_mprotect = Constant("__NR_pkey_mprotect", 288)
__NR_pkey_alloc = Constant("__NR_pkey_alloc", 289)
__NR_pkey_free = Constant("__NR_pkey_free", 290)
__NR_statx = Constant("__NR_statx", 291)
__NR_io_pgetevents = Constant("__NR_io_pgetevents", 292)
__NR_rseq = Constant("__NR_rseq", 293)
__NR_kexec_file_load = Constant("__NR_kexec_file_load", 294)
__NR_pidfd_send_signal = Constant("__NR_pidfd_send_signal", 424)
__NR_io_uring_setup = Constant("__NR_io_uring_setup", 425)
__NR_io_uring_enter = Constant("__NR_io_uring_enter", 426)
__NR_io_uring_register = Constant("__NR_io_uring_register", 427)
__NR_open_tree = Constant("__NR_open_tree", 428)
__NR_move_mount = Constant("__NR_move_mount", 429)
__NR_pidfd_open = Constant("__NR_pidfd_open", 434)
__NR_openat2 = Constant("__NR_openat2", 437)
__NR_pidfd_getfd = Constant("__NR_pidfd_getfd", 438)
__NR_process_madvise = Constant("__NR_process_madvise", 440)
__NR_mount_setattr = Constant("__NR_mount_setattr", 442)
__NR_quotactl_fd = Constant("__NR_quotactl_fd", 443)
__NR_landlock_create_ruleset = Constant("__NR_landlock_create_ruleset", 444)
__NR_landlock_add_rule = Constant("__NR_landlock_add_rule", 445)
__NR_landlock_restrict_self = Constant("__NR_landlock_restrict_self", 446)
__NR_memfd_secret = Constant("__NR_memfd_secret", 447)
__NR_process_mrelease = Constant("__NR_process_mrelease", 448)
__NR_futex_waitv = Constant("__NR_futex_waitv", 449)
__NR_set_mempolicy_home_node = Constant("__NR_set_mempolicy_home_node", 450)
