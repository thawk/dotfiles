from __future__ import annotations

from .constant import Constant

__NR_exit = Constant("__NR_exit", 1)
__NR_fork = Constant("__NR_fork", 2)
__NR_read = Constant("__NR_read", 3)
__NR_write = Constant("__NR_write", 4)
__NR_open = Constant("__NR_open", 5)
__NR_close = Constant("__NR_close", 6)
__NR_waitpid = Constant("__NR_waitpid", 7)
__NR_creat = Constant("__NR_creat", 8)
__NR_link = Constant("__NR_link", 9)
__NR_unlink = Constant("__NR_unlink", 10)
__NR_execve = Constant("__NR_execve", 11)
__NR_chdir = Constant("__NR_chdir", 12)
__NR_time = Constant("__NR_time", 13)
__NR_mknod = Constant("__NR_mknod", 14)
__NR_chmod = Constant("__NR_chmod", 15)
__NR_lchown = Constant("__NR_lchown", 16)
__NR_break = Constant("__NR_break", 17)
__NR_oldstat = Constant("__NR_oldstat", 18)
__NR_lseek = Constant("__NR_lseek", 19)
__NR_getpid = Constant("__NR_getpid", 20)
__NR_mount = Constant("__NR_mount", 21)
__NR_umount = Constant("__NR_umount", 22)
__NR_setuid = Constant("__NR_setuid", 23)
__NR_getuid = Constant("__NR_getuid", 24)
__NR_stime = Constant("__NR_stime", 25)
__NR_ptrace = Constant("__NR_ptrace", 26)
__NR_alarm = Constant("__NR_alarm", 27)
__NR_oldfstat = Constant("__NR_oldfstat", 28)
__NR_pause = Constant("__NR_pause", 29)
__NR_utime = Constant("__NR_utime", 30)
__NR_stty = Constant("__NR_stty", 31)
__NR_gtty = Constant("__NR_gtty", 32)
__NR_access = Constant("__NR_access", 33)
__NR_nice = Constant("__NR_nice", 34)
__NR_ftime = Constant("__NR_ftime", 35)
__NR_sync = Constant("__NR_sync", 36)
__NR_kill = Constant("__NR_kill", 37)
__NR_rename = Constant("__NR_rename", 38)
__NR_mkdir = Constant("__NR_mkdir", 39)
__NR_rmdir = Constant("__NR_rmdir", 40)
__NR_dup = Constant("__NR_dup", 41)
__NR_pipe = Constant("__NR_pipe", 42)
__NR_times = Constant("__NR_times", 43)
__NR_prof = Constant("__NR_prof", 44)
__NR_brk = Constant("__NR_brk", 45)
__NR_setgid = Constant("__NR_setgid", 46)
__NR_getgid = Constant("__NR_getgid", 47)
__NR_signal = Constant("__NR_signal", 48)
__NR_geteuid = Constant("__NR_geteuid", 49)
__NR_getegid = Constant("__NR_getegid", 50)
__NR_acct = Constant("__NR_acct", 51)
__NR_umount2 = Constant("__NR_umount2", 52)
__NR_lock = Constant("__NR_lock", 53)
__NR_ioctl = Constant("__NR_ioctl", 54)
__NR_fcntl = Constant("__NR_fcntl", 55)
__NR_mpx = Constant("__NR_mpx", 56)
__NR_setpgid = Constant("__NR_setpgid", 57)
__NR_ulimit = Constant("__NR_ulimit", 58)
__NR_oldolduname = Constant("__NR_oldolduname", 59)
__NR_umask = Constant("__NR_umask", 60)
__NR_chroot = Constant("__NR_chroot", 61)
__NR_ustat = Constant("__NR_ustat", 62)
__NR_dup2 = Constant("__NR_dup2", 63)
__NR_getppid = Constant("__NR_getppid", 64)
__NR_getpgrp = Constant("__NR_getpgrp", 65)
__NR_setsid = Constant("__NR_setsid", 66)
__NR_sigaction = Constant("__NR_sigaction", 67)
__NR_sgetmask = Constant("__NR_sgetmask", 68)
__NR_ssetmask = Constant("__NR_ssetmask", 69)
__NR_setreuid = Constant("__NR_setreuid", 70)
__NR_setregid = Constant("__NR_setregid", 71)
__NR_sigsuspend = Constant("__NR_sigsuspend", 72)
__NR_sigpending = Constant("__NR_sigpending", 73)
__NR_sethostname = Constant("__NR_sethostname", 74)
__NR_setrlimit = Constant("__NR_setrlimit", 75)
__NR_getrlimit = Constant("__NR_getrlimit", 76)
__NR_getrusage = Constant("__NR_getrusage", 77)
__NR_gettimeofday = Constant("__NR_gettimeofday", 78)
__NR_settimeofday = Constant("__NR_settimeofday", 79)
__NR_getgroups = Constant("__NR_getgroups", 80)
__NR_setgroups = Constant("__NR_setgroups", 81)
__NR_select = Constant("__NR_select", 82)
__NR_symlink = Constant("__NR_symlink", 83)
__NR_oldlstat = Constant("__NR_oldlstat", 84)
__NR_readlink = Constant("__NR_readlink", 85)
__NR_uselib = Constant("__NR_uselib", 86)
__NR_swapon = Constant("__NR_swapon", 87)
__NR_reboot = Constant("__NR_reboot", 88)
__NR_readdir = Constant("__NR_readdir", 89)
__NR_mmap = Constant("__NR_mmap", 90)
__NR_munmap = Constant("__NR_munmap", 91)
__NR_truncate = Constant("__NR_truncate", 92)
__NR_ftruncate = Constant("__NR_ftruncate", 93)
__NR_fchmod = Constant("__NR_fchmod", 94)
__NR_fchown = Constant("__NR_fchown", 95)
__NR_getpriority = Constant("__NR_getpriority", 96)
__NR_setpriority = Constant("__NR_setpriority", 97)
__NR_profil = Constant("__NR_profil", 98)
__NR_statfs = Constant("__NR_statfs", 99)
__NR_fstatfs = Constant("__NR_fstatfs", 100)
__NR_ioperm = Constant("__NR_ioperm", 101)
__NR_socketcall = Constant("__NR_socketcall", 102)
__NR_syslog = Constant("__NR_syslog", 103)
__NR_setitimer = Constant("__NR_setitimer", 104)
__NR_getitimer = Constant("__NR_getitimer", 105)
__NR_stat = Constant("__NR_stat", 106)
__NR_lstat = Constant("__NR_lstat", 107)
__NR_fstat = Constant("__NR_fstat", 108)
__NR_olduname = Constant("__NR_olduname", 109)
__NR_iopl = Constant("__NR_iopl", 110)
__NR_vhangup = Constant("__NR_vhangup", 111)
__NR_idle = Constant("__NR_idle", 112)
__NR_vm86old = Constant("__NR_vm86old", 113)
__NR_wait4 = Constant("__NR_wait4", 114)
__NR_swapoff = Constant("__NR_swapoff", 115)
__NR_sysinfo = Constant("__NR_sysinfo", 116)
__NR_ipc = Constant("__NR_ipc", 117)
__NR_fsync = Constant("__NR_fsync", 118)
__NR_sigreturn = Constant("__NR_sigreturn", 119)
__NR_clone = Constant("__NR_clone", 120)
__NR_setdomainname = Constant("__NR_setdomainname", 121)
__NR_uname = Constant("__NR_uname", 122)
__NR_modify_ldt = Constant("__NR_modify_ldt", 123)
__NR_adjtimex = Constant("__NR_adjtimex", 124)
__NR_mprotect = Constant("__NR_mprotect", 125)
__NR_sigprocmask = Constant("__NR_sigprocmask", 126)
__NR_create_module = Constant("__NR_create_module", 127)
__NR_init_module = Constant("__NR_init_module", 128)
__NR_delete_module = Constant("__NR_delete_module", 129)
__NR_get_kernel_syms = Constant("__NR_get_kernel_syms", 130)
__NR_quotactl = Constant("__NR_quotactl", 131)
__NR_getpgid = Constant("__NR_getpgid", 132)
__NR_fchdir = Constant("__NR_fchdir", 133)
__NR_bdflush = Constant("__NR_bdflush", 134)
__NR_sysfs = Constant("__NR_sysfs", 135)
__NR_personality = Constant("__NR_personality", 136)
__NR_afs_syscall = Constant("__NR_afs_syscall", 137)
__NR_setfsuid = Constant("__NR_setfsuid", 138)
__NR_setfsgid = Constant("__NR_setfsgid", 139)
__NR__llseek = Constant("__NR__llseek", 140)
__NR_getdents = Constant("__NR_getdents", 141)
__NR__newselect = Constant("__NR__newselect", 142)
__NR_flock = Constant("__NR_flock", 143)
__NR_msync = Constant("__NR_msync", 144)
__NR_readv = Constant("__NR_readv", 145)
__NR_writev = Constant("__NR_writev", 146)
__NR_getsid = Constant("__NR_getsid", 147)
__NR_fdatasync = Constant("__NR_fdatasync", 148)
__NR__sysctl = Constant("__NR__sysctl", 149)
__NR_mlock = Constant("__NR_mlock", 150)
__NR_munlock = Constant("__NR_munlock", 151)
__NR_mlockall = Constant("__NR_mlockall", 152)
__NR_munlockall = Constant("__NR_munlockall", 153)
__NR_sched_setparam = Constant("__NR_sched_setparam", 154)
__NR_sched_getparam = Constant("__NR_sched_getparam", 155)
__NR_sched_setscheduler = Constant("__NR_sched_setscheduler", 156)
__NR_sched_getscheduler = Constant("__NR_sched_getscheduler", 157)
__NR_sched_yield = Constant("__NR_sched_yield", 158)
__NR_sched_get_priority_max = Constant("__NR_sched_get_priority_max", 159)
__NR_sched_get_priority_min = Constant("__NR_sched_get_priority_min", 160)
__NR_sched_rr_get_interval = Constant("__NR_sched_rr_get_interval", 161)
__NR_nanosleep = Constant("__NR_nanosleep", 162)
__NR_mremap = Constant("__NR_mremap", 163)
__NR_setresuid = Constant("__NR_setresuid", 164)
__NR_getresuid = Constant("__NR_getresuid", 165)
__NR_vm86 = Constant("__NR_vm86", 166)
__NR_query_module = Constant("__NR_query_module", 167)
__NR_poll = Constant("__NR_poll", 168)
__NR_nfsservctl = Constant("__NR_nfsservctl", 169)
__NR_setresgid = Constant("__NR_setresgid", 170)
__NR_getresgid = Constant("__NR_getresgid", 171)
__NR_prctl = Constant("__NR_prctl", 172)
__NR_rt_sigreturn = Constant("__NR_rt_sigreturn", 173)
__NR_rt_sigaction = Constant("__NR_rt_sigaction", 174)
__NR_rt_sigprocmask = Constant("__NR_rt_sigprocmask", 175)
__NR_rt_sigpending = Constant("__NR_rt_sigpending", 176)
__NR_rt_sigtimedwait = Constant("__NR_rt_sigtimedwait", 177)
__NR_rt_sigqueueinfo = Constant("__NR_rt_sigqueueinfo", 178)
__NR_rt_sigsuspend = Constant("__NR_rt_sigsuspend", 179)
__NR_pread = Constant("__NR_pread", 180)
__NR_pwrite = Constant("__NR_pwrite", 181)
__NR_chown = Constant("__NR_chown", 182)
__NR_getcwd = Constant("__NR_getcwd", 183)
__NR_capget = Constant("__NR_capget", 184)
__NR_capset = Constant("__NR_capset", 185)
__NR_sigaltstack = Constant("__NR_sigaltstack", 186)
__NR_sendfile = Constant("__NR_sendfile", 187)
__NR_getpmsg = Constant("__NR_getpmsg", 188)
__NR_putpmsg = Constant("__NR_putpmsg", 189)
__NR_vfork = Constant("__NR_vfork", 190)
__NR_ugetrlimit = Constant("__NR_ugetrlimit", 191)
__NR_mmap2 = Constant("__NR_mmap2", 192)
__NR_truncate64 = Constant("__NR_truncate64", 193)
__NR_ftruncate64 = Constant("__NR_ftruncate64", 194)
__NR_stat64 = Constant("__NR_stat64", 195)
__NR_lstat64 = Constant("__NR_lstat64", 196)
__NR_fstat64 = Constant("__NR_fstat64", 197)
__NR_lchown32 = Constant("__NR_lchown32", 198)
__NR_getuid32 = Constant("__NR_getuid32", 199)
__NR_getgid32 = Constant("__NR_getgid32", 200)
__NR_geteuid32 = Constant("__NR_geteuid32", 201)
__NR_getegid32 = Constant("__NR_getegid32", 202)
__NR_setreuid32 = Constant("__NR_setreuid32", 203)
__NR_setregid32 = Constant("__NR_setregid32", 204)
__NR_getgroups32 = Constant("__NR_getgroups32", 205)
__NR_setgroups32 = Constant("__NR_setgroups32", 206)
__NR_fchown32 = Constant("__NR_fchown32", 207)
__NR_setresuid32 = Constant("__NR_setresuid32", 208)
__NR_getresuid32 = Constant("__NR_getresuid32", 209)
__NR_setresgid32 = Constant("__NR_setresgid32", 210)
__NR_getresgid32 = Constant("__NR_getresgid32", 211)
__NR_chown32 = Constant("__NR_chown32", 212)
__NR_setuid32 = Constant("__NR_setuid32", 213)
__NR_setgid32 = Constant("__NR_setgid32", 214)
__NR_setfsuid32 = Constant("__NR_setfsuid32", 215)
__NR_setfsgid32 = Constant("__NR_setfsgid32", 216)
__NR_pivot_root = Constant("__NR_pivot_root", 217)
__NR_mincore = Constant("__NR_mincore", 218)
__NR_madvise = Constant("__NR_madvise", 219)
__NR_getdents64 = Constant("__NR_getdents64", 220)
__NR_fcntl64 = Constant("__NR_fcntl64", 221)
__NR_gettid = Constant("__NR_gettid", 224)
__NR_readahead = Constant("__NR_readahead", 225)
__NR_setxattr = Constant("__NR_setxattr", 226)
__NR_lsetxattr = Constant("__NR_lsetxattr", 227)
__NR_fsetxattr = Constant("__NR_fsetxattr", 228)
__NR_getxattr = Constant("__NR_getxattr", 229)
__NR_lgetxattr = Constant("__NR_lgetxattr", 230)
__NR_fgetxattr = Constant("__NR_fgetxattr", 231)
__NR_listxattr = Constant("__NR_listxattr", 232)
__NR_llistxattr = Constant("__NR_llistxattr", 233)
__NR_flistxattr = Constant("__NR_flistxattr", 234)
__NR_removexattr = Constant("__NR_removexattr", 235)
__NR_lremovexattr = Constant("__NR_lremovexattr", 236)
__NR_fremovexattr = Constant("__NR_fremovexattr", 237)
__NR_tkill = Constant("__NR_tkill", 238)
__NR_sendfile64 = Constant("__NR_sendfile64", 239)
__NR_futex = Constant("__NR_futex", 240)
__NR_sched_setaffinity = Constant("__NR_sched_setaffinity", 241)
__NR_sched_getaffinity = Constant("__NR_sched_getaffinity", 242)
__NR_set_thread_area = Constant("__NR_set_thread_area", 243)
__NR_get_thread_area = Constant("__NR_get_thread_area", 244)
__NR_io_setup = Constant("__NR_io_setup", 245)
__NR_io_destroy = Constant("__NR_io_destroy", 246)
__NR_io_getevents = Constant("__NR_io_getevents", 247)
__NR_io_submit = Constant("__NR_io_submit", 248)
__NR_io_cancel = Constant("__NR_io_cancel", 249)
__NR_fadvise64 = Constant("__NR_fadvise64", 250)
__NR_exit_group = Constant("__NR_exit_group", 252)
__NR_lookup_dcookie = Constant("__NR_lookup_dcookie", 253)
__NR_epoll_create = Constant("__NR_epoll_create", 254)
__NR_epoll_ctl = Constant("__NR_epoll_ctl", 255)
__NR_epoll_wait = Constant("__NR_epoll_wait", 256)
__NR_remap_file_pages = Constant("__NR_remap_file_pages", 257)
__NR_set_tid_address = Constant("__NR_set_tid_address", 258)
__NR_timer_create = Constant("__NR_timer_create", 259)
__NR_timer_settime = Constant("__NR_timer_settime", (259 + 1))
__NR_timer_gettime = Constant("__NR_timer_gettime", (259 + 2))
__NR_timer_getoverrun = Constant("__NR_timer_getoverrun", (259 + 3))
__NR_timer_delete = Constant("__NR_timer_delete", (259 + 4))
__NR_clock_settime = Constant("__NR_clock_settime", (259 + 5))
__NR_clock_gettime = Constant("__NR_clock_gettime", (259 + 6))
__NR_clock_getres = Constant("__NR_clock_getres", (259 + 7))
__NR_clock_nanosleep = Constant("__NR_clock_nanosleep", (259 + 8))
__NR_statfs64 = Constant("__NR_statfs64", 268)
__NR_fstatfs64 = Constant("__NR_fstatfs64", 269)
__NR_tgkill = Constant("__NR_tgkill", 270)
__NR_utimes = Constant("__NR_utimes", 271)
__NR_fadvise64_64 = Constant("__NR_fadvise64_64", 272)
__NR_vserver = Constant("__NR_vserver", 273)
__NR_mbind = Constant("__NR_mbind", 274)
__NR_get_mempolicy = Constant("__NR_get_mempolicy", 275)
__NR_set_mempolicy = Constant("__NR_set_mempolicy", 276)
__NR_mq_open = Constant("__NR_mq_open", 277)
__NR_mq_unlink = Constant("__NR_mq_unlink", (277 + 1))
__NR_mq_timedsend = Constant("__NR_mq_timedsend", (277 + 2))
__NR_mq_timedreceive = Constant("__NR_mq_timedreceive", (277 + 3))
__NR_mq_notify = Constant("__NR_mq_notify", (277 + 4))
__NR_mq_getsetattr = Constant("__NR_mq_getsetattr", (277 + 5))
__NR_sys_kexec_load = Constant("__NR_sys_kexec_load", 283)
__NR_waitid = Constant("__NR_waitid", 284)
__NR_add_key = Constant("__NR_add_key", 286)
__NR_request_key = Constant("__NR_request_key", 287)
__NR_keyctl = Constant("__NR_keyctl", 288)
__NR_ioprio_set = Constant("__NR_ioprio_set", 289)
__NR_ioprio_get = Constant("__NR_ioprio_get", 290)
__NR_inotify_init = Constant("__NR_inotify_init", 291)
__NR_inotify_add_watch = Constant("__NR_inotify_add_watch", 292)
__NR_inotify_rm_watch = Constant("__NR_inotify_rm_watch", 293)
__NR_migrate_pages = Constant("__NR_migrate_pages", 294)
__NR_openat = Constant("__NR_openat", 295)
__NR_mkdirat = Constant("__NR_mkdirat", 296)
__NR_mknodat = Constant("__NR_mknodat", 297)
__NR_fchownat = Constant("__NR_fchownat", 298)
__NR_futimesat = Constant("__NR_futimesat", 299)
__NR_fstatat64 = Constant("__NR_fstatat64", 300)
__NR_unlinkat = Constant("__NR_unlinkat", 301)
__NR_renameat = Constant("__NR_renameat", 302)
__NR_linkat = Constant("__NR_linkat", 303)
__NR_symlinkat = Constant("__NR_symlinkat", 304)
__NR_readlinkat = Constant("__NR_readlinkat", 305)
__NR_fchmodat = Constant("__NR_fchmodat", 306)
__NR_faccessat = Constant("__NR_faccessat", 307)
__NR_pselect6 = Constant("__NR_pselect6", 308)
__NR_ppoll = Constant("__NR_ppoll", 309)
__NR_unshare = Constant("__NR_unshare", 310)
__NR_set_robust_list = Constant("__NR_set_robust_list", 311)
__NR_get_robust_list = Constant("__NR_get_robust_list", 312)
__NR_splice = Constant("__NR_splice", 313)
__NR_sync_file_range = Constant("__NR_sync_file_range", 314)
__NR_tee = Constant("__NR_tee", 315)
__NR_vmsplice = Constant("__NR_vmsplice", 316)
__NR_move_pages = Constant("__NR_move_pages", 317)
__NR_getcpu = Constant("__NR_getcpu", 318)
__NR_epoll_pwait = Constant("__NR_epoll_pwait", 319)
__NR_utimensat = Constant("__NR_utimensat", 320)
__NR_signalfd = Constant("__NR_signalfd", 321)
__NR_timerfd = Constant("__NR_timerfd", 322)
__NR_eventfd = Constant("__NR_eventfd", 323)
__NR_fallocate = Constant("__NR_fallocate", 324)
__NR_timerfd_settime = Constant("__NR_timerfd_settime", 325)
__NR_timerfd_gettime = Constant("__NR_timerfd_gettime", 326)
__NR_signalfd4 = Constant("__NR_signalfd4", 327)
__NR_eventfd2 = Constant("__NR_eventfd2", 328)
__NR_epoll_create1 = Constant("__NR_epoll_create1", 329)
__NR_dup3 = Constant("__NR_dup3", 330)
__NR_pipe2 = Constant("__NR_pipe2", 331)
__NR_inotify_init1 = Constant("__NR_inotify_init1", 332)
__NR_preadv = Constant("__NR_preadv", 333)
__NR_pwritev = Constant("__NR_pwritev", 334)
__NR_rt_tgsigqueueinfo = Constant("__NR_rt_tgsigqueueinfo", 335)
__NR_perf_event_open = Constant("__NR_perf_event_open", 336)
__NR_recvmmsg = Constant("__NR_recvmmsg", 337)
__NR_fanotify_init = Constant("__NR_fanotify_init", 338)
__NR_fanotify_mark = Constant("__NR_fanotify_mark", 339)
__NR_prlimit64 = Constant("__NR_prlimit64", 340)
__NR_name_to_handle_at = Constant("__NR_name_to_handle_at", 341)
__NR_open_by_handle_at = Constant("__NR_open_by_handle_at", 342)
__NR_clock_adjtime = Constant("__NR_clock_adjtime", 343)
__NR_syncfs = Constant("__NR_syncfs", 344)
__NR_sendmmsg = Constant("__NR_sendmmsg", 345)
__NR_setns = Constant("__NR_setns", 346)
__NR_process_vm_readv = Constant("__NR_process_vm_readv", 347)
__NR_process_vm_writev = Constant("__NR_process_vm_writev", 348)
__NR_kcmp = Constant("__NR_kcmp", 349)
__NR_finit_module = Constant("__NR_finit_module", 350)
__NR_sched_setattr = Constant("__NR_sched_setattr", 351)
__NR_sched_getattr = Constant("__NR_sched_getattr", 352)
__NR_renameat2 = Constant("__NR_renameat2", 353)
__NR_seccomp = Constant("__NR_seccomp", 354)
__NR_getrandom = Constant("__NR_getrandom", 355)
__NR_memfd_create = Constant("__NR_memfd_create", 356)
__NR_bpf = Constant("__NR_bpf", 357)
__NR_execveat = Constant("__NR_execveat", 358)
__NR_socket = Constant("__NR_socket", 359)
__NR_socketpair = Constant("__NR_socketpair", 360)
__NR_bind = Constant("__NR_bind", 361)
__NR_connect = Constant("__NR_connect", 362)
__NR_listen = Constant("__NR_listen", 363)
__NR_accept4 = Constant("__NR_accept4", 364)
__NR_getsockopt = Constant("__NR_getsockopt", 365)
__NR_setsockopt = Constant("__NR_setsockopt", 366)
__NR_getsockname = Constant("__NR_getsockname", 367)
__NR_getpeername = Constant("__NR_getpeername", 368)
__NR_sendto = Constant("__NR_sendto", 369)
__NR_sendmsg = Constant("__NR_sendmsg", 370)
__NR_recvfrom = Constant("__NR_recvfrom", 371)
__NR_recvmsg = Constant("__NR_recvmsg", 372)
__NR_shutdown = Constant("__NR_shutdown", 373)
__NR_userfaultfd = Constant("__NR_userfaultfd", 374)
__NR_membarrier = Constant("__NR_membarrier", 375)
__NR_mlock2 = Constant("__NR_mlock2", 376)
__NR_copy_file_range = Constant("__NR_copy_file_range", 377)
__NR_preadv2 = Constant("__NR_preadv2", 378)
__NR_pwritev2 = Constant("__NR_pwritev2", 379)
__NR_pkey_mprotect = Constant("__NR_pkey_mprotect", 380)
__NR_pkey_alloc = Constant("__NR_pkey_alloc", 381)
__NR_pkey_free = Constant("__NR_pkey_free", 382)
__NR_statx = Constant("__NR_statx", 383)
__NR_arch_prctl = Constant("__NR_arch_prctl", 384)

SYS_SOCKET = Constant("SYS_SOCKET", 1)
SYS_BIND = Constant("SYS_BIND", 2)
SYS_CONNECT = Constant("SYS_CONNECT", 3)
SYS_LISTEN = Constant("SYS_LISTEN", 4)
SYS_ACCEPT = Constant("SYS_ACCEPT", 5)
SYS_GETSOCKNAME = Constant("SYS_GETSOCKNAME", 6)
SYS_GETPEERNAME = Constant("SYS_GETPEERNAME", 7)
SYS_SOCKETPAIR = Constant("SYS_SOCKETPAIR", 8)
SYS_SEND = Constant("SYS_SEND", 9)
SYS_RECV = Constant("SYS_RECV", 10)
SYS_SENDTO = Constant("SYS_SENDTO", 11)
SYS_RECVFROM = Constant("SYS_RECVFROM", 12)
SYS_SHUTDOWN = Constant("SYS_SHUTDOWN", 13)
SYS_SETSOCKOPT = Constant("SYS_SETSOCKOPT", 14)
SYS_GETSOCKOPT = Constant("SYS_GETSOCKOPT", 15)
SYS_SENDMSG = Constant("SYS_SENDMSG", 16)
SYS_RECVMSG = Constant("SYS_RECVMSG", 17)
__SYS_NERR = Constant("__SYS_NERR", ((129) + 1))
_SYS_TIME_H = Constant("_SYS_TIME_H", 1)
SYS_access = Constant("SYS_access", 33)
SYS_acct = Constant("SYS_acct", 51)
SYS_add_key = Constant("SYS_add_key", 286)
SYS_adjtimex = Constant("SYS_adjtimex", 124)
SYS_afs_syscall = Constant("SYS_afs_syscall", 137)
SYS_alarm = Constant("SYS_alarm", 27)
SYS_bdflush = Constant("SYS_bdflush", 134)
SYS_break = Constant("SYS_break", 17)
SYS_brk = Constant("SYS_brk", 45)
SYS_capget = Constant("SYS_capget", 184)
SYS_capset = Constant("SYS_capset", 185)
SYS_chdir = Constant("SYS_chdir", 12)
SYS_chmod = Constant("SYS_chmod", 15)
SYS_chown = Constant("SYS_chown", 182)
SYS_chown32 = Constant("SYS_chown32", 212)
SYS_chroot = Constant("SYS_chroot", 61)
SYS_clock_getres = Constant("SYS_clock_getres", (259 + 7))
SYS_clock_gettime = Constant("SYS_clock_gettime", (259 + 6))
SYS_clock_nanosleep = Constant("SYS_clock_nanosleep", (259 + 8))
SYS_clock_settime = Constant("SYS_clock_settime", (259 + 5))
SYS_clone = Constant("SYS_clone", 120)
SYS_close = Constant("SYS_close", 6)
SYS_creat = Constant("SYS_creat", 8)
SYS_create_module = Constant("SYS_create_module", 127)
SYS_delete_module = Constant("SYS_delete_module", 129)
SYS_dup = Constant("SYS_dup", 41)
SYS_dup2 = Constant("SYS_dup2", 63)
SYS_dup3 = Constant("SYS_dup3", 330)
SYS_epoll_create = Constant("SYS_epoll_create", 254)
SYS_epoll_create1 = Constant("SYS_epoll_create1", 329)
SYS_epoll_ctl = Constant("SYS_epoll_ctl", 255)
SYS_epoll_pwait = Constant("SYS_epoll_pwait", 319)
SYS_epoll_wait = Constant("SYS_epoll_wait", 256)
SYS_eventfd = Constant("SYS_eventfd", 323)
SYS_eventfd2 = Constant("SYS_eventfd2", 328)
SYS_execve = Constant("SYS_execve", 11)
SYS_exit = Constant("SYS_exit", 1)
SYS_exit_group = Constant("SYS_exit_group", 252)
SYS_faccessat = Constant("SYS_faccessat", 307)
SYS_fadvise64 = Constant("SYS_fadvise64", 250)
SYS_fadvise64_64 = Constant("SYS_fadvise64_64", 272)
SYS_fallocate = Constant("SYS_fallocate", 324)
SYS_fanotify_init = Constant("SYS_fanotify_init", 338)
SYS_fanotify_mark = Constant("SYS_fanotify_mark", 339)
SYS_fchdir = Constant("SYS_fchdir", 133)
SYS_fchmod = Constant("SYS_fchmod", 94)
SYS_fchmodat = Constant("SYS_fchmodat", 306)
SYS_fchown = Constant("SYS_fchown", 95)
SYS_fchown32 = Constant("SYS_fchown32", 207)
SYS_fchownat = Constant("SYS_fchownat", 298)
SYS_fcntl = Constant("SYS_fcntl", 55)
SYS_fcntl64 = Constant("SYS_fcntl64", 221)
SYS_fdatasync = Constant("SYS_fdatasync", 148)
SYS_fgetxattr = Constant("SYS_fgetxattr", 231)
SYS_flistxattr = Constant("SYS_flistxattr", 234)
SYS_flock = Constant("SYS_flock", 143)
SYS_fork = Constant("SYS_fork", 2)
SYS_fremovexattr = Constant("SYS_fremovexattr", 237)
SYS_fsetxattr = Constant("SYS_fsetxattr", 228)
SYS_fstat = Constant("SYS_fstat", 108)
SYS_fstat64 = Constant("SYS_fstat64", 197)
SYS_fstatat64 = Constant("SYS_fstatat64", 300)
SYS_fstatfs = Constant("SYS_fstatfs", 100)
SYS_fstatfs64 = Constant("SYS_fstatfs64", 269)
SYS_fsync = Constant("SYS_fsync", 118)
SYS_ftime = Constant("SYS_ftime", 35)
SYS_ftruncate = Constant("SYS_ftruncate", 93)
SYS_ftruncate64 = Constant("SYS_ftruncate64", 194)
SYS_futex = Constant("SYS_futex", 240)
SYS_futimesat = Constant("SYS_futimesat", 299)
SYS_getcpu = Constant("SYS_getcpu", 318)
SYS_getcwd = Constant("SYS_getcwd", 183)
SYS_getdents = Constant("SYS_getdents", 141)
SYS_getdents64 = Constant("SYS_getdents64", 220)
SYS_getegid = Constant("SYS_getegid", 50)
SYS_getegid32 = Constant("SYS_getegid32", 202)
SYS_geteuid = Constant("SYS_geteuid", 49)
SYS_geteuid32 = Constant("SYS_geteuid32", 201)
SYS_getgid = Constant("SYS_getgid", 47)
SYS_getgid32 = Constant("SYS_getgid32", 200)
SYS_getgroups = Constant("SYS_getgroups", 80)
SYS_getgroups32 = Constant("SYS_getgroups32", 205)
SYS_getitimer = Constant("SYS_getitimer", 105)
SYS_get_kernel_syms = Constant("SYS_get_kernel_syms", 130)
SYS_get_mempolicy = Constant("SYS_get_mempolicy", 275)
SYS_getpgid = Constant("SYS_getpgid", 132)
SYS_getpgrp = Constant("SYS_getpgrp", 65)
SYS_getpid = Constant("SYS_getpid", 20)
SYS_getpmsg = Constant("SYS_getpmsg", 188)
SYS_getppid = Constant("SYS_getppid", 64)
SYS_getpriority = Constant("SYS_getpriority", 96)
SYS_getresgid = Constant("SYS_getresgid", 171)
SYS_getresgid32 = Constant("SYS_getresgid32", 211)
SYS_getresuid = Constant("SYS_getresuid", 165)
SYS_getresuid32 = Constant("SYS_getresuid32", 209)
SYS_getrlimit = Constant("SYS_getrlimit", 76)
SYS_get_robust_list = Constant("SYS_get_robust_list", 312)
SYS_getrusage = Constant("SYS_getrusage", 77)
SYS_getsid = Constant("SYS_getsid", 147)
SYS_get_thread_area = Constant("SYS_get_thread_area", 244)
SYS_gettid = Constant("SYS_gettid", 224)
SYS_gettimeofday = Constant("SYS_gettimeofday", 78)
SYS_getuid = Constant("SYS_getuid", 24)
SYS_getuid32 = Constant("SYS_getuid32", 199)
SYS_getxattr = Constant("SYS_getxattr", 229)
SYS_gtty = Constant("SYS_gtty", 32)
SYS_idle = Constant("SYS_idle", 112)
SYS_init_module = Constant("SYS_init_module", 128)
SYS_inotify_add_watch = Constant("SYS_inotify_add_watch", 292)
SYS_inotify_init = Constant("SYS_inotify_init", 291)
SYS_inotify_init1 = Constant("SYS_inotify_init1", 332)
SYS_inotify_rm_watch = Constant("SYS_inotify_rm_watch", 293)
SYS_io_cancel = Constant("SYS_io_cancel", 249)
SYS_ioctl = Constant("SYS_ioctl", 54)
SYS_io_destroy = Constant("SYS_io_destroy", 246)
SYS_io_getevents = Constant("SYS_io_getevents", 247)
SYS_ioperm = Constant("SYS_ioperm", 101)
SYS_iopl = Constant("SYS_iopl", 110)
SYS_ioprio_get = Constant("SYS_ioprio_get", 290)
SYS_ioprio_set = Constant("SYS_ioprio_set", 289)
SYS_io_setup = Constant("SYS_io_setup", 245)
SYS_io_submit = Constant("SYS_io_submit", 248)
SYS_ipc = Constant("SYS_ipc", 117)
SYS_keyctl = Constant("SYS_keyctl", 288)
SYS_kill = Constant("SYS_kill", 37)
SYS_lchown = Constant("SYS_lchown", 16)
SYS_lchown32 = Constant("SYS_lchown32", 198)
SYS_lgetxattr = Constant("SYS_lgetxattr", 230)
SYS_link = Constant("SYS_link", 9)
SYS_linkat = Constant("SYS_linkat", 303)
SYS_listxattr = Constant("SYS_listxattr", 232)
SYS_llistxattr = Constant("SYS_llistxattr", 233)
SYS__llseek = Constant("SYS__llseek", 140)
SYS_lock = Constant("SYS_lock", 53)
SYS_lookup_dcookie = Constant("SYS_lookup_dcookie", 253)
SYS_lremovexattr = Constant("SYS_lremovexattr", 236)
SYS_lseek = Constant("SYS_lseek", 19)
SYS_lsetxattr = Constant("SYS_lsetxattr", 227)
SYS_lstat = Constant("SYS_lstat", 107)
SYS_lstat64 = Constant("SYS_lstat64", 196)
SYS_madvise = Constant("SYS_madvise", 219)
SYS_madvise1 = Constant("SYS_madvise1", 219)
SYS_mbind = Constant("SYS_mbind", 274)
SYS_migrate_pages = Constant("SYS_migrate_pages", 294)
SYS_mincore = Constant("SYS_mincore", 218)
SYS_mkdir = Constant("SYS_mkdir", 39)
SYS_mkdirat = Constant("SYS_mkdirat", 296)
SYS_mknod = Constant("SYS_mknod", 14)
SYS_mknodat = Constant("SYS_mknodat", 297)
SYS_mlock = Constant("SYS_mlock", 150)
SYS_mlockall = Constant("SYS_mlockall", 152)
SYS_mmap = Constant("SYS_mmap", 90)
SYS_mmap2 = Constant("SYS_mmap2", 192)
SYS_modify_ldt = Constant("SYS_modify_ldt", 123)
SYS_mount = Constant("SYS_mount", 21)
SYS_move_pages = Constant("SYS_move_pages", 317)
SYS_mprotect = Constant("SYS_mprotect", 125)
SYS_mpx = Constant("SYS_mpx", 56)
SYS_mq_getsetattr = Constant("SYS_mq_getsetattr", (277 + 5))
SYS_mq_notify = Constant("SYS_mq_notify", (277 + 4))
SYS_mq_open = Constant("SYS_mq_open", 277)
SYS_mq_timedreceive = Constant("SYS_mq_timedreceive", (277 + 3))
SYS_mq_timedsend = Constant("SYS_mq_timedsend", (277 + 2))
SYS_mq_unlink = Constant("SYS_mq_unlink", (277 + 1))
SYS_mremap = Constant("SYS_mremap", 163)
SYS_msync = Constant("SYS_msync", 144)
SYS_munlock = Constant("SYS_munlock", 151)
SYS_munlockall = Constant("SYS_munlockall", 153)
SYS_munmap = Constant("SYS_munmap", 91)
SYS_nanosleep = Constant("SYS_nanosleep", 162)
SYS__newselect = Constant("SYS__newselect", 142)
SYS_nfsservctl = Constant("SYS_nfsservctl", 169)
SYS_nice = Constant("SYS_nice", 34)
SYS_oldfstat = Constant("SYS_oldfstat", 28)
SYS_oldlstat = Constant("SYS_oldlstat", 84)
SYS_oldolduname = Constant("SYS_oldolduname", 59)
SYS_oldstat = Constant("SYS_oldstat", 18)
SYS_olduname = Constant("SYS_olduname", 109)
SYS_open = Constant("SYS_open", 5)
SYS_openat = Constant("SYS_openat", 295)
SYS_pause = Constant("SYS_pause", 29)
SYS_perf_event_open = Constant("SYS_perf_event_open", 336)
SYS_personality = Constant("SYS_personality", 136)
SYS_pipe = Constant("SYS_pipe", 42)
SYS_pipe2 = Constant("SYS_pipe2", 331)
SYS_pivot_root = Constant("SYS_pivot_root", 217)
SYS_poll = Constant("SYS_poll", 168)
SYS_ppoll = Constant("SYS_ppoll", 309)
SYS_prctl = Constant("SYS_prctl", 172)
SYS_pread = Constant("SYS_pread", 180)
SYS_preadv = Constant("SYS_preadv", 333)
SYS_prlimit64 = Constant("SYS_prlimit64", 340)
SYS_prof = Constant("SYS_prof", 44)
SYS_profil = Constant("SYS_profil", 98)
SYS_pselect6 = Constant("SYS_pselect6", 308)
SYS_ptrace = Constant("SYS_ptrace", 26)
SYS_putpmsg = Constant("SYS_putpmsg", 189)
SYS_pwrite = Constant("SYS_pwrite", 181)
SYS_pwritev = Constant("SYS_pwritev", 334)
SYS_query_module = Constant("SYS_query_module", 167)
SYS_quotactl = Constant("SYS_quotactl", 131)
SYS_read = Constant("SYS_read", 3)
SYS_readahead = Constant("SYS_readahead", 225)
SYS_readdir = Constant("SYS_readdir", 89)
SYS_readlink = Constant("SYS_readlink", 85)
SYS_readlinkat = Constant("SYS_readlinkat", 305)
SYS_readv = Constant("SYS_readv", 145)
SYS_reboot = Constant("SYS_reboot", 88)
SYS_recvmmsg = Constant("SYS_recvmmsg", 337)
SYS_remap_file_pages = Constant("SYS_remap_file_pages", 257)
SYS_removexattr = Constant("SYS_removexattr", 235)
SYS_rename = Constant("SYS_rename", 38)
SYS_renameat = Constant("SYS_renameat", 302)
SYS_request_key = Constant("SYS_request_key", 287)
SYS_rmdir = Constant("SYS_rmdir", 40)
SYS_rt_sigaction = Constant("SYS_rt_sigaction", 174)
SYS_rt_sigpending = Constant("SYS_rt_sigpending", 176)
SYS_rt_sigprocmask = Constant("SYS_rt_sigprocmask", 175)
SYS_rt_sigqueueinfo = Constant("SYS_rt_sigqueueinfo", 178)
SYS_rt_sigreturn = Constant("SYS_rt_sigreturn", 173)
SYS_rt_sigsuspend = Constant("SYS_rt_sigsuspend", 179)
SYS_rt_sigtimedwait = Constant("SYS_rt_sigtimedwait", 177)
SYS_rt_tgsigqueueinfo = Constant("SYS_rt_tgsigqueueinfo", 335)
SYS_sched_getaffinity = Constant("SYS_sched_getaffinity", 242)
SYS_sched_getparam = Constant("SYS_sched_getparam", 155)
SYS_sched_get_priority_max = Constant("SYS_sched_get_priority_max", 159)
SYS_sched_get_priority_min = Constant("SYS_sched_get_priority_min", 160)
SYS_sched_getscheduler = Constant("SYS_sched_getscheduler", 157)
SYS_sched_rr_get_interval = Constant("SYS_sched_rr_get_interval", 161)
SYS_sched_setaffinity = Constant("SYS_sched_setaffinity", 241)
SYS_sched_setparam = Constant("SYS_sched_setparam", 154)
SYS_sched_setscheduler = Constant("SYS_sched_setscheduler", 156)
SYS_sched_yield = Constant("SYS_sched_yield", 158)
SYS_select = Constant("SYS_select", 82)
SYS_sendfile = Constant("SYS_sendfile", 187)
SYS_sendfile64 = Constant("SYS_sendfile64", 239)
SYS_setdomainname = Constant("SYS_setdomainname", 121)
SYS_setfsgid = Constant("SYS_setfsgid", 139)
SYS_setfsgid32 = Constant("SYS_setfsgid32", 216)
SYS_setfsuid = Constant("SYS_setfsuid", 138)
SYS_setfsuid32 = Constant("SYS_setfsuid32", 215)
SYS_setgid = Constant("SYS_setgid", 46)
SYS_setgid32 = Constant("SYS_setgid32", 214)
SYS_setgroups = Constant("SYS_setgroups", 81)
SYS_setgroups32 = Constant("SYS_setgroups32", 206)
SYS_sethostname = Constant("SYS_sethostname", 74)
SYS_setitimer = Constant("SYS_setitimer", 104)
SYS_set_mempolicy = Constant("SYS_set_mempolicy", 276)
SYS_setpgid = Constant("SYS_setpgid", 57)
SYS_setpriority = Constant("SYS_setpriority", 97)
SYS_setregid = Constant("SYS_setregid", 71)
SYS_setregid32 = Constant("SYS_setregid32", 204)
SYS_setresgid = Constant("SYS_setresgid", 170)
SYS_setresgid32 = Constant("SYS_setresgid32", 210)
SYS_setresuid = Constant("SYS_setresuid", 164)
SYS_setresuid32 = Constant("SYS_setresuid32", 208)
SYS_setreuid = Constant("SYS_setreuid", 70)
SYS_setreuid32 = Constant("SYS_setreuid32", 203)
SYS_setrlimit = Constant("SYS_setrlimit", 75)
SYS_set_robust_list = Constant("SYS_set_robust_list", 311)
SYS_setsid = Constant("SYS_setsid", 66)
SYS_set_thread_area = Constant("SYS_set_thread_area", 243)
SYS_set_tid_address = Constant("SYS_set_tid_address", 258)
SYS_settimeofday = Constant("SYS_settimeofday", 79)
SYS_setuid = Constant("SYS_setuid", 23)
SYS_setuid32 = Constant("SYS_setuid32", 213)
SYS_setxattr = Constant("SYS_setxattr", 226)
SYS_sgetmask = Constant("SYS_sgetmask", 68)
SYS_sigaction = Constant("SYS_sigaction", 67)
SYS_sigaltstack = Constant("SYS_sigaltstack", 186)
SYS_signal = Constant("SYS_signal", 48)
SYS_signalfd = Constant("SYS_signalfd", 321)
SYS_signalfd4 = Constant("SYS_signalfd4", 327)
SYS_sigpending = Constant("SYS_sigpending", 73)
SYS_sigprocmask = Constant("SYS_sigprocmask", 126)
SYS_sigreturn = Constant("SYS_sigreturn", 119)
SYS_sigsuspend = Constant("SYS_sigsuspend", 72)
SYS_socketcall = Constant("SYS_socketcall", 102)
SYS_splice = Constant("SYS_splice", 313)
SYS_ssetmask = Constant("SYS_ssetmask", 69)
SYS_stat = Constant("SYS_stat", 106)
SYS_stat64 = Constant("SYS_stat64", 195)
SYS_statfs = Constant("SYS_statfs", 99)
SYS_statfs64 = Constant("SYS_statfs64", 268)
SYS_stime = Constant("SYS_stime", 25)
SYS_stty = Constant("SYS_stty", 31)
SYS_swapoff = Constant("SYS_swapoff", 115)
SYS_swapon = Constant("SYS_swapon", 87)
SYS_symlink = Constant("SYS_symlink", 83)
SYS_symlinkat = Constant("SYS_symlinkat", 304)
SYS_sync = Constant("SYS_sync", 36)
SYS_sync_file_range = Constant("SYS_sync_file_range", 314)
SYS__sysctl = Constant("SYS__sysctl", 149)
SYS_sysfs = Constant("SYS_sysfs", 135)
SYS_sysinfo = Constant("SYS_sysinfo", 116)
SYS_sys_kexec_load = Constant("SYS_sys_kexec_load", 283)
SYS_syslog = Constant("SYS_syslog", 103)
SYS_tee = Constant("SYS_tee", 315)
SYS_tgkill = Constant("SYS_tgkill", 270)
SYS_time = Constant("SYS_time", 13)
SYS_timer_create = Constant("SYS_timer_create", 259)
SYS_timer_delete = Constant("SYS_timer_delete", (259 + 4))
SYS_timerfd = Constant("SYS_timerfd", 322)
SYS_timerfd_gettime = Constant("SYS_timerfd_gettime", 326)
SYS_timerfd_settime = Constant("SYS_timerfd_settime", 325)
SYS_timer_getoverrun = Constant("SYS_timer_getoverrun", (259 + 3))
SYS_timer_gettime = Constant("SYS_timer_gettime", (259 + 2))
SYS_timer_settime = Constant("SYS_timer_settime", (259 + 1))
SYS_times = Constant("SYS_times", 43)
SYS_tkill = Constant("SYS_tkill", 238)
SYS_truncate = Constant("SYS_truncate", 92)
SYS_truncate64 = Constant("SYS_truncate64", 193)
SYS_ugetrlimit = Constant("SYS_ugetrlimit", 191)
SYS_ulimit = Constant("SYS_ulimit", 58)
SYS_umask = Constant("SYS_umask", 60)
SYS_umount = Constant("SYS_umount", 22)
SYS_umount2 = Constant("SYS_umount2", 52)
SYS_uname = Constant("SYS_uname", 122)
SYS_unlink = Constant("SYS_unlink", 10)
SYS_unlinkat = Constant("SYS_unlinkat", 301)
SYS_unshare = Constant("SYS_unshare", 310)
SYS_uselib = Constant("SYS_uselib", 86)
SYS_ustat = Constant("SYS_ustat", 62)
SYS_utime = Constant("SYS_utime", 30)
SYS_utimensat = Constant("SYS_utimensat", 320)
SYS_utimes = Constant("SYS_utimes", 271)
SYS_vfork = Constant("SYS_vfork", 190)
SYS_vhangup = Constant("SYS_vhangup", 111)
SYS_vm86 = Constant("SYS_vm86", 166)
SYS_vm86old = Constant("SYS_vm86old", 113)
SYS_vmsplice = Constant("SYS_vmsplice", 316)
SYS_vserver = Constant("SYS_vserver", 273)
SYS_wait4 = Constant("SYS_wait4", 114)
SYS_waitid = Constant("SYS_waitid", 284)
SYS_waitpid = Constant("SYS_waitpid", 7)
SYS_write = Constant("SYS_write", 4)
SYS_writev = Constant("SYS_writev", 146)
SYS_socketcall_socket = Constant("SYS_socketcall_socket", 1)
SYS_socketcall_bind = Constant("SYS_socketcall_bind", 2)
SYS_socketcall_connect = Constant("SYS_socketcall_connect", 3)
SYS_socketcall_listen = Constant("SYS_socketcall_listen", 4)
SYS_socketcall_accept = Constant("SYS_socketcall_accept", 5)
SYS_socketcall_getsockname = Constant("SYS_socketcall_getsockname", 6)
SYS_socketcall_getpeername = Constant("SYS_socketcall_getpeername", 7)
SYS_socketcall_socketpair = Constant("SYS_socketcall_socketpair", 8)
SYS_socketcall_send = Constant("SYS_socketcall_send", 9)
SYS_socketcall_recv = Constant("SYS_socketcall_recv", 10)
SYS_socketcall_sendto = Constant("SYS_socketcall_sendto", 11)
SYS_socketcall_recvfrom = Constant("SYS_socketcall_recvfrom", 12)
SYS_socketcall_shutdown = Constant("SYS_socketcall_shutdown", 13)
SYS_socketcall_setsockopt = Constant("SYS_socketcall_setsockopt", 14)
SYS_socketcall_getsockopt = Constant("SYS_socketcall_getsockopt", 15)
SYS_socketcall_sendmsg = Constant("SYS_socketcall_sendmsg", 16)
SYS_socketcall_recvmsg = Constant("SYS_socketcall_recvmsg", 17)
