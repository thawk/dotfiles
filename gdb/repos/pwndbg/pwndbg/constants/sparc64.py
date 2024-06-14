from __future__ import annotations

from .constant import Constant

__NR_exit = Constant("__NR_exit", 1)
__NR_fork = Constant("__NR_fork", 2)
__NR_read = Constant("__NR_read", 3)
__NR_write = Constant("__NR_write", 4)
__NR_open = Constant("__NR_open", 5)
__NR_close = Constant("__NR_close", 6)
__NR_wait4 = Constant("__NR_wait4", 7)
__NR_creat = Constant("__NR_creat", 8)
__NR_link = Constant("__NR_link", 9)
__NR_unlink = Constant("__NR_unlink", 10)
__NR_execv = Constant("__NR_execv", 11)
__NR_chdir = Constant("__NR_chdir", 12)
__NR_chown = Constant("__NR_chown", 13)
__NR_mknod = Constant("__NR_mknod", 14)
__NR_chmod = Constant("__NR_chmod", 15)
__NR_lchown = Constant("__NR_lchown", 16)
__NR_brk = Constant("__NR_brk", 17)
__NR_perfctr = Constant("__NR_perfctr", 18)
__NR_lseek = Constant("__NR_lseek", 19)
__NR_getpid = Constant("__NR_getpid", 20)
__NR_capget = Constant("__NR_capget", 21)
__NR_capset = Constant("__NR_capset", 22)
__NR_setuid = Constant("__NR_setuid", 23)
__NR_getuid = Constant("__NR_getuid", 24)
__NR_ptrace = Constant("__NR_ptrace", 26)
__NR_alarm = Constant("__NR_alarm", 27)
__NR_sigaltstack = Constant("__NR_sigaltstack", 28)
__NR_pause = Constant("__NR_pause", 29)
__NR_utime = Constant("__NR_utime", 30)
__NR_access = Constant("__NR_access", 33)
__NR_nice = Constant("__NR_nice", 34)
__NR_sync = Constant("__NR_sync", 36)
__NR_kill = Constant("__NR_kill", 37)
__NR_stat = Constant("__NR_stat", 38)
__NR_sendfile = Constant("__NR_sendfile", 39)
__NR_lstat = Constant("__NR_lstat", 40)
__NR_dup = Constant("__NR_dup", 41)
__NR_pipe = Constant("__NR_pipe", 42)
__NR_times = Constant("__NR_times", 43)
__NR_umount2 = Constant("__NR_umount2", 45)
__NR_setgid = Constant("__NR_setgid", 46)
__NR_getgid = Constant("__NR_getgid", 47)
__NR_signal = Constant("__NR_signal", 48)
__NR_geteuid = Constant("__NR_geteuid", 49)
__NR_getegid = Constant("__NR_getegid", 50)
__NR_acct = Constant("__NR_acct", 51)
__NR_memory_ordering = Constant("__NR_memory_ordering", 52)
__NR_ioctl = Constant("__NR_ioctl", 54)
__NR_reboot = Constant("__NR_reboot", 55)
__NR_symlink = Constant("__NR_symlink", 57)
__NR_readlink = Constant("__NR_readlink", 58)
__NR_execve = Constant("__NR_execve", 59)
__NR_umask = Constant("__NR_umask", 60)
__NR_chroot = Constant("__NR_chroot", 61)
__NR_fstat = Constant("__NR_fstat", 62)
__NR_getpagesize = Constant("__NR_getpagesize", 64)
__NR_msync = Constant("__NR_msync", 65)
__NR_vfork = Constant("__NR_vfork", 66)
__NR_pread = Constant("__NR_pread", 67)
__NR_pwrite = Constant("__NR_pwrite", 68)
__NR_mmap = Constant("__NR_mmap", 71)
__NR_munmap = Constant("__NR_munmap", 73)
__NR_mprotect = Constant("__NR_mprotect", 74)
__NR_madvise = Constant("__NR_madvise", 75)
__NR_vhangup = Constant("__NR_vhangup", 76)
__NR_mincore = Constant("__NR_mincore", 78)
__NR_getgroups = Constant("__NR_getgroups", 79)
__NR_setgroups = Constant("__NR_setgroups", 80)
__NR_getpgrp = Constant("__NR_getpgrp", 81)
__NR_setitimer = Constant("__NR_setitimer", 83)
__NR_swapon = Constant("__NR_swapon", 85)
__NR_getitimer = Constant("__NR_getitimer", 86)
__NR_sethostname = Constant("__NR_sethostname", 88)
__NR_dup2 = Constant("__NR_dup2", 90)
__NR_fcntl = Constant("__NR_fcntl", 92)
__NR_select = Constant("__NR_select", 93)
__NR_fsync = Constant("__NR_fsync", 95)
__NR_setpriority = Constant("__NR_setpriority", 96)
__NR_socket = Constant("__NR_socket", 97)
__NR_connect = Constant("__NR_connect", 98)
__NR_accept = Constant("__NR_accept", 99)
__NR_getpriority = Constant("__NR_getpriority", 100)
__NR_rt_sigreturn = Constant("__NR_rt_sigreturn", 101)
__NR_rt_sigaction = Constant("__NR_rt_sigaction", 102)
__NR_rt_sigprocmask = Constant("__NR_rt_sigprocmask", 103)
__NR_rt_sigpending = Constant("__NR_rt_sigpending", 104)
__NR_rt_sigtimedwait = Constant("__NR_rt_sigtimedwait", 105)
__NR_rt_sigqueueinfo = Constant("__NR_rt_sigqueueinfo", 106)
__NR_rt_sigsuspend = Constant("__NR_rt_sigsuspend", 107)
__NR_setresuid = Constant("__NR_setresuid", 108)
__NR_getresuid = Constant("__NR_getresuid", 109)
__NR_setresgid = Constant("__NR_setresgid", 110)
__NR_getresgid = Constant("__NR_getresgid", 111)
__NR_recvmsg = Constant("__NR_recvmsg", 113)
__NR_sendmsg = Constant("__NR_sendmsg", 114)
__NR_gettimeofday = Constant("__NR_gettimeofday", 116)
__NR_getrusage = Constant("__NR_getrusage", 117)
__NR_getsockopt = Constant("__NR_getsockopt", 118)
__NR_getcwd = Constant("__NR_getcwd", 119)
__NR_readv = Constant("__NR_readv", 120)
__NR_writev = Constant("__NR_writev", 121)
__NR_settimeofday = Constant("__NR_settimeofday", 122)
__NR_fchown = Constant("__NR_fchown", 123)
__NR_fchmod = Constant("__NR_fchmod", 124)
__NR_recvfrom = Constant("__NR_recvfrom", 125)
__NR_setreuid = Constant("__NR_setreuid", 126)
__NR_setregid = Constant("__NR_setregid", 127)
__NR_rename = Constant("__NR_rename", 128)
__NR_truncate = Constant("__NR_truncate", 129)
__NR_ftruncate = Constant("__NR_ftruncate", 130)
__NR_flock = Constant("__NR_flock", 131)
__NR_sendto = Constant("__NR_sendto", 133)
__NR_shutdown = Constant("__NR_shutdown", 134)
__NR_socketpair = Constant("__NR_socketpair", 135)
__NR_mkdir = Constant("__NR_mkdir", 136)
__NR_rmdir = Constant("__NR_rmdir", 137)
__NR_utimes = Constant("__NR_utimes", 138)
__NR_sendfile64 = Constant("__NR_sendfile64", 140)
__NR_getpeername = Constant("__NR_getpeername", 141)
__NR_futex = Constant("__NR_futex", 142)
__NR_gettid = Constant("__NR_gettid", 143)
__NR_getrlimit = Constant("__NR_getrlimit", 144)
__NR_setrlimit = Constant("__NR_setrlimit", 145)
__NR_pivot_root = Constant("__NR_pivot_root", 146)
__NR_prctl = Constant("__NR_prctl", 147)
__NR_pciconfig_read = Constant("__NR_pciconfig_read", 148)
__NR_pciconfig_write = Constant("__NR_pciconfig_write", 149)
__NR_getsockname = Constant("__NR_getsockname", 150)
__NR_poll = Constant("__NR_poll", 153)
__NR_getdents64 = Constant("__NR_getdents64", 154)
__NR_statfs = Constant("__NR_statfs", 157)
__NR_fstatfs = Constant("__NR_fstatfs", 158)
__NR_umount = Constant("__NR_umount", 159)
__NR_sched_set_affinity = Constant("__NR_sched_set_affinity", 160)
__NR_sched_get_affinity = Constant("__NR_sched_get_affinity", 161)
__NR_getdomainname = Constant("__NR_getdomainname", 162)
__NR_setdomainname = Constant("__NR_setdomainname", 163)
__NR_utrap_install = Constant("__NR_utrap_install", 164)
__NR_quotactl = Constant("__NR_quotactl", 165)
__NR_set_tid_address = Constant("__NR_set_tid_address", 166)
__NR_mount = Constant("__NR_mount", 167)
__NR_ustat = Constant("__NR_ustat", 168)
__NR_setxattr = Constant("__NR_setxattr", 169)
__NR_lsetxattr = Constant("__NR_lsetxattr", 170)
__NR_fsetxattr = Constant("__NR_fsetxattr", 171)
__NR_getxattr = Constant("__NR_getxattr", 172)
__NR_lgetxattr = Constant("__NR_lgetxattr", 173)
__NR_getdents = Constant("__NR_getdents", 174)
__NR_setsid = Constant("__NR_setsid", 175)
__NR_fchdir = Constant("__NR_fchdir", 176)
__NR_fgetxattr = Constant("__NR_fgetxattr", 177)
__NR_listxattr = Constant("__NR_listxattr", 178)
__NR_llistxattr = Constant("__NR_llistxattr", 179)
__NR_flistxattr = Constant("__NR_flistxattr", 180)
__NR_removexattr = Constant("__NR_removexattr", 181)
__NR_lremovexattr = Constant("__NR_lremovexattr", 182)
__NR_sigpending = Constant("__NR_sigpending", 183)
__NR_query_module = Constant("__NR_query_module", 184)
__NR_setpgid = Constant("__NR_setpgid", 185)
__NR_fremovexattr = Constant("__NR_fremovexattr", 186)
__NR_tkill = Constant("__NR_tkill", 187)
__NR_exit_group = Constant("__NR_exit_group", 188)
__NR_uname = Constant("__NR_uname", 189)
__NR_init_module = Constant("__NR_init_module", 190)
__NR_personality = Constant("__NR_personality", 191)
__NR_remap_file_pages = Constant("__NR_remap_file_pages", 192)
__NR_epoll_create = Constant("__NR_epoll_create", 193)
__NR_epoll_ctl = Constant("__NR_epoll_ctl", 194)
__NR_epoll_wait = Constant("__NR_epoll_wait", 195)
__NR_getppid = Constant("__NR_getppid", 197)
__NR_sigaction = Constant("__NR_sigaction", 198)
__NR_sgetmask = Constant("__NR_sgetmask", 199)
__NR_ssetmask = Constant("__NR_ssetmask", 200)
__NR_sigsuspend = Constant("__NR_sigsuspend", 201)
__NR_oldlstat = Constant("__NR_oldlstat", 202)
__NR_uselib = Constant("__NR_uselib", 203)
__NR_readdir = Constant("__NR_readdir", 204)
__NR_readahead = Constant("__NR_readahead", 205)
__NR_socketcall = Constant("__NR_socketcall", 206)
__NR_syslog = Constant("__NR_syslog", 207)
__NR_lookup_dcookie = Constant("__NR_lookup_dcookie", 208)
__NR_fadvise64 = Constant("__NR_fadvise64", 209)
__NR_fadvise64_64 = Constant("__NR_fadvise64_64", 210)
__NR_tgkill = Constant("__NR_tgkill", 211)
__NR_waitpid = Constant("__NR_waitpid", 212)
__NR_swapoff = Constant("__NR_swapoff", 213)
__NR_sysinfo = Constant("__NR_sysinfo", 214)
__NR_ipc = Constant("__NR_ipc", 215)
__NR_sigreturn = Constant("__NR_sigreturn", 216)
__NR_clone = Constant("__NR_clone", 217)
__NR_adjtimex = Constant("__NR_adjtimex", 219)
__NR_sigprocmask = Constant("__NR_sigprocmask", 220)
__NR_create_module = Constant("__NR_create_module", 221)
__NR_delete_module = Constant("__NR_delete_module", 222)
__NR_get_kernel_syms = Constant("__NR_get_kernel_syms", 223)
__NR_getpgid = Constant("__NR_getpgid", 224)
__NR_bdflush = Constant("__NR_bdflush", 225)
__NR_sysfs = Constant("__NR_sysfs", 226)
__NR_afs_syscall = Constant("__NR_afs_syscall", 227)
__NR_setfsuid = Constant("__NR_setfsuid", 228)
__NR_setfsgid = Constant("__NR_setfsgid", 229)
__NR__newselect = Constant("__NR__newselect", 230)
__NR_stime = Constant("__NR_stime", 233)
__NR_statfs64 = Constant("__NR_statfs64", 234)
__NR_fstatfs64 = Constant("__NR_fstatfs64", 235)
__NR__llseek = Constant("__NR__llseek", 236)
__NR_mlock = Constant("__NR_mlock", 237)
__NR_munlock = Constant("__NR_munlock", 238)
__NR_mlockall = Constant("__NR_mlockall", 239)
__NR_munlockall = Constant("__NR_munlockall", 240)
__NR_sched_setparam = Constant("__NR_sched_setparam", 241)
__NR_sched_getparam = Constant("__NR_sched_getparam", 242)
__NR_sched_setscheduler = Constant("__NR_sched_setscheduler", 243)
__NR_sched_getscheduler = Constant("__NR_sched_getscheduler", 244)
__NR_sched_yield = Constant("__NR_sched_yield", 245)
__NR_sched_get_priority_max = Constant("__NR_sched_get_priority_max", 246)
__NR_sched_get_priority_min = Constant("__NR_sched_get_priority_min", 247)
__NR_sched_rr_get_interval = Constant("__NR_sched_rr_get_interval", 248)
__NR_nanosleep = Constant("__NR_nanosleep", 249)
__NR_mremap = Constant("__NR_mremap", 250)
__NR__sysctl = Constant("__NR__sysctl", 251)
__NR_getsid = Constant("__NR_getsid", 252)
__NR_fdatasync = Constant("__NR_fdatasync", 253)
__NR_nfsservctl = Constant("__NR_nfsservctl", 254)
__NR_aplib = Constant("__NR_aplib", 255)
__NR_clock_settime = Constant("__NR_clock_settime", 256)
__NR_clock_gettime = Constant("__NR_clock_gettime", 257)
__NR_clock_getres = Constant("__NR_clock_getres", 258)
__NR_clock_nanosleep = Constant("__NR_clock_nanosleep", 259)
__NR_sched_getaffinity = Constant("__NR_sched_getaffinity", 260)
__NR_sched_setaffinity = Constant("__NR_sched_setaffinity", 261)
__NR_timer_settime = Constant("__NR_timer_settime", 262)
__NR_timer_gettime = Constant("__NR_timer_gettime", 263)
__NR_timer_getoverrun = Constant("__NR_timer_getoverrun", 264)
__NR_timer_delete = Constant("__NR_timer_delete", 265)
__NR_timer_create = Constant("__NR_timer_create", 266)
__NR_io_setup = Constant("__NR_io_setup", 268)
__NR_io_destroy = Constant("__NR_io_destroy", 269)
__NR_io_submit = Constant("__NR_io_submit", 270)
__NR_io_cancel = Constant("__NR_io_cancel", 271)
__NR_io_getevents = Constant("__NR_io_getevents", 272)
__NR_mq_open = Constant("__NR_mq_open", 273)
__NR_mq_unlink = Constant("__NR_mq_unlink", 274)
__NR_mq_timedsend = Constant("__NR_mq_timedsend", 275)
__NR_mq_timedreceive = Constant("__NR_mq_timedreceive", 276)
__NR_mq_notify = Constant("__NR_mq_notify", 277)
__NR_mq_getsetattr = Constant("__NR_mq_getsetattr", 278)
__NR_waitid = Constant("__NR_waitid", 279)
__NR_add_key = Constant("__NR_add_key", 281)
__NR_request_key = Constant("__NR_request_key", 282)
__NR_keyctl = Constant("__NR_keyctl", 283)
__NR_openat = Constant("__NR_openat", 284)
__NR_mkdirat = Constant("__NR_mkdirat", 285)
__NR_mknodat = Constant("__NR_mknodat", 286)
__NR_fchownat = Constant("__NR_fchownat", 287)
__NR_futimesat = Constant("__NR_futimesat", 288)
__NR_fstatat64 = Constant("__NR_fstatat64", 289)
__NR_unlinkat = Constant("__NR_unlinkat", 290)
__NR_renameat = Constant("__NR_renameat", 291)
__NR_linkat = Constant("__NR_linkat", 292)
__NR_symlinkat = Constant("__NR_symlinkat", 293)
__NR_readlinkat = Constant("__NR_readlinkat", 294)
__NR_fchmodat = Constant("__NR_fchmodat", 295)
__NR_faccessat = Constant("__NR_faccessat", 296)
__NR_pselect6 = Constant("__NR_pselect6", 297)
__NR_ppoll = Constant("__NR_ppoll", 298)
__NR_unshare = Constant("__NR_unshare", 299)
__NR_set_robust_list = Constant("__NR_set_robust_list", 300)
__NR_get_robust_list = Constant("__NR_get_robust_list", 301)
__NR_migrate_pages = Constant("__NR_migrate_pages", 302)
__NR_mbind = Constant("__NR_mbind", 303)
__NR_get_mempolicy = Constant("__NR_get_mempolicy", 304)
__NR_set_mempolicy = Constant("__NR_set_mempolicy", 305)
__NR_kexec_load = Constant("__NR_kexec_load", 306)
__NR_move_pages = Constant("__NR_move_pages", 307)
__NR_getcpu = Constant("__NR_getcpu", 308)
__NR_epoll_pwait = Constant("__NR_epoll_pwait", 309)
__NR_utimensat = Constant("__NR_utimensat", 310)
__NR_signalfd = Constant("__NR_signalfd", 311)
__NR_timerfd = Constant("__NR_timerfd", 312)
__NR_eventfd = Constant("__NR_eventfd", 313)
__NR_fallocate = Constant("__NR_fallocate", 314)
__NR_timerfd_settime = Constant("__NR_timerfd_settime", 315)
__NR_timerfd_gettime = Constant("__NR_timerfd_gettime", 316)
__SYS_NERR = Constant("__SYS_NERR", ((129) + 1))
_SYS_TIME_H = Constant("_SYS_TIME_H", 1)
SYS_accept = Constant("SYS_accept", 99)
SYS_access = Constant("SYS_access", 33)
SYS_acct = Constant("SYS_acct", 51)
SYS_add_key = Constant("SYS_add_key", 281)
SYS_adjtimex = Constant("SYS_adjtimex", 219)
SYS_afs_syscall = Constant("SYS_afs_syscall", 227)
SYS_alarm = Constant("SYS_alarm", 27)
SYS_aplib = Constant("SYS_aplib", 255)
SYS_bdflush = Constant("SYS_bdflush", 225)
SYS_brk = Constant("SYS_brk", 17)
SYS_capget = Constant("SYS_capget", 21)
SYS_capset = Constant("SYS_capset", 22)
SYS_chdir = Constant("SYS_chdir", 12)
SYS_chmod = Constant("SYS_chmod", 15)
SYS_chown = Constant("SYS_chown", 13)
SYS_chroot = Constant("SYS_chroot", 61)
SYS_clock_getres = Constant("SYS_clock_getres", 258)
SYS_clock_gettime = Constant("SYS_clock_gettime", 257)
SYS_clock_nanosleep = Constant("SYS_clock_nanosleep", 259)
SYS_clock_settime = Constant("SYS_clock_settime", 256)
SYS_clone = Constant("SYS_clone", 217)
SYS_close = Constant("SYS_close", 6)
SYS_connect = Constant("SYS_connect", 98)
SYS_creat = Constant("SYS_creat", 8)
SYS_create_module = Constant("SYS_create_module", 221)
SYS_delete_module = Constant("SYS_delete_module", 222)
SYS_dup = Constant("SYS_dup", 41)
SYS_dup2 = Constant("SYS_dup2", 90)
SYS_epoll_create = Constant("SYS_epoll_create", 193)
SYS_epoll_ctl = Constant("SYS_epoll_ctl", 194)
SYS_epoll_pwait = Constant("SYS_epoll_pwait", 309)
SYS_epoll_wait = Constant("SYS_epoll_wait", 195)
SYS_eventfd = Constant("SYS_eventfd", 313)
SYS_execv = Constant("SYS_execv", 11)
SYS_execve = Constant("SYS_execve", 59)
SYS_exit = Constant("SYS_exit", 1)
SYS_exit_group = Constant("SYS_exit_group", 188)
SYS_faccessat = Constant("SYS_faccessat", 296)
SYS_fadvise64 = Constant("SYS_fadvise64", 209)
SYS_fadvise64_64 = Constant("SYS_fadvise64_64", 210)
SYS_fallocate = Constant("SYS_fallocate", 314)
SYS_fchdir = Constant("SYS_fchdir", 176)
SYS_fchmod = Constant("SYS_fchmod", 124)
SYS_fchmodat = Constant("SYS_fchmodat", 295)
SYS_fchown = Constant("SYS_fchown", 123)
SYS_fchownat = Constant("SYS_fchownat", 287)
SYS_fcntl = Constant("SYS_fcntl", 92)
SYS_fdatasync = Constant("SYS_fdatasync", 253)
SYS_fgetxattr = Constant("SYS_fgetxattr", 177)
SYS_flistxattr = Constant("SYS_flistxattr", 180)
SYS_flock = Constant("SYS_flock", 131)
SYS_fork = Constant("SYS_fork", 2)
SYS_fremovexattr = Constant("SYS_fremovexattr", 186)
SYS_fsetxattr = Constant("SYS_fsetxattr", 171)
SYS_fstat = Constant("SYS_fstat", 62)
SYS_fstatat64 = Constant("SYS_fstatat64", 289)
SYS_fstatfs = Constant("SYS_fstatfs", 158)
SYS_fstatfs64 = Constant("SYS_fstatfs64", 235)
SYS_fsync = Constant("SYS_fsync", 95)
SYS_ftruncate = Constant("SYS_ftruncate", 130)
SYS_futex = Constant("SYS_futex", 142)
SYS_futimesat = Constant("SYS_futimesat", 288)
SYS_getcpu = Constant("SYS_getcpu", 308)
SYS_getcwd = Constant("SYS_getcwd", 119)
SYS_getdents = Constant("SYS_getdents", 174)
SYS_getdents64 = Constant("SYS_getdents64", 154)
SYS_getdomainname = Constant("SYS_getdomainname", 162)
SYS_getegid = Constant("SYS_getegid", 50)
SYS_geteuid = Constant("SYS_geteuid", 49)
SYS_getgid = Constant("SYS_getgid", 47)
SYS_getgroups = Constant("SYS_getgroups", 79)
SYS_getitimer = Constant("SYS_getitimer", 86)
SYS_get_kernel_syms = Constant("SYS_get_kernel_syms", 223)
SYS_get_mempolicy = Constant("SYS_get_mempolicy", 304)
SYS_getpagesize = Constant("SYS_getpagesize", 64)
SYS_getpeername = Constant("SYS_getpeername", 141)
SYS_getpgid = Constant("SYS_getpgid", 224)
SYS_getpgrp = Constant("SYS_getpgrp", 81)
SYS_getpid = Constant("SYS_getpid", 20)
SYS_getppid = Constant("SYS_getppid", 197)
SYS_getpriority = Constant("SYS_getpriority", 100)
SYS_getresgid = Constant("SYS_getresgid", 111)
SYS_getresuid = Constant("SYS_getresuid", 109)
SYS_getrlimit = Constant("SYS_getrlimit", 144)
SYS_get_robust_list = Constant("SYS_get_robust_list", 301)
SYS_getrusage = Constant("SYS_getrusage", 117)
SYS_getsid = Constant("SYS_getsid", 252)
SYS_getsockname = Constant("SYS_getsockname", 150)
SYS_getsockopt = Constant("SYS_getsockopt", 118)
SYS_gettid = Constant("SYS_gettid", 143)
SYS_gettimeofday = Constant("SYS_gettimeofday", 116)
SYS_getuid = Constant("SYS_getuid", 24)
SYS_getxattr = Constant("SYS_getxattr", 172)
SYS_init_module = Constant("SYS_init_module", 190)
SYS_io_cancel = Constant("SYS_io_cancel", 271)
SYS_ioctl = Constant("SYS_ioctl", 54)
SYS_io_destroy = Constant("SYS_io_destroy", 269)
SYS_io_getevents = Constant("SYS_io_getevents", 272)
SYS_io_setup = Constant("SYS_io_setup", 268)
SYS_io_submit = Constant("SYS_io_submit", 270)
SYS_ipc = Constant("SYS_ipc", 215)
SYS_kexec_load = Constant("SYS_kexec_load", 306)
SYS_keyctl = Constant("SYS_keyctl", 283)
SYS_kill = Constant("SYS_kill", 37)
SYS_lchown = Constant("SYS_lchown", 16)
SYS_lgetxattr = Constant("SYS_lgetxattr", 173)
SYS_link = Constant("SYS_link", 9)
SYS_linkat = Constant("SYS_linkat", 292)
SYS_listxattr = Constant("SYS_listxattr", 178)
SYS_llistxattr = Constant("SYS_llistxattr", 179)
SYS__llseek = Constant("SYS__llseek", 236)
SYS_lookup_dcookie = Constant("SYS_lookup_dcookie", 208)
SYS_lremovexattr = Constant("SYS_lremovexattr", 182)
SYS_lseek = Constant("SYS_lseek", 19)
SYS_lsetxattr = Constant("SYS_lsetxattr", 170)
SYS_lstat = Constant("SYS_lstat", 40)
SYS_madvise = Constant("SYS_madvise", 75)
SYS_mbind = Constant("SYS_mbind", 303)
SYS_memory_ordering = Constant("SYS_memory_ordering", 52)
SYS_migrate_pages = Constant("SYS_migrate_pages", 302)
SYS_mincore = Constant("SYS_mincore", 78)
SYS_mkdir = Constant("SYS_mkdir", 136)
SYS_mkdirat = Constant("SYS_mkdirat", 285)
SYS_mknod = Constant("SYS_mknod", 14)
SYS_mknodat = Constant("SYS_mknodat", 286)
SYS_mlock = Constant("SYS_mlock", 237)
SYS_mlockall = Constant("SYS_mlockall", 239)
SYS_mmap = Constant("SYS_mmap", 71)
SYS_mount = Constant("SYS_mount", 167)
SYS_move_pages = Constant("SYS_move_pages", 307)
SYS_mprotect = Constant("SYS_mprotect", 74)
SYS_mq_getsetattr = Constant("SYS_mq_getsetattr", 278)
SYS_mq_notify = Constant("SYS_mq_notify", 277)
SYS_mq_open = Constant("SYS_mq_open", 273)
SYS_mq_timedreceive = Constant("SYS_mq_timedreceive", 276)
SYS_mq_timedsend = Constant("SYS_mq_timedsend", 275)
SYS_mq_unlink = Constant("SYS_mq_unlink", 274)
SYS_mremap = Constant("SYS_mremap", 250)
SYS_msync = Constant("SYS_msync", 65)
SYS_munlock = Constant("SYS_munlock", 238)
SYS_munlockall = Constant("SYS_munlockall", 240)
SYS_munmap = Constant("SYS_munmap", 73)
SYS_nanosleep = Constant("SYS_nanosleep", 249)
SYS__newselect = Constant("SYS__newselect", 230)
SYS_nfsservctl = Constant("SYS_nfsservctl", 254)
SYS_nice = Constant("SYS_nice", 34)
SYS_oldlstat = Constant("SYS_oldlstat", 202)
SYS_open = Constant("SYS_open", 5)
SYS_openat = Constant("SYS_openat", 284)
SYS_pause = Constant("SYS_pause", 29)
SYS_pciconfig_read = Constant("SYS_pciconfig_read", 148)
SYS_pciconfig_write = Constant("SYS_pciconfig_write", 149)
SYS_perfctr = Constant("SYS_perfctr", 18)
SYS_personality = Constant("SYS_personality", 191)
SYS_pipe = Constant("SYS_pipe", 42)
SYS_pivot_root = Constant("SYS_pivot_root", 146)
SYS_poll = Constant("SYS_poll", 153)
SYS_ppoll = Constant("SYS_ppoll", 298)
SYS_prctl = Constant("SYS_prctl", 147)
SYS_pread = Constant("SYS_pread", 67)
SYS_pselect6 = Constant("SYS_pselect6", 297)
SYS_ptrace = Constant("SYS_ptrace", 26)
SYS_pwrite = Constant("SYS_pwrite", 68)
SYS_query_module = Constant("SYS_query_module", 184)
SYS_quotactl = Constant("SYS_quotactl", 165)
SYS_read = Constant("SYS_read", 3)
SYS_readahead = Constant("SYS_readahead", 205)
SYS_readdir = Constant("SYS_readdir", 204)
SYS_readlink = Constant("SYS_readlink", 58)
SYS_readlinkat = Constant("SYS_readlinkat", 294)
SYS_readv = Constant("SYS_readv", 120)
SYS_reboot = Constant("SYS_reboot", 55)
SYS_recvfrom = Constant("SYS_recvfrom", 125)
SYS_recvmsg = Constant("SYS_recvmsg", 113)
SYS_remap_file_pages = Constant("SYS_remap_file_pages", 192)
SYS_removexattr = Constant("SYS_removexattr", 181)
SYS_rename = Constant("SYS_rename", 128)
SYS_renameat = Constant("SYS_renameat", 291)
SYS_request_key = Constant("SYS_request_key", 282)
SYS_rmdir = Constant("SYS_rmdir", 137)
SYS_rt_sigaction = Constant("SYS_rt_sigaction", 102)
SYS_rt_sigpending = Constant("SYS_rt_sigpending", 104)
SYS_rt_sigprocmask = Constant("SYS_rt_sigprocmask", 103)
SYS_rt_sigqueueinfo = Constant("SYS_rt_sigqueueinfo", 106)
SYS_rt_sigreturn = Constant("SYS_rt_sigreturn", 101)
SYS_rt_sigsuspend = Constant("SYS_rt_sigsuspend", 107)
SYS_rt_sigtimedwait = Constant("SYS_rt_sigtimedwait", 105)
SYS_sched_getaffinity = Constant("SYS_sched_getaffinity", 260)
SYS_sched_get_affinity = Constant("SYS_sched_get_affinity", 161)
SYS_sched_getparam = Constant("SYS_sched_getparam", 242)
SYS_sched_get_priority_max = Constant("SYS_sched_get_priority_max", 246)
SYS_sched_get_priority_min = Constant("SYS_sched_get_priority_min", 247)
SYS_sched_getscheduler = Constant("SYS_sched_getscheduler", 244)
SYS_sched_rr_get_interval = Constant("SYS_sched_rr_get_interval", 248)
SYS_sched_setaffinity = Constant("SYS_sched_setaffinity", 261)
SYS_sched_set_affinity = Constant("SYS_sched_set_affinity", 160)
SYS_sched_setparam = Constant("SYS_sched_setparam", 241)
SYS_sched_setscheduler = Constant("SYS_sched_setscheduler", 243)
SYS_sched_yield = Constant("SYS_sched_yield", 245)
SYS_select = Constant("SYS_select", 93)
SYS_sendfile = Constant("SYS_sendfile", 39)
SYS_sendfile64 = Constant("SYS_sendfile64", 140)
SYS_sendmsg = Constant("SYS_sendmsg", 114)
SYS_sendto = Constant("SYS_sendto", 133)
SYS_setdomainname = Constant("SYS_setdomainname", 163)
SYS_setfsgid = Constant("SYS_setfsgid", 229)
SYS_setfsuid = Constant("SYS_setfsuid", 228)
SYS_setgid = Constant("SYS_setgid", 46)
SYS_setgroups = Constant("SYS_setgroups", 80)
SYS_sethostname = Constant("SYS_sethostname", 88)
SYS_setitimer = Constant("SYS_setitimer", 83)
SYS_set_mempolicy = Constant("SYS_set_mempolicy", 305)
SYS_setpgid = Constant("SYS_setpgid", 185)
SYS_setpriority = Constant("SYS_setpriority", 96)
SYS_setregid = Constant("SYS_setregid", 127)
SYS_setresgid = Constant("SYS_setresgid", 110)
SYS_setresuid = Constant("SYS_setresuid", 108)
SYS_setreuid = Constant("SYS_setreuid", 126)
SYS_setrlimit = Constant("SYS_setrlimit", 145)
SYS_set_robust_list = Constant("SYS_set_robust_list", 300)
SYS_setsid = Constant("SYS_setsid", 175)
SYS_set_tid_address = Constant("SYS_set_tid_address", 166)
SYS_settimeofday = Constant("SYS_settimeofday", 122)
SYS_setuid = Constant("SYS_setuid", 23)
SYS_setxattr = Constant("SYS_setxattr", 169)
SYS_sgetmask = Constant("SYS_sgetmask", 199)
SYS_shutdown = Constant("SYS_shutdown", 134)
SYS_sigaction = Constant("SYS_sigaction", 198)
SYS_sigaltstack = Constant("SYS_sigaltstack", 28)
SYS_signal = Constant("SYS_signal", 48)
SYS_signalfd = Constant("SYS_signalfd", 311)
SYS_sigpending = Constant("SYS_sigpending", 183)
SYS_sigprocmask = Constant("SYS_sigprocmask", 220)
SYS_sigreturn = Constant("SYS_sigreturn", 216)
SYS_sigsuspend = Constant("SYS_sigsuspend", 201)
SYS_socket = Constant("SYS_socket", 97)
SYS_socketcall = Constant("SYS_socketcall", 206)
SYS_socketpair = Constant("SYS_socketpair", 135)
SYS_ssetmask = Constant("SYS_ssetmask", 200)
SYS_stat = Constant("SYS_stat", 38)
SYS_statfs = Constant("SYS_statfs", 157)
SYS_statfs64 = Constant("SYS_statfs64", 234)
SYS_stime = Constant("SYS_stime", 233)
SYS_swapoff = Constant("SYS_swapoff", 213)
SYS_swapon = Constant("SYS_swapon", 85)
SYS_symlink = Constant("SYS_symlink", 57)
SYS_symlinkat = Constant("SYS_symlinkat", 293)
SYS_sync = Constant("SYS_sync", 36)
SYS__sysctl = Constant("SYS__sysctl", 251)
SYS_sysfs = Constant("SYS_sysfs", 226)
SYS_sysinfo = Constant("SYS_sysinfo", 214)
SYS_syslog = Constant("SYS_syslog", 207)
SYS_tgkill = Constant("SYS_tgkill", 211)
SYS_timer_create = Constant("SYS_timer_create", 266)
SYS_timer_delete = Constant("SYS_timer_delete", 265)
SYS_timerfd = Constant("SYS_timerfd", 312)
SYS_timerfd_gettime = Constant("SYS_timerfd_gettime", 316)
SYS_timerfd_settime = Constant("SYS_timerfd_settime", 315)
SYS_timer_getoverrun = Constant("SYS_timer_getoverrun", 264)
SYS_timer_gettime = Constant("SYS_timer_gettime", 263)
SYS_timer_settime = Constant("SYS_timer_settime", 262)
SYS_times = Constant("SYS_times", 43)
SYS_tkill = Constant("SYS_tkill", 187)
SYS_truncate = Constant("SYS_truncate", 129)
SYS_umask = Constant("SYS_umask", 60)
SYS_umount = Constant("SYS_umount", 159)
SYS_umount2 = Constant("SYS_umount2", 45)
SYS_uname = Constant("SYS_uname", 189)
SYS_unlink = Constant("SYS_unlink", 10)
SYS_unlinkat = Constant("SYS_unlinkat", 290)
SYS_unshare = Constant("SYS_unshare", 299)
SYS_uselib = Constant("SYS_uselib", 203)
SYS_ustat = Constant("SYS_ustat", 168)
SYS_utime = Constant("SYS_utime", 30)
SYS_utimensat = Constant("SYS_utimensat", 310)
SYS_utimes = Constant("SYS_utimes", 138)
SYS_utrap_install = Constant("SYS_utrap_install", 164)
SYS_vfork = Constant("SYS_vfork", 66)
SYS_vhangup = Constant("SYS_vhangup", 76)
SYS_wait4 = Constant("SYS_wait4", 7)
SYS_waitid = Constant("SYS_waitid", 279)
SYS_waitpid = Constant("SYS_waitpid", 212)
SYS_write = Constant("SYS_write", 4)
SYS_writev = Constant("SYS_writev", 121)
