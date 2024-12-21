"""
Routines to enumerate mapped memory, and attempt to associate
address ranges with various ELF files and permissions.

The reason that we need robustness is that not every operating
system has /proc/$$/maps, which backs 'info proc mapping'.
"""

from __future__ import annotations

import bisect
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import gdb

import pwndbg
import pwndbg.aglib.elf
import pwndbg.aglib.file
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.regs
import pwndbg.aglib.stack
import pwndbg.auxv
import pwndbg.color.message as M
import pwndbg.gdblib.abi
import pwndbg.gdblib.info
import pwndbg.lib.cache
import pwndbg.lib.config
import pwndbg.lib.memory
from pwndbg.aglib.kernel.vmmap import kernel_vmmap_via_monitor_info_mem
from pwndbg.aglib.kernel.vmmap import kernel_vmmap_via_page_tables

# List of manually-explored pages which were discovered
# by analyzing the stack or register context.
explored_pages: List[pwndbg.lib.memory.Page] = []

# List of custom pages that can be managed manually by vmmap_* commands family
custom_pages: List[pwndbg.lib.memory.Page] = []


kernel_vmmap_via_pt = pwndbg.config.add_param(
    "kernel-vmmap-via-page-tables",
    "deprecated",
    "the deprecated config of the method get kernel vmmap",
    help_docstring="Deprecated in favor of `kernel-vmmap`",
)

kernel_vmmap = pwndbg.config.add_param(
    "kernel-vmmap",
    "page-tables",
    "the method to get vmmap information when debugging via QEMU kernel",
    help_docstring="""\
kernel-vmmap can be:
page-tables    - read /proc/$qemu-pid/mem to parse kernel page tables to render vmmap
monitor        - use QEMU's `monitor info mem` to render vmmap
none           - disable vmmap rendering; useful if rendering is particularly slow

Note that the page-tables method will require the QEMU kernel process to be on the same machine and within the same PID namespace. Running QEMU kernel and GDB in different Docker containers will not work. Consider running both containers with --pid=host (meaning they will see and so be able to interact with all processes on the machine).
""",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["page-tables", "monitor", "none"],
)

auto_explore = pwndbg.config.add_param(
    "auto-explore-pages",
    "yes",
    "whether to try to infer page permissions when memory maps missing (can cause errors)",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["yes", "warn", "no"],
)


@pwndbg.lib.cache.cache_until("objfile", "start")
def is_corefile() -> bool:
    """
    For example output use:
        gdb ./tests/binaries/crash_simple.out -ex run -ex 'generate-core-file ./core' -ex 'quit'

    And then use:
        gdb ./tests/binaries/crash_simple.out -core ./core -ex 'info target'
    And:
        gdb -core ./core

    As the two differ in output slighty.
    """
    return "Local core dump file:\n" in pwndbg.gdblib.info.target()


inside_no_proc_maps_search = False


@pwndbg.lib.cache.cache_until("start", "stop")
def get_known_maps() -> Tuple[pwndbg.lib.memory.Page, ...] | None:
    """
    Similar to `vmmap.get()`, except only returns maps in cases where
    the mappings are known, like if it's a coredump, or if process
    mappings are available.
    """
    # Note: debugging a coredump does still show proc.alive == True
    if not pwndbg.aglib.proc.alive:
        return ()

    if is_corefile():
        return tuple(coredump_maps())

    proc_maps = None
    if pwndbg.aglib.qemu.is_qemu_usermode():
        # On Qemu < 8.1 info proc maps are not supported. In that case we callback on proc_tid_maps
        proc_maps = info_proc_maps()

    if not proc_maps:
        proc_maps = proc_tid_maps()

    return proc_maps


@pwndbg.lib.cache.cache_until("start", "stop")
def get() -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Returns a tuple of `Page` objects representing the memory mappings of the
    target, sorted by virtual address ascending.
    """
    proc_maps = get_known_maps()
    if proc_maps is not None:
        return proc_maps

    # The `proc_maps` is usually a tuple of Page objects but it can also be:
    #   None    - when /proc/$tid/maps does not exist/is not available
    #   tuple() - when the process has no maps yet which happens only during its very early init
    #             (usually when we attach to a process)
    if proc_maps is not None:
        return proc_maps

    pages: List[pwndbg.lib.memory.Page] = []
    if pwndbg.aglib.qemu.is_qemu_kernel() and pwndbg.aglib.arch.current in (
        "i386",
        "x86-64",
        "aarch64",
        "rv32",
        "rv64",
    ):
        # If kernel_vmmap_via_pt is not set to the default value of "deprecated",
        # That means the user was explicitly setting it themselves and need to
        # be warned that the option is deprecated
        if kernel_vmmap_via_pt != "deprecated":
            print(
                M.warn(
                    "`kernel-vmmap-via-page-tables` is deprecated, please use `kernel-vmmap` instead."
                )
            )

        if kernel_vmmap == "page-tables":
            pages.extend(kernel_vmmap_via_page_tables())
        elif kernel_vmmap == "monitor":
            pages.extend(kernel_vmmap_via_monitor_info_mem())

    # TODO/FIXME: Add tests for  QEMU-user targets when this is needed
    global inside_no_proc_maps_search
    if not pages and not inside_no_proc_maps_search:
        inside_no_proc_maps_search = True
        # If debuggee is launched from a symlink the debuggee memory maps will be
        # labeled with symlink path while in normal scenario the /proc/pid/maps
        # labels debuggee memory maps with real path (after symlinks).
        # This is because the exe path in AUXV (and so `info auxv`) is before
        # following links.
        pages.extend(info_auxv())

        if pages:
            pages.extend(info_sharedlibrary())
        else:
            if pwndbg.aglib.qemu.is_qemu():
                return (pwndbg.lib.memory.Page(0, pwndbg.aglib.arch.ptrmask, 7, 0, "[qemu]"),)
            pages.extend(info_files())

        pages.extend(pwndbg.aglib.stack.get().values())
        inside_no_proc_maps_search = False

    pages.extend(explored_pages)
    pages.extend(custom_pages)
    pages.sort()
    return tuple(pages)


_warn_cache: Set[int] = set()


@pwndbg.gdblib.events.new_objfile
def clear_warn_cache():
    _warn_cache.clear()


@pwndbg.lib.cache.cache_until("stop")
def find(
    address: int | gdb.Value | None, *, should_explore: bool | None = None
) -> pwndbg.lib.memory.Page | None:
    if address is None:
        return None

    address = int(address)

    for page in get():
        if address in page:
            return page

    if should_explore is None:
        if auto_explore.value == "warn":
            page_start = pwndbg.lib.memory.page_align(address)
            if page_start not in _warn_cache:
                _warn_cache.add(page_start)
                print(
                    M.warn(
                        f"Warning: Avoided exploring possible address {address:#x}. You can explicitly explore it with `vmmap_explore {page_start:#x}`"
                    )
                )
        elif auto_explore.value == "yes":
            return explore(address)
    elif should_explore and not proc_tid_maps():
        return explore(address)

    return None


@pwndbg.gdblib.abi.LinuxOnly()
def explore(address_maybe: int) -> pwndbg.lib.memory.Page | None:
    """
    Given a potential address, check to see what permissions it has.

    Returns:
        Page object

    Note:
        Adds the Page object to a persistent list of pages which are
        only reset when the process dies.  This means pages which are
        added this way will not be removed when unmapped.

        Also assumes the entire contiguous section has the same permission.
    """

    address_maybe = pwndbg.lib.memory.page_align(address_maybe)

    flags = 4 if pwndbg.aglib.memory.peek(address_maybe) else 0

    if not flags:
        return None

    if pwndbg.aglib.memory.poke(address_maybe):
        flags |= 2
    # It's really hard to check for executability, so we just make some guesses:
    # If it's in the same page as the stack pointer, try to check the NX bit
    # If it's in the same page as the instruction pointer, assume it's executable
    # Otherwise, just say it's not executable
    if address_maybe == pwndbg.lib.memory.page_align(pwndbg.aglib.regs.pc):
        flags |= 1
    # TODO: could maybe make this check look at the stacks in pwndbg.aglib.stack.get() but that might have issues
    elif (
        address_maybe == pwndbg.lib.memory.page_align(pwndbg.aglib.regs.sp)
        and pwndbg.aglib.stack.is_executable()
    ):
        flags |= 1

    page = find_boundaries(address_maybe)
    page.objfile = "<explored>"
    page.flags = flags

    explored_pages.append(page)

    # Clear the "get" cache so pages that are explored in the current step are included
    get.cache.clear()  # type: ignore[attr-defined]

    return page


# Automatically ensure that all registers are explored on each stop
# @pwndbg.dbg.event_handler(EventType.STOP)
def explore_registers() -> None:
    for regname in pwndbg.aglib.regs.common:
        find(pwndbg.aglib.regs[regname])


# @pwndbg.dbg.event_handler(EventType.EXIT)
def clear_explored_pages() -> None:
    while explored_pages:
        explored_pages.pop()


def add_custom_page(page: pwndbg.lib.memory.Page) -> None:
    bisect.insort(custom_pages, page)

    # Reset all the cache
    # We can not reset get() only, since the result may be used by others.
    # TODO: avoid flush all caches
    pwndbg.lib.cache.clear_caches()


def clear_custom_page() -> None:
    while custom_pages:
        custom_pages.pop()

    # Reset all the cache
    # We can not reset get() only, since the result may be used by others.
    # TODO: avoid flush all caches
    pwndbg.lib.cache.clear_caches()


@pwndbg.lib.cache.cache_until("objfile", "start")
def coredump_maps() -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Parses `info proc mappings` and `maintenance info sections`
    and tries to make sense out of the result :)
    """
    pages = list(info_proc_maps(parse_flags=False))

    started_sections = False
    for line in gdb.execute("maintenance info sections", to_string=True).splitlines():
        if not started_sections:
            if "Core file:" in line:
                started_sections = True
            continue

        # We look for lines like:
        # ['[9]', '0x00000000->0x00000150', 'at', '0x00098c40:', '.auxv', 'HAS_CONTENTS']
        # ['[15]', '0x555555555000->0x555555556000', 'at', '0x00001430:', 'load2', 'ALLOC', 'LOAD', 'READONLY', 'CODE', 'HAS_CONTENTS']
        try:
            _idx, start_end, _at_str, _at, name, *flags_list = line.split()
            start, end = (int(v, 16) for v in start_end.split("->"))

            # Skip pages with start=0x0, this is unlikely this is valid vmmap
            if start == 0:
                continue

            # Tried taking this from the 'at 0x...' value
            # but it turns out to be invalid, so keep it 0 until we find better way
            offset = 0
        except (IndexError, ValueError):
            continue

        # Note: can we deduce anything from 'ALLOC', 'HAS_CONTENTS' or 'LOAD' flags?
        flags = 0
        if "READONLY" in flags_list:
            flags |= 4
        if "DATA" in flags_list:
            flags |= 2
        if "CODE" in flags_list:
            flags |= 1

        # Now, if the section is already in pages, just add its perms
        known_page = False

        for page in pages:
            if start in page:
                page.flags |= flags
                known_page = True
                break

        if known_page:
            continue

        pages.append(pwndbg.lib.memory.Page(start, end - start, flags, offset, name))

    if not pages:
        return ()

    # If the last page starts on e.g. 0xffffffffff600000 it must be vsyscall
    vsyscall_page = pages[-1]
    if vsyscall_page.start > 0xFFFFFFFFFF000000 and vsyscall_page.flags & 1:
        vsyscall_page.objfile = "[vsyscall]"
        vsyscall_page.offset = 0

    # Detect stack based on addresses in AUXV from stack memory
    stack_addr = None

    # TODO/FIXME: Can we uxe `pwndbg.auxv.get()` for this somehow?
    auxv = pwndbg.gdblib.info.auxv().splitlines()
    for line in auxv:
        if "AT_EXECFN" in line:
            try:
                stack_addr = int(line.split()[-2], 16)
            except Exception:
                pass
            break

    if stack_addr is not None:
        for page in pages:
            if stack_addr in page:
                page.objfile = "[stack]"
                page.flags |= 6
                page.offset = 0
                break

    pages.sort(key=lambda page: page.start)
    return tuple(pages)


def parse_info_proc_mappings_line(
    line: str, perms_available: bool, parse_flags: bool
) -> Optional[pwndbg.lib.memory.Page]:
    """
    Parse a line from `info proc mappings` and return a pwndbg.lib.memory.Page
    object if the line is valid.

    Example lines:
        0x4c3000           0x4c5000     0x2000    0xc2000  rw-p   /root/hello_world/main
        0x4c5000           0x4cb000     0x6000        0x0  rw-p

    The objfile column might be empty, and the permissions column is only present in GDB versions >= 12.1
    https://github.com/bminor/binutils-gdb/commit/29ef4c0699e1b46d41ade00ae07a54f979ea21cc

    Args:
        line: A line from `info proc mappings`.

    Returns:
        A pwndbg.lib.memory.Page object or None.
    """
    try:
        # Example line with all fields present: ['0x555555555000', '0x555555556000', '0x1000', '0x1000', 'rw-p', '/home/user/a.out']
        split_line = line.split()

        start_str = split_line[0]
        _end = split_line[1]
        size_str = split_line[2]
        offset_str = split_line[3]

        if perms_available:
            perm = split_line[4]
            # The objfile column may be empty.
            objfile = split_line[5] if len(split_line) > 5 else ""
        else:
            perm = "rwxp"
            objfile = split_line[4] if len(split_line) > 4 else ""

        start, size, offset = int(start_str, 16), int(size_str, 16), int(offset_str, 16)
    except (IndexError, ValueError):
        return None

    flags = 0
    if parse_flags:
        if "r" in perm:
            flags |= 4
        if "w" in perm:
            flags |= 2
        if "x" in perm:
            flags |= 1

    return pwndbg.lib.memory.Page(start, size, flags, offset, objfile)


@pwndbg.lib.cache.cache_until("start", "stop")
def info_proc_maps(parse_flags=True) -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Parse the result of info proc mappings.

    Example output:

            Start Addr           End Addr       Size     Offset  Perms  objfile
              0x400000           0x401000     0x1000        0x0  r--p   /root/hello_world/main
              0x401000           0x497000    0x96000     0x1000  r-xp   /root/hello_world/main
              0x497000           0x4be000    0x27000    0x97000  r--p   /root/hello_world/main
              0x4be000           0x4c3000     0x5000    0xbd000  r--p   /root/hello_world/main
              0x4c3000           0x4c5000     0x2000    0xc2000  rw-p   /root/hello_world/main
              0x4c5000           0x4cb000     0x6000        0x0  rw-p
              0x4cb000           0x4ed000    0x22000        0x0  rw-p   [heap]
        0x7ffff7ff9000     0x7ffff7ffd000     0x4000        0x0  r--p   [vvar]
        0x7ffff7ffd000     0x7ffff7fff000     0x2000        0x0  r-xp   [vdso]
        0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]
    0xffffffffff600000 0xffffffffff601000     0x1000        0x0  --xp   [vsyscall]

    Note: this may return no pages due to a bug/behavior of GDB.
    See https://sourceware.org/bugzilla/show_bug.cgi?id=31207
    for more information.

    Returns:
        A tuple of pwndbg.lib.memory.Page objects or an empty tuple if
        info proc mapping is not supported on the target.
    """

    try:
        info_proc_mappings = pwndbg.gdblib.info.proc_mappings().splitlines()
    except gdb.error:
        # On qemu user emulation, we may get: gdb.error: Not supported on this target.
        info_proc_mappings = []

    # See if "Perms" is in the header line
    perms_available = len(info_proc_mappings) >= 4 and "Perms" in info_proc_mappings[3]

    pages: List[pwndbg.lib.memory.Page] = []
    for line in info_proc_mappings:
        page = parse_info_proc_mappings_line(line, perms_available, parse_flags)
        if page is not None:
            pages.append(page)

    return tuple(pages)


@pwndbg.lib.cache.cache_until("start", "stop")
def proc_tid_maps() -> Tuple[pwndbg.lib.memory.Page, ...] | None:
    """
    Parse the contents of /proc/$TID/maps on the server.
    (TID == Thread Identifier. We do not use PID since it may not be correct)

    Returns:
        A tuple of pwndbg.lib.memory.Page objects or None if
        /proc/$tid/maps doesn't exist or when we debug a qemu-user target
    """

    # If we debug remotely a qemu-user or qemu-system target,
    # there is no point of hitting things further
    if pwndbg.aglib.qemu.is_qemu():
        return None

    # Example /proc/$tid/maps
    # 7f95266fa000-7f95268b5000 r-xp 00000000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f95268b5000-7f9526ab5000 ---p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f9526ab5000-7f9526ab9000 r--p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f9526ab9000-7f9526abb000 rw-p 001bf000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f9526abb000-7f9526ac0000 rw-p 00000000 00:00 0
    # 7f9526ac0000-7f9526ae3000 r-xp 00000000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    # 7f9526cbe000-7f9526cc1000 rw-p 00000000 00:00 0
    # 7f9526ce0000-7f9526ce2000 rw-p 00000000 00:00 0
    # 7f9526ce2000-7f9526ce3000 r--p 00022000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    # 7f9526ce3000-7f9526ce4000 rw-p 00023000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    # 7f9526ce4000-7f9526ce5000 rw-p 00000000 00:00 0
    # 7f9526ce5000-7f9526d01000 r-xp 00000000 08:01 786466                     /bin/dash
    # 7f9526f00000-7f9526f02000 r--p 0001b000 08:01 786466                     /bin/dash
    # 7f9526f02000-7f9526f03000 rw-p 0001d000 08:01 786466                     /bin/dash
    # 7f9526f03000-7f9526f05000 rw-p 00000000 00:00 0
    # 7f95279fe000-7f9527a1f000 rw-p 00000000 00:00 0                          [heap]
    # 7fff3c177000-7fff3c199000 rw-p 00000000 00:00 0                          [stack]
    # 7fff3c1e8000-7fff3c1ea000 r-xp 00000000 00:00 0                          [vdso]
    # ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

    tid = pwndbg.aglib.proc.tid
    locations = [
        f"/proc/{tid}/maps",
        f"/proc/{tid}/map",
        f"/usr/compat/linux/proc/{tid}/maps",
    ]

    for location in locations:
        try:
            data = pwndbg.aglib.file.get(location).decode()
            break
        except (OSError, gdb.error):
            continue
    else:
        return None

    # Process hasn't been fully created yet; it is in Z (zombie) state
    if data == "":
        return ()

    pages: List[pwndbg.lib.memory.Page] = []
    for line in data.splitlines():
        maps, perm, offset, dev, inode_objfile = line.split(maxsplit=4)

        start, stop = maps.split("-")

        try:
            inode, objfile = inode_objfile.split(maxsplit=1)
        except Exception:
            # Name unnamed anonymous pages so they can be used e.g. with search commands
            objfile = "[anon_" + start[:-3] + "]"

        start = int(start, 16)
        stop = int(stop, 16)
        offset = int(offset, 16)
        size = stop - start

        flags = 0
        if "r" in perm:
            flags |= 4
        if "w" in perm:
            flags |= 2
        if "x" in perm:
            flags |= 1

        page = pwndbg.lib.memory.Page(start, size, flags, offset, objfile)
        pages.append(page)

    return tuple(pages)


@pwndbg.lib.cache.cache_until("stop")
def info_sharedlibrary() -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Parses the output of `info sharedlibrary`.

    Specifically, all we really want is any valid pointer into each library,
    and the path to the library on disk.

    With this information, we can use the ELF parser to get all of the
    page permissions for every mapped page in the ELF.

    Returns:
        A list of pwndbg.lib.memory.Page objects.
    """

    # Example of `info sharedlibrary` on FreeBSD
    # From        To          Syms Read   Shared Object Library
    # 0x280fbea0  0x2810e570  Yes (*)     /libexec/ld-elf.so.1
    # 0x281260a0  0x281495c0  Yes (*)     /lib/libncurses.so.8
    # 0x28158390  0x2815dcf0  Yes (*)     /usr/local/lib/libintl.so.9
    # 0x28188b00  0x2828e060  Yes (*)     /lib/libc.so.7
    # (*): Shared library is missing debugging information.

    # Example of `info sharedlibrary` on Linux
    # From                To                  Syms Read   Shared Object Library
    # 0x00007ffff7ddaae0  0x00007ffff7df54e0  Yes         /lib64/ld-linux-x86-64.so.2
    # 0x00007ffff7bbd3d0  0x00007ffff7bc9028  Yes (*)     /lib/x86_64-linux-gnu/libtinfo.so.5
    # 0x00007ffff79aded0  0x00007ffff79ae9ce  Yes         /lib/x86_64-linux-gnu/libdl.so.2
    # 0x00007ffff76064a0  0x00007ffff774c113  Yes         /lib/x86_64-linux-gnu/libc.so.6
    # (*): Shared library is missing debugging information.

    pages: List[pwndbg.lib.memory.Page] = []

    for line in pwndbg.gdblib.info.sharedlibrary().splitlines():
        if not line.startswith("0x"):
            continue

        tokens = line.split()
        text = int(tokens[0], 16)
        obj = tokens[-1]

        pages.extend(pwndbg.aglib.elf.map(text, obj))

    return tuple(sorted(pages))


@pwndbg.lib.cache.cache_until("stop")
def info_files() -> Tuple[pwndbg.lib.memory.Page, ...]:
    # Example of `info files` output:
    # Symbols from "/bin/bash".
    # Unix child process:
    # Using the running image of child process 5903.
    # While running this, GDB does not access memory from...
    # Local exec file:
    # `/bin/bash', file type elf64-x86-64.
    # Entry point: 0x42020b
    # 0x0000000000400238 - 0x0000000000400254 is .interp
    # 0x0000000000400254 - 0x0000000000400274 is .note.ABI-tag
    # ...
    # 0x00000000006f06c0 - 0x00000000006f8ca8 is .data
    # 0x00000000006f8cc0 - 0x00000000006fe898 is .bss
    # 0x00007ffff7dda1c8 - 0x00007ffff7dda1ec is .note.gnu.build-id in /lib64/ld-linux-x86-64.so.2
    # 0x00007ffff7dda1f0 - 0x00007ffff7dda2ac is .hash in /lib64/ld-linux-x86-64.so.2
    # 0x00007ffff7dda2b0 - 0x00007ffff7dda38c is .gnu.hash in /lib64/ld-linux-x86-64.so.2

    seen_files: Set[str] = set()
    pages: List[pwndbg.lib.memory.Page] = []
    main_exe = ""

    for line in pwndbg.gdblib.info.files().splitlines():
        line = line.strip()

        # The name of the main executable
        if line.startswith("`"):
            exename, filetype = line.split(maxsplit=1)
            main_exe = exename.strip("`,'")
            continue

        # Everything else should be addresses
        if not line.startswith("0x"):
            continue

        # start, stop, _, segment, _, filename = line.split(maxsplit=6)
        fields = line.split(maxsplit=6)
        vaddr = int(fields[0], 16)

        if len(fields) == 5:
            objfile = main_exe
        elif len(fields) == 7:
            objfile = fields[6]
        else:
            print("Bad data: %r" % line)
            continue

        if objfile not in seen_files:
            seen_files.add(objfile)

        pages.extend(pwndbg.aglib.elf.map(vaddr, objfile))

    return tuple(pages)


@pwndbg.lib.cache.cache_until("exit")
def info_auxv(skip_exe: bool = False) -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Extracts the name of the executable from the output of the command
    "info auxv". Note that if the executable path is a symlink,
    it is not dereferenced by `info auxv` and we also don't dereference it.

    Arguments:
        skip_exe(bool): Do not return any mappings that belong to the exe.

    Returns:
        A list of pwndbg.lib.memory.Page objects.
    """
    auxv = pwndbg.auxv.get()

    if not auxv:
        return ()

    pages: List[pwndbg.lib.memory.Page] = []
    exe_name = auxv.AT_EXECFN or "main.exe"
    entry = auxv.AT_ENTRY
    base = auxv.AT_BASE
    vdso = auxv.AT_SYSINFO_EHDR or auxv.AT_SYSINFO
    phdr = auxv.AT_PHDR

    if not skip_exe and (entry or phdr):
        for addr in [entry, phdr]:
            if not addr:
                continue
            new_pages = pwndbg.aglib.elf.map(addr, exe_name)
            if new_pages:
                pages.extend(new_pages)
                break

    if base:
        pages.extend(pwndbg.aglib.elf.map(base, "[linker]"))

    if vdso:
        pages.extend(pwndbg.aglib.elf.map(vdso, "[vdso]"))

    return tuple(sorted(pages))


def find_boundaries(addr: int, name: str = "", min: int = 0) -> pwndbg.lib.memory.Page:
    """
    Given a single address, find all contiguous pages
    which are mapped.
    """
    start = pwndbg.aglib.memory.find_lower_boundary(addr)
    end = pwndbg.aglib.memory.find_upper_boundary(addr)

    start = max(start, min)

    return pwndbg.lib.memory.Page(start, end - start, 4, 0, name)
