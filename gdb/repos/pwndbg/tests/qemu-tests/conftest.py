"""
This file should consist of global test fixtures.
"""

from __future__ import annotations

import os
import subprocess
import sys

import gdb
import pytest
from pwn import context
from pwn import make_elf_from_assembly
from pwn import pwnlib

_start_binary_called = False

QEMU_PORT = os.environ.get("QEMU_PORT")


@pytest.fixture
def qemu_assembly_run():
    """
    Returns function that launches given binary with 'starti' command

    The `path` is returned from `make_elf_from_assembly` (provided by pwntools)
    """

    qemu: subprocess.Popen = None

    if QEMU_PORT is None:
        print("'QEMU_PORT' environment variable not set")
        sys.stdout.flush()
        os._exit(1)

    def _start_binary(asm: str, arch: str, *args):
        nonlocal qemu

        # This is defaulting to 32-bit in this case, breaks the compilation
        if arch == "riscv64":
            context.bits = 64

        context.arch = arch
        binary_tmp_path = make_elf_from_assembly(asm)
        qemu_suffix = pwnlib.qemu.archname(arch=arch)

        qemu = subprocess.Popen(
            [
                f"qemu-{qemu_suffix}",
                "-g",
                f"{QEMU_PORT}",
                f"{binary_tmp_path}",
            ]
        )

        os.environ["PWNDBG_IN_TEST"] = "1"
        os.environ["COLUMNS"] = "80"
        gdb.execute("set exception-verbose on")
        gdb.execute("set width 80")
        gdb.execute(f"target remote :{QEMU_PORT}")

        global _start_binary_called
        # if _start_binary_called:
        #     raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary

    qemu.kill()


@pytest.fixture
def qemu_start_binary():
    """
    Returns function that launches given binary with 'starti' command

    Argument `path` is the path to the binary
    """

    qemu: subprocess.Popen = None

    if QEMU_PORT is None:
        print("'QEMU_PORT' environment variable not set")
        sys.stdout.flush()
        os._exit(1)

    def _start_binary(path: str, arch: str, *args):
        nonlocal qemu

        qemu = subprocess.Popen(
            [
                f"qemu-{arch}",
                "-L",
                f"/usr/{arch}-linux-gnu/",
                "-g",
                f"{QEMU_PORT}",
                f"{path}",
            ]
        )

        os.environ["PWNDBG_IN_TEST"] = "1"
        os.environ["COLUMNS"] = "80"
        gdb.execute("set exception-verbose on")
        gdb.execute("set width 80")
        gdb.execute(f"target remote :{QEMU_PORT}")

        global _start_binary_called
        # if _start_binary_called:
        #     raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary

    qemu.kill()
