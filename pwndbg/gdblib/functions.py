"""
Put all functions defined for gdb in here.

This file might be changed into a module in the future.
"""

from __future__ import annotations

import functools
from typing import Any
from typing import Callable
from typing import List

import gdb

import pwndbg.aglib.elf
import pwndbg.aglib.proc
import pwndbg.aglib.vmmap
from pwndbg.lib.common import hex2ptr_common

functions: List[_GdbFunction] = []


def GdbFunction(only_when_running: bool = False) -> Callable[..., Any]:
    return functools.partial(_GdbFunction, only_when_running=only_when_running)


class _GdbFunction(gdb.Function):
    def __init__(self, func: Callable[..., Any], only_when_running: bool) -> None:
        self.name = func.__name__
        self.func = func
        self.only_when_running = only_when_running
        self.__doc__ = func.__doc__

        functions.append(self)

        super().__init__(self.name)

        functools.update_wrapper(self, func)

    def invoke(self, *args: gdb.Value) -> Any:
        if self.only_when_running and not pwndbg.aglib.proc.alive:
            # Returning empty string is a workaround that we can't stop e.g. `break *$rebase(offset)`
            # Thx to that, gdb will print out 'evaluation of this expression requires the target program to be active'
            return ""

        return self.func(*args)

    def __call__(self, *args: gdb.Value) -> Any:
        return self.invoke(*args)


@GdbFunction(only_when_running=True)
def rebase(addr: gdb.Value | int) -> int:
    """Return rebased address."""
    base = pwndbg.aglib.elf.exe().address
    return base + int(addr)


@GdbFunction(only_when_running=True)
def base(name_pattern: gdb.Value | str) -> int:
    """Return base address of the first memory mapping containing the given name."""
    if isinstance(name_pattern, gdb.Value):
        name = name_pattern.string()
    else:
        name = name_pattern

    for p in pwndbg.aglib.vmmap.get():
        if name in p.objfile:
            return p.vaddr
    raise ValueError(f"No mapping named {name}")


@GdbFunction(only_when_running=True)
def hex2ptr(hex_string: gdb.Value | str) -> int:
    """Converts a hex string to a little-endian address and returns the address.
    Example usage: $hex2ptr("00 70 75 c1 cd ef 59 00")"""
    if isinstance(hex_string, gdb.Value):
        hex_string = hex_string.string()

    hex_string = hex_string.replace(" ", "")
    pointer = hex2ptr_common(hex_string)
    return pointer
