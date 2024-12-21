from __future__ import annotations

import gdb

import pwndbg.color

ARM_GRACEFUL_EXIT = """
mov r0, 0
mov r7, 0xf8
swi #0
"""

ARM_BRANCHES = f"""
mov r2, #5
mov r1, #10
cmp r0, r1
bne not_equal
nop
nop
not_equal:
    mov r3, #1
    cmp r1, r3
    bgt greater
nop
nop
greater:
    cmp r3, r1
    bls end
nop
nop
end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_simple_branch(qemu_assembly_run):
    """
    Simple test to ensure branches are being followed correctly and that they are remembered when stepping past them
    """
    qemu_assembly_run(ARM_BRANCHES, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>         mov    r2, #5       R2 => 5\n"
        "   0x10000004 <_start+4>       mov    r1, #0xa     R1 => 0xa\n"
        "   0x10000008 <_start+8>       cmp    r0, r1       0x0 - 0xa     CPSR => 0x80000010 [ N z c v q j t e a i f ]\n"
        "   0x1000000c <_start+12>    ✔ bne    #not_equal                  <not_equal>\n"
        "    ↓\n"
        "   0x10000018 <not_equal>      mov    r3, #1       R3 => 1\n"
        "   0x1000001c <not_equal+4>    cmp    r1, r3       0xa - 0x1     CPSR => 0x20000010 [ n z C v q j t e a i f ]\n"
        "   0x10000020 <not_equal+8>  ✔ bgt    #greater                    <greater>\n"
        "    ↓\n"
        "   0x1000002c <greater>        cmp    r3, r1       0x1 - 0xa     CPSR => 0x80000010 [ N z c v q j t e a i f ]\n"
        "   0x10000030 <greater+4>    ✔ bls    #end                        <end>\n"
        "    ↓\n"
        "   0x1000003c <end>            mov    r0, #0        R0 => 0\n"
        "   0x10000040 <end+4>          mov    r7, #0xf8     R7 => 0xf8\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )
    assert dis == expected

    gdb.execute("si 8")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        "   0x1000000c <_start+12>    ✔ bne    #not_equal                  <not_equal>\n"
        "    ↓\n"
        "   0x10000018 <not_equal>      mov    r3, #1       R3 => 1\n"
        "   0x1000001c <not_equal+4>    cmp    r1, r3       0xa - 0x1     CPSR => 0x20000010 [ n z C v q j t e a i f ]\n"
        "   0x10000020 <not_equal+8>  ✔ bgt    #greater                    <greater>\n"
        "    ↓\n"
        "   0x1000002c <greater>        cmp    r3, r1       0x1 - 0xa     CPSR => 0x80000010 [ N z c v q j t e a i f ]\n"
        " ► 0x10000030 <greater+4>    ✔ bls    #end                        <end>\n"
        "    ↓\n"
        "   0x1000003c <end>            mov    r0, #0                  R0 => 0\n"
        "   0x10000040 <end+4>          mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x10000044 <end+8>          svc    #0 <SYS_exit_group>\n"
        "   0x10000048                  andeq  r1, r0, r1, asr #24\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_INTERWORKING_BRANCH = f"""
add r0, pc, #1
bx r0

.THUMB
mov r2, #4
add r2, r2, r0

end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_interworking_branch(qemu_assembly_run):
    """
    This test checks that we properly recognize a transition from Arm to Thumb mode.
    This requires Capstone to be synced with Unicorn, and for Unicorn to properly execute Thumb instructions.

    The code starts in Arm mode, then transitions to Thumb mode.
    If this breaks, it is likely that something has stopped Unicorn from correctly running Thumb mode instructions.

    Additionally, the lowest bit of the target must always be 0 - although interworking branches that transition to Thumb mode
    appear to write a 1 to the lowest bit, in the hardware the bit is directed to the Thumb bit in the CPSR flags register.
    See: https://github.com/pwndbg/pwndbg/pull/2292
    """
    qemu_assembly_run(ARM_INTERWORKING_BRANCH, "arm")

    dis = gdb.execute("emulate 3", to_string=True)

    expected = (
        " ► 0x10000000 <_start>       add    r0, pc, #1     R0 => 0x10000009 (_start+9) (0x10000008 + 0x1)\n"
        "   0x10000004 <_start+4>     bx     r0                          <_start+8>\n"
        "    ↓\n"
        "   0x10000008 <_start+8>     mov.w  r2, #4                  R2 => 4\n"
        "   0x1000000c <_start+12>    add    r2, r0                  R2 => 0x1000000d (_start+13) (0x4 + 0x10000009)\n"
        "   0x1000000e <end>          mov.w  r0, #0                  R0 => 0\n"
        "   0x10000012 <end+4>        mov.w  r7, #0xf8               R7 => 0xf8\n"
        "   0x10000016 <end+8>        svc    #0 <SYS_exit_group>\n"
    )

    assert dis == expected

    # Make sure the transition is remembered

    gdb.execute("si 2")

    dis = gdb.execute("emulate 3", to_string=True)

    expected = (
        "   0x10000000 <_start>       add    r0, pc, #1     R0 => 0x10000009 (_start+9) (0x10000008 + 0x1)\n"
        "   0x10000004 <_start+4>     bx     r0                          <_start+8>\n"
        "    ↓\n"
        " ► 0x10000008 <_start+8>     mov.w  r2, #4                  R2 => 4\n"
        "   0x1000000c <_start+12>    add    r2, r0                  R2 => 0x1000000d (_start+13) (0x4 + 0x10000009)\n"
        "   0x1000000e <end>          mov.w  r0, #0                  R0 => 0\n"
        "   0x10000012 <end+4>        mov.w  r7, #0xf8               R7 => 0xf8\n"
        "   0x10000016 <end+8>        svc    #0 <SYS_exit_group>\n"
    )

    assert dis == expected


ARM_IMPLICIT_BRANCH = """
ldr     R1, =_target
ADD PC, R1, #1

nop

.THUMB
_target:
mov r1, #2
mov r2, #4
mov r6, #3
add r1, r2, r3
sub r4, r5, r6
orr r6, r6, r5
and r2, r2, r5
eor r1, r2, r1
lsr r3, #4
"""


def test_arm_implicit_branch(qemu_assembly_run):
    """
    In Arm, many general-purpose instructions can target the PC as the destination register, particularly while changing between Arm/Thumb mode

    For example, the `add` and `sub` instructions can be used to directory write to the PC, forming a branch.

    This test contains a "add" instruction that causes the PC to change. We want there to be a <target> displayed, and a space after it in the disasm
    """

    qemu_assembly_run(ARM_IMPLICIT_BRANCH, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>        ldr    r1, [pc, #0x28]     R1, [_target+36] => 0x1000000c (_target) ◂— 0x102f04f\n"
        "   0x10000004 <_start+4>      add    pc, r1, #1                  <_target>\n"
        "    ↓\n"
        "   0x1000000c <_target>       mov.w  r1, #2              R1 => 2\n"
        "   0x10000010 <_target+4>     mov.w  r2, #4              R2 => 4\n"
        "   0x10000014 <_target+8>     mov.w  r6, #3              R6 => 3\n"
        "   0x10000018 <_target+12>    add.w  r1, r2, r3          R1 => 4 (4 + 0)\n"
        "   0x1000001c <_target+16>    sub.w  r4, r5, r6          R4 => 0xfffffffd (0 - 3)\n"
        "   0x10000020 <_target+20>    orr.w  r6, r6, r5          R6 => 3 (3 | 0)\n"
        "   0x10000024 <_target+24>    and.w  r2, r2, r5          R2 => 0 (4 & 0)\n"
        "   0x10000028 <_target+28>    eor.w  r1, r2, r1          R1 => 4 (0 ^ 4)\n"
        "   0x1000002c <_target+32>    lsr.w  r3, r3, #4          R3 => 0 (0 >> 4)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_IMPLICIT_BRANCH_NEXT_INSTRUCTION = """
ldr     R1, =_target
ADD PC, R1, #1

.THUMB
_target:
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
"""


def test_arm_implicit_branch_next_instruction(qemu_assembly_run):
    """
    This is near identical to the test above, with a minor change that makes it tricky.

    The branch target of the add instruction is the next instruction in memory. This requires special detection for this case, as we typically
    detect branches based on the "next pc" being NOT the address of the next instruction in memory.

    Seeing something like this is very typical while interworking
    """
    qemu_assembly_run(ARM_IMPLICIT_BRANCH_NEXT_INSTRUCTION, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>        ldr    r1, [pc, #0x24]     R1, [_target+36] => 0x10000008 (_target) ◂— 0x103eb02\n"
        "   0x10000004 <_start+4>      add    pc, r1, #1                  <_target>\n"
        "    ↓\n"
        "   0x10000008 <_target>       add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x1000000c <_target+4>     add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x10000010 <_target+8>     add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x10000014 <_target+12>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x10000018 <_target+16>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x1000001c <_target+20>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x10000020 <_target+24>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x10000024 <_target+28>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x10000028 <_target+32>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_LDR_TO_PC = f"""

ldr    pc, =end
nop

end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_implicit_branch_ldr(qemu_assembly_run):
    """
    Like the previous test, but using the LDR instruction to load a value into the PC.

    These are very common as PLT trampolines:
        ldr    pc, [ip, #0xbf4]!           <printf>
    """
    qemu_assembly_run(ARM_LDR_TO_PC, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>    ldr    pc, [pc, #0xc]              <end>\n"
        "    ↓\n"
        "   0x10000008 <end>       mov    r0, #0                  R0 => 0\n"
        "   0x1000000c <end+4>     mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x10000010 <end+8>     svc    #0 <SYS_exit_group>\n"
        "   0x10000014 <end+12>    andne  r0, r0, r8\n"
        "   0x10000018             andeq  r1, r0, r1, asr #24\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    gdb.execute("si")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        "   0x10000000 <_start>    ldr    pc, [pc, #0xc]              <end>\n"
        "    ↓\n"
        " ► 0x10000008 <end>       mov    r0, #0                  R0 => 0\n"
        "   0x1000000c <end+4>     mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x10000010 <end+8>     svc    #0 <SYS_exit_group>\n"
        "   0x10000014 <end+12>    andne  r0, r0, r8\n"
        "   0x10000018             andeq  r1, r0, r1, asr #24\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


def test_arm_mode_banner(qemu_assembly_run):
    """
    Makes sure that we detect Arm mode correctly in the banner
    """
    qemu_assembly_run(ARM_INTERWORKING_BRANCH, "arm")

    out = gdb.execute("context disasm", to_string=True).split("\n")

    assert (
        out[1] == "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────"
    )

    gdb.execute("si 2")

    out = gdb.execute("context disasm", to_string=True).split("\n")

    assert (
        out[1] == "─────────────────[ DISASM / arm / thumb mode / set emulate on ]─────────────────"
    )


ARM_STACK_CRASH = f"""
mov r0, #4
mov r1, #3
add r2, r0, r1
sub r3, r2, #2
push {{r3}}
pop {{r4}}
mul r4, r2, r1
add r4, r4, #1
end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_stack_pointer_check(qemu_assembly_run):
    """
    This tests runs a small program that has an access to the stack in the middle.

    We are testing to ensure that Unicorn does not crash on this access to the stack pointer (the pop instruction).
    If the emulator registers are not instantiated in the correct order (CPSR is written AFTER stack pointer),
    the stack pointer will be reset to zero due to banked registers: https://github.com/unicorn-engine/unicorn/issues/1984

    If this test fails (annotations after the str/pop don't show), it likely means that the stack pointer has the incorrect value.

    See also: https://github.com/pwndbg/pwndbg/pull/2337
    """
    qemu_assembly_run(ARM_STACK_CRASH, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>       mov    r0, #4                  R0 => 4\n"
        "   0x10000004 <_start+4>     mov    r1, #3                  R1 => 3\n"
        "   0x10000008 <_start+8>     add    r2, r0, r1              R2 => 7 (4 + 3)\n"
        "   0x1000000c <_start+12>    sub    r3, r2, #2              R3 => 5 (7 - 2)\n"
        f"   0x10000010 <_start+16>    str    r3, [sp, #-4]!          [{hex(pwndbg.aglib.regs.sp - 4)}] <= 5\n"
        "   0x10000014 <_start+20>    pop    {r4}\n"
        "   0x10000018 <_start+24>    mul    r4, r2, r1              R4 => 21 (7 * 3)\n"
        "   0x1000001c <_start+28>    add    r4, r4, #1              R4 => 22 (0x15 + 0x1)\n"
        "   0x10000020 <end>          mov    r0, #0                  R0 => 0\n"
        "   0x10000024 <end+4>        mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x10000028 <end+8>        svc    #0 <SYS_exit_group>\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_CMP = f"""
mov r0, #5
mov r1, #5
cmp r0, r1
beq end
nop
nop
nop
end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_cmp_instructions(qemu_assembly_run):
    qemu_assembly_run(ARM_CMP, "arm")
    dis = gdb.execute("context disasm", to_string=True)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>       mov    r0, #5     R0 => 5\n"
        "   0x10000004 <_start+4>     mov    r1, #5     R1 => 5\n"
        "   0x10000008 <_start+8>     cmp    r0, r1     5 - 5     CPSR => 0x60000010 [ n Z C v q j t e a i f ]\n"
        "   0x1000000c <_start+12>  ✔ beq    #end                        <end>\n"
        "    ↓\n"
        "   0x1000001c <end>          mov    r0, #0                  R0 => 0\n"
        "   0x10000020 <end+4>        mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x10000024 <end+8>        svc    #0 <SYS_exit_group>\n"
        "   0x10000028                andeq  r1, r0, r1, asr #24\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_BRANCH_AND_LINK = f"""
nop
bl func
nop
nop

end:
{ARM_GRACEFUL_EXIT}

nop
nop
nop
nop

func:
mov r0, #0
bx lr
"""


def test_arm_call_instructions(qemu_assembly_run):
    """
    This test ensures that "call" instructions in Arm do not get unrolled.

    This means the `branch-and-link` instruction, `bl`
    """
    qemu_assembly_run(ARM_BRANCH_AND_LINK, "arm")

    dis = gdb.execute("context disasm", to_string=True)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>       nop    \n"
        "   0x10000004 <_start+4>     bl     #func                       <func>\n"
        " \n"
        "   0x10000008 <_start+8>     nop    \n"
        "   0x1000000c <_start+12>    nop    \n"
        "   0x10000010 <end>          mov    r0, #0        R0 => 0\n"
        "   0x10000014 <end+4>        mov    r7, #0xf8     R7 => 0xf8\n"
        "   0x10000018 <end+8>        svc    #0\n"
        "   0x1000001c <end+12>       nop    \n"
        "   0x10000020 <end+16>       nop    \n"
        "   0x10000024 <end+20>       nop    \n"
        "   0x10000028 <end+24>       nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_STORE = f"""
ldr r0, =value1
ldr r1, =0x87654321
ldr r2, =0x12345678

str r1, [r0]
strex r3, r2, [r0]
str r1, [r0], #1
add r0, r1
nop
nop
nop
nop
nop
{ARM_GRACEFUL_EXIT}

    .data
value1:
    .word 0x0
"""


def test_arm_exclusive_store(qemu_assembly_run):
    """
    This tests that we properly handle both stores, exclusive stores, and store with post-indexing
    """
    qemu_assembly_run(ARM_STORE, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>       ldr    r0, [pc, #0x34]     R0, [_start+60] => 0x11094 (value1) ◂— 0\n"
        "   0x10000004 <_start+4>     ldr    r1, [pc, #0x34]     R1, [_start+64] => 0x87654321\n"
        "   0x10000008 <_start+8>     ldr    r2, [pc, #0x34]     R2, [_start+68] => 0x12345678\n"
        "   0x1000000c <_start+12>    str    r1, [r0]            [value1] <= 0x87654321\n"
        "   0x10000010 <_start+16>    strex  r3, r2, [r0]        [value1] <= 0x12345678\n"
        "   0x10000014 <_start+20>    str    r1, [r0], #1        [value1] <= 0x87654321\n"
        "   0x10000018 <_start+24>    add    r0, r0, r1          R0 => 0x876653b6 (0x11095 + 0x87654321)\n"
        "   0x1000001c <_start+28>    nop    \n"
        "   0x10000020 <_start+32>    nop    \n"
        "   0x10000024 <_start+36>    nop    \n"
        "   0x10000028 <_start+40>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_SHIFTS = """
MOV r0, #0xF000
LSR r1, r0, #4
MOV r2, #2
LSR r3, r0, r2
MOV r4, #0x1234
LSL r5, r4, #8
LSL r6, r4, r2
nop
nop
nop
nop
"""


def test_logical_shifts(qemu_assembly_run):
    """
    Shifts have a different underlying Capstone representation if it's an constant or a register offset.
    This test ensures we handle both cases.
    """
    qemu_assembly_run(ARM_SHIFTS, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x10000000 <_start>       mov    r0, #0xf000     R0 => 0xf000\n"
        "   0x10000004 <_start+4>     lsr    r1, r0, #4      R1 => 0xf00 (0xf000 >> 0x4)\n"
        "   0x10000008 <_start+8>     mov    r2, #2          R2 => 2\n"
        "   0x1000000c <_start+12>    lsr    r3, r0, r2      R3 => 0x3c00 (0xf000 >> 0x2)\n"
        "   0x10000010 <_start+16>    movw   r4, #0x1234     R4 => 0x1234\n"
        "   0x10000014 <_start+20>    lsl    r5, r4, #8      R5 => 0x123400 (0x1234 << 0x8)\n"
        "   0x10000018 <_start+24>    lsl    r6, r4, r2      R6 => 0x48d0 (0x1234 << 0x2)\n"
        "   0x1000001c <_start+28>    nop    \n"
        "   0x10000020 <_start+32>    nop    \n"
        "   0x10000024 <_start+36>    nop    \n"
        "   0x10000028 <_start+40>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected
