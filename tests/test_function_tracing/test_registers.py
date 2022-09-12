"""
Tests emulated register objects.
"""

import pytest


@pytest.mark.in_ida
def test_registers():
    """Tests registers"""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing.cpu_context import ProcessorContext
    from kordesii.utils.function_tracing.registers import Register

    # Basic register tests.
    reg = Register(8, rax=0xFFFFFFFFFFFFFFFF, eax=0xFFFFFFFF, ax=0xFFFF, al=0xFF, ah=0xFF00)
    assert sorted(reg.names) == ["ah", "al", "ax", "eax", "rax"]
    assert reg.rax == 0
    assert reg.ax == 0
    assert reg["rax"] == 0
    assert reg["ax"] == 0
    reg.ah = 0x23
    assert reg.ah == 0x23
    assert reg.al == 0x00
    assert reg.ax == 0x2300
    assert reg.eax == 0x00002300
    reg.eax = 0x123
    assert reg.ah == 0x01
    assert reg.al == 0x23
    assert reg.rax == 0x0000000000000123

    emulator = function_tracing.Emulator()
    context = emulator.new_context()
    registers = context.registers

    # fmt: off
    # Test getting all register names.
    assert sorted(registers.names) == [
        'ac', 'af', 'ah', 'al', 'ax', 'b', 'bh', 'bl', 'bp', 'bpl', 'bx',
        'c0', 'c1', 'c2', 'c3', 'cf', 'ch', 'cl', 'cs', 'cx', 'd', 'df',
        'dh', 'di', 'dil', 'dl', 'dm', 'ds', 'dx', 'eax', 'ebp', 'ebx',
        'ecx', 'edi', 'edx', 'eflags', 'es', 'esi', 'esp', 'flags', 'fs', 'gs', 'i', 'ic',
        'id', 'iem', 'if', 'im', 'iopl', 'ir', 'nt', 'o', 'of', 'om', 'p',
        'pc', 'pf', 'pm', 'r10', 'r10b', 'r10d', 'r10w', 'r11', 'r11b',
        'r11d', 'r11w', 'r12', 'r12b', 'r12d', 'r12w', 'r13', 'r13b', 'r13d',
        'r13w', 'r14', 'r14b', 'r14d', 'r14w', 'r15', 'r15b', 'r15d', 'r15w',
        'r8', 'r8b', 'r8d', 'r8w', 'r9', 'r9b', 'r9d', 'r9w', 'rax', 'rbp',
        'rbx', 'rc', 'rcx', 'rdi', 'rdx', 'rf', 'rip', 'rsi', 'rsp', 'sf',
        'sf', 'si', 'sil', 'sp', 'spl', 'ss',
        'st', 'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7',
        'tag0', 'tag1', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6', 'tag7',
        'tf', 'top', 'u', 'um', 'vif', 'vip', 'vm',
        'xmm0', 'xmm1', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
        'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9',
        'z', 'zf', 'zm',
    ]
    # Test getting register names for FPU.
    assert sorted(registers.fpu.names) == [
        "b", "c0", "c1", "c2", "c3", "d", "dm", "i", "ic", "iem", "im", "ir",
        "o", "om", "p", "pc", "pm", "rc", "sf",
        "st", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
        "tag0", "tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7",
        "top", "u", "um", "z", "zm",
    ]
    # fmt: on

    # Test FPU registers.
    # TODO: Add tests for flags
    EMPTY = registers.fpu.EMPTY
    assert registers.st0 == EMPTY
    assert registers["st0"] == EMPTY
    assert registers.fpu.st0 == EMPTY
    assert registers.fpu["st0"] == EMPTY
    registers.fpu.push(-12.3)
    assert registers.st0 == -12.3
    assert registers.st1 == EMPTY
    registers.fpu.push(34)
    assert registers.st0 == 34
    assert registers.st1 == -12.3
    registers.fpu.pop()
    assert registers.st0 == -12.3
    assert registers.st1 == EMPTY
    registers.fpu.push(registers.fpu.INFINITY)
    assert registers.st0 == registers.fpu.INFINITY
    assert registers.st1 == -12.3
