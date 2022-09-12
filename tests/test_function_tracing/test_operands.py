"""
Tests emulated operand objects.
"""

import pytest


@pytest.mark.in_ida_arm
def test_barrel_shifted_operands():
    """Tests ARM's barrel shifted operand types"""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing import FunctionTracingError

    emulator = function_tracing.Emulator()

    # MOV     R1, R3,LSR#31
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103A4)
    ctx.ip = insn.ip
    assert insn.operands[1].text == "R3,LSR#31"
    ctx.registers.r3 = 0xffffffff
    ctx.registers.c = 0
    assert ctx.registers.r3 == 0xffffffff
    assert ctx.registers.c == 0
    assert insn.operands[1].value == 0x1
    assert ctx.registers.c == 0  # carry flag should have not been updated, (not MOVS)

    # ADD     R1, R1, R3,ASR#2
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103A8)
    ctx.ip = insn.ip
    assert insn.operands[2].text == "R3,ASR#2"
    ctx.registers.r3 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[2].value == 0x1013 >> 2
    assert ctx.registers.c == 0  # carry flag should have not been updated, (not ADDS)
    # Test again with a negative number to ensure ASR sign extends appropriately.
    ctx.registers.r3 = -0x1013
    assert ctx.registers.r3 == 0xffffefed   # sanity check
    assert insn.operands[2].value == 0xfffffbfb  # sign extended shift right 2
    assert ctx.registers.c == 0

    # MOVS    R1, R1,ASR#1
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103AC)
    ctx.ip = insn.ip
    assert insn.operands[1].text == "R1,ASR#1"
    ctx.registers.r1 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[1].value == 0x1013 >> 1
    assert ctx.registers.c == 1  # carry flag should be affected (MOVS)
    # reset instruction pointer to ensure carry flag is only affected if ip is the same.
    ctx.ip = 0
    assert ctx.ip != insn.ip
    ctx.registers.r1 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[1].value == 0x1013 >> 1
    assert ctx.registers.c == 0  # carry flag should not be affected, (ctx.ip != insn.ip)

    # Ensure proper error is thrown if we attempt to set the operand value.
    with pytest.raises(FunctionTracingError):
        insn.operands[1].value = 10


@pytest.mark.in_ida_arm
def test_register_list_operands():
    """Tests ARM operands that are register lists."""
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # POPEQ   {R4-R10,PC}
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x106A8)
    assert insn.operands[0].text == "{R4-R10,PC}"
    assert insn.operands[0].is_register_list is True
    assert insn.operands[0].register_list == ["R4", "R5", "R6", "R7", "R8", "R9", "R10", "PC"]
    ctx.registers.r4 = 4
    ctx.registers.r5 = 5
    ctx.registers.r6 = 6
    ctx.registers.r7 = 7
    ctx.registers.r8 = 8
    ctx.registers.r9 = 9
    ctx.registers.r10 = 10
    ctx.registers.pc = 1024
    assert insn.operands[0].value == [4, 5, 6, 7, 8, 9, 10, 1024]
    insn.operands[0].value = [10, 20, 30, 40, 50, 60, 70, 80]
    assert insn.operands[0].value == [10, 20, 30, 40, 50, 60, 70, 80]
    assert ctx.registers.r4 == 10
    assert ctx.registers.r5 == 20
    assert ctx.registers.r6 == 30
    assert ctx.registers.r7 == 40
    assert ctx.registers.r8 == 50
    assert ctx.registers.r9 == 60
    assert ctx.registers.r10 == 70
    assert ctx.registers.pc == 80

    # ValueError should be thrown if we set the wrong amount of values.
    with pytest.raises(ValueError):
        insn.operands[0].value = [1, 2, 3]


@pytest.mark.in_ida_arm
def test_memory_addressing_modes():
    """Tests pre/post indexed memory address operands."""
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Post-index
    # LDR     R3, [R5],#4
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x106BC)
    assert insn.operands[1].text == "[R5],#4"
    ctx.registers.r5 = 5
    # operand initially points to address 0x5
    assert insn.operands[1].addr == 5
    assert insn.operands[1].value == 0x8070605
    insn.execute()
    # operand should now point to address 0x5 + 4
    assert ctx.registers.r5 == 5 + 4
    assert insn.operands[1].addr == 5 + 4
    assert insn.operands[1].value == 0xc0b0a09

    # Pre-index (no update)
    # LDR     R2, [R3,R2]
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x10354)
    assert insn.operands[1].text == "[R3,R2]"
    ctx.registers.r2 = 2
    ctx.registers.r3 = 3
    # operand initially points to address 3 + 2
    assert insn.operands[1].addr == 3 + 2
    assert insn.operands[1].value == 0x8070605
    insn.execute()
    # operands should still point to address 3 + 2
    assert ctx.registers.r3 == 3
    ctx.registers.r2 = 2  # undo the modification to R2 the instruction does :)
    assert insn.operands[1].addr == 3 + 2
    assert insn.operands[1].value == 0x8070605

    # Pre-index with update
    # LDR     PC, [LR,#8]!
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x102D4)
    assert insn.operands[1].text in ("[LR,#8]!", "[LR,#(off_21008 - 0x21000)]!")
    ctx.registers.lr = 2
    # operand initially points to address 0x2 + 8
    assert insn.operands[1].addr == 2 + 8
    assert insn.operands[1].value == 0xd0c0b0a
    insn.execute()
    # operand should now point to address 0x2 + 8 + 8
    assert ctx.registers.lr == 2 + 8
    assert insn.operands[1].addr == 2 + 8 + 8
    assert insn.operands[1].value == 0x15141312
