import logging

from . import utils as arm_utils
from .. import utils
from ..exceptions import FunctionTracingError
from ..registry import registrar


logger = logging.getLogger(__name__)


# Dictionary containing opcode names -> function
OPCODES = {}
opcode = registrar(OPCODES, name="opcode")


""" 
Conditional branch instructions

Conditional branches change the flow of execution depending on the current state of the Condition flags or the value
in a general-purpose register.

Condition codes

cond    Mnemonic    Meaning (integer)                   Meaning (floating-point)*           Condition flags
0000    EQ          Equal                               Equal                               Z == 1
0001    NE          Not equal                           Not equal or unordered              Z == 0
0010    CS or HS    Carry set                           Greater than, equal, or unordered   C == 1
0011    CC or LO    Carry clear                         Less than                           C == 0
0100    MI          Minus, negative                     Less than                           N == 1
0101    PL          Plus, positive or zero              Greater than, equal, or unordered   N == 0
0110    VS          Overflow                            Unordered                           V == 1
0111    VC          No overflow                         Ordered                             V == 0
1000    HI          Unsigned higher                     Greater than, or unordered          C ==1 && Z == 0
1001    LS          Unsigned lower or same              Less than or equal                  !(C ==1 && Z ==0)
1010    GE          Signed greater than or equal        Greater than or equal               N == V
1011    LT          Signed less than                    Less than, or unordered             N! = V
1100    GT          Signed greater than                 Greater than                        Z == 0 && N == V
1101    LE          Signed less than or equal           Less than, equal, or unordered      !(Z == 0 && N == V)
1110    AL          Always                              Always                              Any
1111    NV**        Always                              Always                              Any

*  Unordered means at least one NaN operand.
** The Condition code NV exists only to provide a valid disassembly of the 0b1111 encoding, otherwise its behavior is identical
   to AL.
   
   
   
Mnemonic        Instruction                         Branch offset range from the PC
B.cond          Branch conditionally                ±1MB 
CBNZ            Compare and branch if nonzero       ±1MB
CBZ             Compare and branch if zero          ±1MB 
TBNZ            Test bit and branch if nonzero      ±32KB
TBZ             Test bit and branch if zero         ±32KB
"""

# TODO: How does IDA report the mnemonic for B.cond


@opcode
def CBNZ(cpu_context, instruction):
    """Compare and branch if nonzero"""
    operands = instruction.operands
    value = operands[0].value
    jump_target = operands[1].value

    if value != 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.


@opcode
def CBZ(cpu_context, instruction):
    """Compare and branch if zero"""
    operands = instruction.operands
    value = operands[0].value
    jump_target = operands[1].value

    if value == 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.


@opcode
def TBNZ(cpu_context, instruction):
    """Test bit and branch if nonzero"""
    operands = instruction.operands
    value = operands[0].value
    bit_number = operands[1].value
    jump_target = operands[2].value

    if value & (1 << bit_number) != 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.


@opcode
def TBZ(cpu_context, instruction):
    """Test bit and branch if zero"""
    operands = instruction.operands
    value = operands[0].value
    bit_number = operands[1].value
    jump_target = operands[2].value

    if value & (1 << bit_number) == 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.


"""
Unconditional branch (immediate/register)

Unconditional branch (immediate) instructions change the flow of execution unconditionally by adding an immediate
offset with a range of ±128MB to the value of the program counter that fetched the instruction.  The BL instruction
also writes the address of the sequentially following instruction to general-purpose register X30.

Unconditional branch (register) instructions change the flow of execution unconditionally by setting the program 
counter to the value in a general-purpose register.  The BLR instruction also writes the address of the sequentially
following instruction to general-purpose register X30.
"""


@opcode("b")
@opcode("br")
@opcode("bx")
def B(cpu_context, instruction):
    """Branch unconditionally"""
    cpu_context.ip = instruction.operands[0].value


@opcode("bl")
@opcode("blr")
@opcode("blx")
def BL(cpu_context, instruction):
    """Branch with link"""
    operands = instruction.operands
    # Function pointer can be a memory reference or immediate.
    func_ea = operands[0].addr or operands[0].value
    func_name = utils.get_function_name(func_ea)

    logger.debug("call %s", func_name or f"0x{func_ea:X}")

    # Store next ip to lr register.
    cpu_context.registers.lr = instruction.ip + 4
    # Branch
    cpu_context.ip = operands[0].value

    if operands[0].is_func_ptr:
        cpu_context._execute_call(func_name, func_ea, instruction.ip)

    # Restore instruction pointer to return address.
    cpu_context.ip = cpu_context.registers.lr


"""
System register instructions

For detailed information about the System register instructions, see Chapter C5 The A64 System Instruction Class.
Table C3-7 shows the System register instructions.

Mnemonic        Instruction                                             See
MRS             Move System register to general-purpose register        MRS on page C6-1024
MSR             Move general-purpose register to System register        MSR (register) on page C6-1027
                Move immediate to PE state field                        MSR (immediate) on page C6-1025
"""


@opcode("mrs")
@opcode("msr")
def _mov(cpu_context, instruction):
    operands = instruction.operands
    operands[0].value = operands[1].value


"""
Load/Store register
The Load/Store register instructions support the following addressing modes:
• Base plus a scaled 12-bit unsigned immediate offset or base plus an unscaled 9-bit signed immediate offset.
• Base plus a 64-bit register offset, optionally scaled.
• Base plus a 32-bit extended register offset, optionally scaled.
• Pre-indexed by an unscaled 9-bit signed immediate offset.
• Post-indexed by an unscaled 9-bit signed immediate offset.
• PC-relative literal for loads of 32 bits or more.

If a Load instruction specifies writeback and the register being loaded is also the base register, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs the load using the specified addressing mode and the base register becomes
  UNKNOWN. In addition, if an exception occurs during the execution of such an instruction, the base address
  might be corrupted so that the instruction cannot be repeated.

If a Store instruction performs a writeback and the register that is stored is also the base register, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs the store to the designated register using the specified addressing mode, but the
  value stored is UNKNOWN.
  
  
Load/Store scalar SIMD and floating-point
The Load/Store scalar SIMD and floating-point instructions operate on scalar values in the SIMD and floating-point
register file as described in SIMD and floating-point scalar register names on page C1-155. The memory addressing
modes available, described in Load/Store addressing modes on page C1-157, are identical to the general-purpose
register Load/Store instructions, and like those instructions permit arbitrary address alignment unless strict
alignment checking is enabled. However, unlike the Load/Store instructions that transfer general-purpose registers,
Load/Store scalar SIMD and floating-point instructions make no guarantee of atomicity, even when the address is
naturally aligned to the size of the data.

Load/Store scalar SIMD and floating-point register
The Load/Store scalar SIMD and floating-point register instructions support the following addressing modes:
• Base plus a scaled 12-bit unsigned immediate offset or base plus unscaled 9-bit signed immediate offset.
• Base plus 64-bit register offset, optionally scaled.
• Base plus 32-bit extended register offset, optionally scaled.
• Pre-indexed by an unscaled 9-bit signed immediate offset.
• Post-indexed by an unscaled 9-bit signed immediate offset.
• PC-relative literal for loads of 32 bits or more.

Note
The unscaled 9-bit signed immediate offset address mode requires its own instruction form

"""


@opcode
def LDR(cpu_context, instruction):
    """Load with immediate"""
    operands = instruction.operands
    operands[0].value = operands[1].value


@opcode
def STR(cpu_context, instruction):
    """Store with immediate"""
    operands = instruction.operands
    operands[1].value = operands[0].value


"""
Load/Store register (unscaled offset)
The Load/Store register instructions with an unscaled offset support only one addressing mode:
• Base plus an unscaled 9-bit signed immediate offset.

The Load/Store register (unscaled offset) instructions are required to disambiguate this instruction class from the
Load/Store register instruction forms that support an addressing mode of base plus a scaled, unsigned 12-bit
immediate offset, because that can represent some offset values in the same range.

The ambiguous immediate offsets are byte offsets that are both:
• In the range 0-255, inclusive.
• Naturally aligned to the access size.

Other byte offsets in the range -256 to 255 inclusive are unambiguous. An assembler program translating a
Load/Store instruction, for example LDR, is required to encode an unambiguous offset using the unscaled 9-bit offset
form, and to encode an ambiguous offset using the scaled 12-bit offset form. A programmer might force the
generation of the unscaled 9-bit form by using one of the mnemonics in Table C3-16. ARM recommends that a
disassembler outputs all unscaled 9-bit offset forms using one of these mnemonics, but unambiguous offsets can be
output using a Load/Store single register mnemonic, for example, LDR.

Load/Store scalar SIMD and floating-point register (unscaled offset)
The Load /Store scalar SIMD and floating-point register instructions support only one addressing mode:
• Base plus an unscaled 9-bit signed immediate offset.

The Load/Store scalar SIMD and floating-point register (unscaled offset) instructions are required to disambiguate
this instruction class from the Load/Store single SIMD and floating-point instruction forms that support an
addressing mode of base plus a scaled, unsigned 12-bit immediate offset. This is similar to the Load/Store register
(unscaled offset) instructions, that disambiguate this instruction class from the Load/Store register instruction
"""

# TODO: Can LDUR just be an alias for LDR?
@opcode
def LDUR(cpu_context, instruction):
    """Load register (unscaled offset)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


# TODO: Can STUR just be an alias for STR?
@opcode
def STUR(cpu_context, instruction):
    """Store register (unscaled offset)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Load Multiple (Increment After, Full Descending) loads multiple registers from consecutive memory locations
using an address from a base register. The consecutive memory locations start at this address, and the address just
above the highest of those locations can optionally be written back to the base register.
The lowest-numbered register is loaded from the lowest memory address, through to the highest-numbered register
from the highest memory address.

Pop Multiple Registers from Stack loads multiple general-purpose registers from the stack, loading from
consecutive memory locations starting at the address in SP, and updates SP to point just above the loaded data
"""


@opcode
def LDM(cpu_context, instruction):
    """Load Multiple Registers"""
    operands = instruction.operands
    if not operands[1].is_register_list:
        raise FunctionTracingError(f"Expected {operands[1].text} to be a register list.")

    for reg_name in operands[1].register_list:
        value = utils.struct_unpack(cpu_context.memory.read(operands[0].value, 4))
        cpu_context.registers[reg_name] = value
        # TODO: confirm operand is auto-increased in ARMInstruction._execute()


@opcode
def POP(cpu_context, instruction):
    """Load Multiple Register from Stack"""
    operands = instruction.operands
    if not operands[0].is_register_list:
        raise FunctionTracingError(f"Expected {operands[0].text} to be a register list.")

    for reg_name in operands[0].register_list:
        value = utils.struct_unpack(cpu_context.memory.read(cpu_context.sp, 4))
        cpu_context.registers[reg_name] = value
        cpu_context.sp += 4


"""
Store Multiple (Increment After, Empty Ascending) stores multiple registers to consecutive memory locations using
an address from a base register. The consecutive memory locations start at this address, and the address just above
the last of those locations can optionally be written back to the base register.

Push multiple registers to Stack stores multiple general-purpose registers to the stack, storing to consecutive
memory locations ending just below the address in SP, and updates SP to point to the start of the stored data
"""


# TODO: Support different stack types:
#  (STMFD, STMFA, STMED, STMEA, STMIA, STMIB, STMDA, STMDB)
@opcode
def STM(cpu_context, instruction):
    """Store Multiple Registers"""
    operands = instruction.operands
    if not operands[1].is_register_list:
        raise FunctionTracingError(f"Expected {operands[1].text} to be a register list.")

    for value in reversed(operands[1].value):  # .value is a list of values
        cpu_context.write_data(operands[0].value, value)
        # TODO: confirm operand is auto-decreased in ARMInstruction._execute()


@opcode
def PUSH(cpu_context, instruction):
    """Store Multiple Register onto Stack"""
    operands = instruction.operands
    if not operands[0].is_register_list:
        raise FunctionTracingError(f"Expected {operands[0].text} to be a register list.")

    # .value is a list of register values from lowest to highest.
    # Registers are pushed from largest to smallest for PUSH.
    for value in reversed(operands[0].value):
        cpu_context.write_data(cpu_context.sp, value)
        cpu_context.sp -= 4


"""
Load/Store Pair
The Load/Store Pair instructions support the following addressing modes:
• Base plus a scaled 7-bit signed immediate offset.
• Pre-indexed by a scaled 7-bit signed immediate offset.
• Post-indexed by a scaled 7-bit signed immediate offset.

If a Load Pair instruction specifies the same register for the two registers that are being loaded, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs all the loads using the specified addressing mode and the register that is loaded takes
  an UNKNOWN value.
  
If a Load Pair instruction specifies writeback and one of the registers being loaded is also the base register, then
behavior is CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs all of the loads using the specified addressing mode, and the base register becomes
  UNKNOWN. In addition, if an exception occurs during the instruction, the base address might be corrupted so
  that the instruction cannot be repeated.
  
If a Store Pair instruction performs a writeback and one of the registers being stored is also the base register, then
behavior is CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs all the stores of the registers indicated by the specified addressing mode, but the
  value stored for the base register is UNKNOWN.
  
Load/Store SIMD and Floating-point register pair
The Load/Store SIMD and floating-point register pair instructions support the following addressing modes:
• Base plus a scaled 7-bit signed immediate offset.
• Pre-indexed by a scaled 7-bit signed immediate offset.
• Post-indexed by a scaled 7-bit signed immediate offset.

If a Load pair instruction specifies the same register for the two registers that are being loaded, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs all of the loads using the specified addressing mode and the register being loaded
  takes an UNKNOWN value.
"""


@opcode
def LDP(cpu_context, instruction):
    """Load Pair"""
    operands = instruction.operands
    value_a = operands[2].value
    value_b = utils.struct_unpack(cpu_context.memory.read(
        operands[2].addr + operands[0].width,
        operands[1].width,
    ))

    logger.debug("Load 0x%X into %s", value_a, operands[0].text)
    logger.debug("Load 0x%X into %s", value_b, operands[1].text)

    operands[0].value = value_a
    operands[1].value = value_b


@opcode
def STP(cpu_context, instruction):
    """Store Pair"""
    operands = instruction.operands
    value_a = operands[0].value
    value_b = operands[1].value

    logger.debug("Store 0x%X and 0x%X into %s", value_a, value_b, operands[2].text)

    operands[2].value = value_a
    cpu_context.memory.write(
        operands[2].addr + operands[0].width,
        utils.struct_pack(value_b, width=operands[1].width),
    )


"""
Load/Store unprivileged
The Load/Store unprivileged instructions support only one addressing mode:
• Base plus an unscaled 9-bit signed immediate offset.

The accesses permissions that apply to accesses made at EL0 apply to the memory accesses made by a Load/Store
unprivileged instruction that is executed either:
• At EL1 when the Effective value of PSTATE.UAO is 0.
• At EL2 when both the Effective value of HCR_EL2.{E2H, TGE} is {1, 1} and the Effective value of
  PSTATE.UAO is 0.
  
Otherwise, memory accesses made by a Load/Store unprivileged instruction are subject to the access permissions
that apply to the Exception level at which the instruction is executed. These are the permissions that apply to the
corresponding Load/Store register instruction, see Load/Store register on page C3-177.

Note
This means that when the value of PSTATE.UAO is 1 the access permissions for a Load/Store unprivileged
instruction are always the same as those for the corresponding Load/Store register instruction.
"""


@opcode
def LDTR(cpu_context, instruction):
    """Load unprivileged register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STTR(cpu_context, instruction):
    """Store unprivileged register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Load-Exclusive/Store-Exclusive
The Load-Exclusive/Store-Exclusive instructions support only one addressing mode:
• Base register with no offset.

The Load-Exclusive instructions mark the physical address being accessed as an exclusive access. This exclusive
access mark is checked by the Store-Exclusive instruction, permitting the construction of atomic read-modify-write
operations on shared memory variables, semaphores, mutexes, and spinlocks. 

The Load-Exclusive/Store-Exclusive instructions other than Load-Exclusive pair and Store-Exclusive pair require
natural alignment, and an unaligned address generates an Alignment fault. Memory accesses generated by
Load-Exclusive pair or Store-Exclusive pair instructions must be aligned to the size of the pair, otherwise the access
generates an Alignment fault. When a Store-Exclusive pair succeeds, it causes a single-copy atomic update of the
entire memory location.
"""


@opcode
def LDXR(cpu_context, instruction):
    """Load Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDXP(cpu_context, instruction):
    """Load Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STXR(cpu_context, instruction):
    """Store Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STXP(cpu_context, instruction):
    """Store Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Load-Acquire/Store-Release
The Load-Acquire, Load-AcquirePC, and Store-Release instructions support only one addressing mode:
• Base register with no offset.

The Load-Acquire, Load-AcquirePC, and Store-Release instructions can remove the requirement to use the explicit
DMB memory barrier instruction. For more information about the ordering of Load-Acquire, Load-AcquirePC, and
Store-Release, see Load-Acquire, Load-AcquirePC, and Store-Release on page B2-108.

The Load-Acquire, Load-AcquirePC, and Store-Release instructions other than Load-Acquire pair and
Store-Release pair require natural alignment, and an unaligned address generates an Alignment fault. Memory
accesses generated by Load-Acquire pair or Store-Release pair instructions must be aligned to the size of the pair,
otherwise the access generates an Alignment fault.

A Store-Release Exclusive instruction only has the Release semantics if the store is successful.
"""


@opcode
def LDAPR(cpu_context, instruction):
    """Load-Acquire RCpc Register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAPUR(cpu_context, instruction):
    """Load-Acquire RCpc Register (unscaled)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAR(cpu_context, instruction):
    """Load-Acquire Register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLR(cpu_context, instruction):
    """Store-Release Register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLUR(cpu_context, instruction):
    """Store-Release Register (unscaled)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAXR(cpu_context, instruction):
    """Load-Acquire Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAXP(cpu_context, instruction):
    """Load-Acquire Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLXR(cpu_context, instruction):
    """Store-Release Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLXP(cpu_context, instruction):
    """Store-Release Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
The LoadLOAcquire/StoreLORelease instructions support only one addressing mode:
• Base register with no offset.

The LoadLOAcquire/StoreLORelease instructions can remove the requirement to use the explicit DMB memory
barrier instruction. For more information about the ordering of LoadLOAcquire/StoreLORelease, see
LoadLOAcquire, StoreLORelease on page B2-109.

The LoadLOAcquire/StoreLORelease instructions require natural alignment, and an unaligned address generates an
Alignment fault.
"""


@opcode
def LDLAR(cpu_context, instruction):
    """LoadLOAcquire register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLLR(cpu_context, instruction):
    """StoreLORelease register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
The Load/Store SIMD and Floating-point Non-temporal pair instructions support only one addressing mode:
• Base plus a scaled 7-bit signed immediate offset.

The Load/Store Non-temporal pair instructions provide a hint to the memory system that an access is non-temporal
or streaming, and unlikely to be repeated in the near future. This means that data caching is not required. However,
depending on the memory type, the instructions might permit memory reads to be preloaded and memory writes to
be gathered to accelerate bulk memory transfers.

In addition, there is an exception to the usual memory ordering rules. If an address dependency exists between two
memory reads, and a Load non-temporal pair instruction generated the second read, then in the absence of any other
barrier mechanism to achieve order, those memory accesses can be observed in any order by the other observers
within the shareability domain of the memory addresses being accessed.

If a Load Non-temporal pair instruction specifies the same register for the two registers that are being loaded, then
behavior is CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs all the loads using the specified addressing mode and the register that is loaded takes
  an UNKNOWN value.
  
Load/Store Non-temporal Pair
The Load/Store Non-temporal Pair instructions support only one addressing mode:
• Base plus a scaled 7-bit signed immediate offset.

The Load/Store Non-temporal Pair instructions provide a hint to the memory system that an access is non-temporal
or streaming, and unlikely to be repeated in the near future. This means that data caching is not required. However,
depending on the memory type, the instructions might permit memory reads to be preloaded and memory writes to
be gathered to accelerate bulk memory transfers.

In addition, there is an exception to the usual memory ordering rules. If an address dependency exists between two
memory reads, and a Load Non-temporal Pair instruction generated the second read, then in the absence of any other
barrier mechanism to achieve order, the memory accesses can be observed in any order by the other observers within
the shareability domain of the memory addresses being accessed.

If a Load Non-Temporal Pair instruction specifies the same register for the two registers that are being loaded, then
behavior is CONSTRAINED UNPREDICTABLE and one of the following must occur:
• The instruction is treated as UNDEFINED.
• The instruction is treated as a NOP.
• The instruction performs all the loads using the specified addressing mode and the register that is loaded takes
  an UNKNOWN value.
"""


@opcode
def LDNP(cpu_context, instruction):
    """Load pair of scalar SIMD&FP registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STNP(cpu_context, instruction):
    """Store pair of scalar SIMD&FP registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Load/Store Vector
The Vector Load/Store structure instructions support the following addressing modes:
• Base register only.
• Post-indexed by a 64-bit register.
• Post-indexed by an immediate, equal to the number of bytes transferred.

Load/Store vector instructions, like other Load/Store instructions, allow any address alignment, unless strict
alignment checking is enabled. If strict alignment checking is enabled, then alignment checking to the size of the
element is performed. However, unlike the Load/Store instructions that transfer general-purpose registers, the
Load/Store vector instructions do not guarantee atomicity, even when the address is naturally aligned to the size of
the element.
"""


@opcode
def LD1(cpu_context, instruction):
    """
    Load single 1-element structure to one lane of one register LD1 (single structure) on page C7-1637
    Load multiple 1-element structures to one register or to two, three, or four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD2(cpu_context, instruction):
    """
    Load single 2-element structure to one lane of two consecutive registers LD2 (single structure)
    Load multiple 2-element structures to two consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD3(cpu_context, instruction):
    """
    Load single 3-element structure to one lane of three consecutive registers
    Load multiple 3-element structures to three consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD4(cpu_context, instruction):
    """
    Load single 4-element structure to one lane of four consecutive registers
    Load multiple 4-element structures to four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST1(cpu_context, instruction):
    """
    Store single 1-element structure from one lane of one register
    Store multiple 1-element structures from one register, or from two, three, or four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST2(cpu_context, instruction):
    """
    Store single 2-element structure from one lane of two consecutive registers
    Store multiple 2-element structures from two consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST3(cpu_context, instruction):
    """
    Store single 3-element structure from one lane of three consecutive registers
    Store multiple 3-element structures from three consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST4(cpu_context, instruction):
    """
    Store single 4-element structure from one lane of four consecutive registers
    Store multiple 4-element structures from four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD1R(cpu_context, instruction):
    """Load single 1-element structure and replicate to all lanes of one register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD2R(cpu_context, instruction):
    """Load single 2-element structure and replicate to all lanes of two registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD3R(cpu_context, instruction):
    """Load single 3-element structure and replicate to all lanes of three registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD4R(cpu_context, instruction):
    """Load single 4-element structure and replicate to all lanes of four registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Compare and Swap
The Compare and Swap instructions support only one addressing mode:
• Base register only.

For the purpose of permission checking, and for watchpoints, all of the Compare and Swap instructions are treated
as performing both a load and a store.

The CAS instructions require natural alignment.

The CASP instructions require alignment to the total size of the memory being accessed.

All Compare and Swap instructions generate an Alignment fault if the address being accessed is not aligned to the
size of the data structure being accessed.

The instructions are provided with ordering options, which map to the acquire and release definitions used in the
ARMv8-A architecture. If a compare and swap instruction does not perform a store, then the instruction does not
have release semantics, regardless of the instruction ordering options.
The atomic instructions with release semantics have the same rules as Store-Release instructions regarding
multi-copy atomicity.

For the CAS and CASP instructions, the architecture permits that a data read clears any Exclusives monitors associated
with that location, even if the compare subsequently fails. If these instructions generate a synchronous Data Abort,
the registers which are compared and loaded are restored to the values held in the registers before the instruction
was executed.
"""


@opcode
def CAS(cpu_context, instruction):
    """Compare and swap"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CASP(cpu_context, instruction):
    """Compare and swap pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""Atomic memory operations
The atomic memory operation instructions support only one addressing mode:
• Base register only.

For the purpose of permission checking, and for watchpoints, all of the Compare and Swap instructions are treated
as performing both a load and a store.

The LD<OP> and ST<OP> instructions require natural alignment, and an unaligned address generates an Alignment
fault.

The instructions are provided with ordering options, which map to the acquire and release definitions used in the
ARMv8-A architecture. The atomic instructions with release semantics have the same rules as Store-Release
instructions regarding multi-copy atomicity. These operations map to the acquire and release definitions, and are
counted as Load-Acquire and Store-Release operations respectively.

For the LD<OP> instructions, where the source and destination registers are the same, if the instruction generates a
synchronous Data Abort, then the source register is restored to the value it held before the instruction was executed.

The ST<OP> instructions, and LD<OP> instructions where the destination register is WZR or XZR, are not regarded as
doing a read for the purpose of a DMB LD barrier.
"""


@opcode
def LDADD(cpu_context, instruction):
    """Atomic add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDCLR(cpu_context, instruction):
    """Atomic bit clear"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDEOR(cpu_context, instruction):
    """Atomic exclusive OR"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDSET(cpu_context, instruction):
    """Atomic bit set"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDMAX(cpu_context, instruction):
    """Atomic signed maximum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDMIN(cpu_context, instruction):
    """Atomic signed minimum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDUMAX(cpu_context, instruction):
    """Atomic unsigned maximum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDUMIN(cpu_context, instruction):
    """Atomic unsigned minimum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STADD(cpu_context, instruction):
    """Atomic add, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STCLR(cpu_context, instruction):
    """Atomic bit clear, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STEOR(cpu_context, instruction):
    """Atomic exclusive OR, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STSET(cpu_context, instruction):
    """Atomic bit set, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STMAX(cpu_context, instruction):
    """Atomic signed maximum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STMIN(cpu_context, instruction):
    """Atomic signed minimum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STUMAX(cpu_context, instruction):
    """Atomic unsigned maximum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STUMIN(cpu_context, instruction):
    """Atomic unsigned minimum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Swap
The swap instructions support only one addressing mode:
• Base register only.

For the purpose of permission checking, and for watchpoints, all of the Compare and Swap instructions are treated
as performing both a load and a store.

The SWP instructions require natural alignment, and an unaligned address generates an Alignment fault.

The instructions are provided with ordering options, which map to the acquire and release definitions used in the
ARMv8-A architecture. The atomic instructions with release semantics have the same rules as Store-Release
instructions regarding multi-copy atomicity.

For the SWP instructions, where the source and destination registers are the same, if the instruction generates a
synchronous Data Abort, then the source register is restored to the value it held before the instruction was executed.
"""


@opcode
def SWP(cpu_context, instruction):
    """Swap"""
    operands = instruction.operands
    value_a = operands[0].value
    value_c = operands[2].value

    logger.debug("Swap %s %s %s", operands[0].text, operands[1].text, operands[2].text)

    operands[1].value = value_c
    operands[2].value = value_a


"""
Arithmetic (immediate)
The Arithmetic (immediate) instructions accept a 12-bit unsigned immediate value, optionally shifted left by 12 bits.

The Arithmetic (immediate) instructions that do not set Condition flags can read from and write to the current stack
pointer. The flag setting instructions can read from the stack pointer, but they cannot write to it.
"""


@opcode("add")
@opcode("adc")
def ADD(cpu_context, instruction):
    """
    Handle both ADC and ADD here since the only difference is the flags.
    """
    operands = instruction.operands
    term_1 = operands[-2].value
    term_2 = operands[-1].value
    result = term_1 + term_2
    if instruction.root_mnem.startswith("adc"):
        result += cpu_context.registers.c

    width = get_max_operand_size(operands)
    mask = utils.get_mask(width)

    if instruction.flag_update:
        cpu_context.registers.c = int(result > mask)
        cpu_context.registers.z = int(result & mask == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.registers.v = int(utils.sign_bit(~(term_1 ^ term_2) & (term_2 ^ result), width) == 0)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    result = result & mask

    logger.debug("0x%X + 0x%X = 0x%X", term_1, term_2, result)
    operands[0].value = result


# TODO: Due to simplification, it may be better to just keep the opcodes separate.
@opcode("sub")
@opcode("sbc")
@opcode("rsb")
@opcode("rsc")
def SUB(cpu_context, instruction):
    """Subtract"""
    operands = instruction.operands
    term_1 = operands[1].value
    term_2 = operands[2].value
    if instruction.mnem.startswith("r"):  # reverse subtract
        term_1, term_2 = term_2, term_1

    result = term_1 - term_2
    if instruction.mnem.startswith(("sbc", "rsc")):
        result -= cpu_context.registers.c ^ 1

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        mask = utils.get_mask(width)
        cpu_context.registers.c = int((term_1 & mask) < (term_2 & mask))
        cpu_context.registers.z = int(result & mask == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.registers.v = int(utils.sign_bit((term_1 ^ term_2) & (term_1 ^ result), width) == 0)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("0x%X - 0x%X = 0x%X", term_1, term_2, result)
    operands[0].value = result


@opcode
def CMP(cpu_context, instruction):
    """Compare"""
    operands = instruction.operands
    term_1 = operands[0].value
    term_2 = operands[1].value
    result = term_1 - term_2
    width = get_max_operand_size(operands)

    # Flags are always updated for CMP
    mask = utils.get_mask(width)
    cpu_context.registers.c = int((term_1 & mask) < (term_2 & mask))
    cpu_context.registers.z = int(result & mask == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.registers.v = int(utils.sign_bit((term_1 ^ term_2) & (term_1 ^ result), width) == 0)
    cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("0x%X <-> 0x%X = 0x%X", term_1, term_2, result)


@opcode
def CMN(cpu_context, instruction):
    """Compare negative"""
    operands = instruction.operands
    value_a = operands[1].value
    value_b = operands[2].value
    result = value_a + value_b
    width = get_max_operand_size(operands)

    mask = utils.get_mask(width)
    cpu_context.registers.c = int(result > mask)
    cpu_context.registers.z = int(result & mask == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.registers.v = int(utils.sign_bit(~(value_a ^ value_b) & (value_b ^ result), width) == 0)
    cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("0x%X <-> 0x%X = 0x%X", value_a, value_b, result)


"""
Logical (immediate)
The Logical (immediate) instructions accept a bitmask immediate value that is a 32-bit pattern or a 64-bit pattern
viewed as a vector of identical elements of size e = 2, 4, 8, 16, 32 or, 64 bits. Each element contains the same
sub-pattern, that is a single run of 1 to (e - 1) nonzero bits from bit 0 followed by zero bits, then rotated by 0 to (e -
1) bits. This mechanism can generate 5334 unique 64-bit patterns as 2667 pairs of pattern and their bitwise inverse.

Note
Values that consist of only zeros or only ones cannot be described in this way.
The Logical (immediate) instructions that do not set the Condition flags can write to the current stack pointer, for
example to align the stack pointer in a function prologue.

Note
Apart from ANDS, and its TST alias, Logical (immediate) instructions do not set the Condition flags. However, the
final results of a bitwise operation can be tested by a CBZ, CBNZ, TBZ, or TBNZ conditional branch.
"""


@opcode
def AND(cpu_context, instruction):
    """Bitwise AND"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 & opvalue3

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X & 0x%X = 0x%X", opvalue2, opvalue3, result)
    operands[0].value = result


def TST(cpu_context, instruction):
    """Test bits (same as ANDS, but result is discarded)"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 & opvalue3

    width = get_max_operand_size(operands)
    cpu_context.registers.z = int(result == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X & 0x%X = 0x%X", opvalue2, opvalue3, result)


@opcode
def EOR(cpu_context, instruction):
    """Bitwise exclusive OR"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 ^ opvalue3

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X ^ 0x%X = 0x%X", opvalue2, opvalue3, result)
    operands[0].value = result


@opcode
def TEQ(cpu_context, instruction):
    """Test Equivalence (same as EORS, except the result is discarded)"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 ^ opvalue3

    width = get_max_operand_size(operands)
    cpu_context.registers.z = int(result == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X ^ 0x%X = 0x%X", opvalue2, opvalue3, result)


@opcode
def ORR(cpu_context, instruction):
    """Bitwise inclusive OR"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 | opvalue3

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X | 0x%X = 0x%X", opvalue2, opvalue3, result)
    operands[0].value = result


"""
Move (wide immediate)
The Move (wide immediate) instructions insert a 16-bit immediate, or inverted immediate, into a 16-bit aligned
position in the destination register. The value of the other bits in the destination register depends on the variant used.
The optional shift amount can be any multiple of 16 that is smaller than the register size.

Move (immediate)
The Move (immediate) instructions are aliases for a single MOVZ, MOVN, or ORR (immediate with zero register),
instruction to load an immediate value into the destination register. An assembler must permit a signed or unsigned
immediate, as long as its binary representation can be generated using one of these instructions, and an assembler
error results if the immediate cannot be generated in this way. On disassembly, it is unspecified whether the
immediate is output as a signed or an unsigned value.

If there is a choice between the MOVZ, MOVN, and ORR instruction to encode the immediate, then an assembler must
prefer MOVZ to MOVN, and MOVZ or MOVN to ORR, to ensure reversability. A disassembler must output ORR (immediate with
zero register) MOVZ, and MOVN, as a MOV mnemonic except that the underlying instruction must be used when:
• ORR has an immediate that can be generated by a MOVZ or MOVN instruction.
• A MOVN instruction has an immediate that can be encoded by MOVZ.
• MOVZ #0 or MOVN #0 have a shift amount other than LSL #0.
"""


@opcode("mov")
@opcode("movz")
def MOV(cpu_context, instruction):
    """Move wide with zero"""
    operands = instruction.operands
    result = operands[1].value

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    operands[0].value = result


@opcode
def MOVN(cpu_context, instruction):
    """Move wide with NOT"""
    operands = instruction.operands
    result = ~operands[1].value

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    operands[0].value = result


@opcode
def MOVK(cpu_context, instruction):
    """Move wide with keep"""
    operands = instruction.operands

    # TODO: Is it always lsl?
    shift_mask = {
        0: 0xFFFFFFFFFFFF0000,
        16: 0xFFFFFFFF0000FFFF,
        32: 0xFFFF0000FFFFFFFF,
        48: 0x0000FFFFFFFFFFFF,
    }[operands[1].shift_count]
    operands[0].value = (operands[0].value & shift_mask) | operands[1].value


"""
PC-relative address calculation
The ADR instruction adds a signed, 21-bit immediate to the value of the program counter that fetched this instruction,
and then writes the result to a general-purpose register. This permits the calculation of any byte address within
±1MB of the current PC.

The ADRP instruction shifts a signed, 21-bit immediate left by 12 bits, adds it to the value of the program counter with
the bottom 12 bits cleared to zero, and then writes the result to a general-purpose register. This permits the
calculation of the address at a 4KB aligned memory region. In conjunction with an ADD (immediate) instruction, or
a Load/Store instruction with a 12-bit immediate offset, this allows for the calculation of, or access to, any address
within ±4GB of the current PC.

Note
The term page used in the ADRP description is short-hand for the 4KB memory region, and is not related to the virtual
memory translation granule size.
"""


@opcode
def ADRP(cpu_context, instruction):
    """Compute address of 4KB page at a PC-relative offset"""
    operands = instruction.operands
    pc = cpu_context.registers.pc
    pc = pc & 0xFFFFFFFFFFFFF000  # Zero out bottom 12 bits of PC
    opvalue2 = operands[1].value
    result = pc + 0x1000*opvalue2

    logger.debug("0x%X + 0x1000*0x%X = 0x%X", pc, opvalue2, result)
    operands[0].value = result


@opcode
def ADR(cpu_context, instruction):
    """Compute address of label at a PC-relative offset."""
    operands = instruction.operands
    pc = cpu_context.registers.pc
    opvalue2 = operands[1].value
    result = pc + opvalue2

    logger.debug("0x%X + 0x%X = 0x%X", pc, opvalue2, result)
    operands[0].value = result


"""
Bitfield move
The Bitfield move instructions copy a field of constant width from bit 0 in the source register to a constant bit
position in the destination register, or from a constant bit position in the source register to bit 0 in the destination
register. The remaining bits in the destination register are set as follows:
• For BFM, the remaining bits are unchanged.
• For UBFM the lower bits, if any, and upper bits, if any, are set to zero.
• For SBFM, the lower bits, if any, are set to zero, and the upper bits, if any, are set to a copy of the
  most-significant bit in the copied field.
"""


@opcode
def BFM(cpu_context, instruction):
    """Bitfield move"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SBFM(cpu_context, instruction):
    """Signed bitfield move"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UBFM(cpu_context, instruction):
    """Unsigned bitfield move (32-bit)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Bitfield insert and extract
The Bitfield insert and extract instructions are implemented as aliases of the Bitfield move instructions. Table C3-40
shows the Bitfield insert and extract aliases.
"""


@opcode
def BFC(cpu_context, instruction):
    """Bitfield insert clear"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BFI(cpu_context, instruction):
    """Bitfield insert"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BFXIL(cpu_context, instruction):
    """Bitfield extract and insert low"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SBFIZ(cpu_context, instruction):
    """Signed bitfield insert in zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SBFX(cpu_context, instruction):
    """Signed bitfield extract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UBFIZ(cpu_context, instruction):
    """Unsigned bitfield insert in zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UBFX(cpu_context, instruction):
    """Unsigned bitfield extract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Extract register
Depending on the register width of the operands, the Extract register instruction copies a 32-bit or 64-bit field from
a constant bit position within a double-width value formed by the concatenation of a pair of source registers to a
destination register.
"""


@opcode
def EXTR(cpu_context, instruction):
    """Extract register from pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Shift (immediate)
Shifts and rotates by a constant amount are implemented as aliases of the Bitfield move or Extract register
instructions. The shift or rotate amount must be in the range 0 to one less than the register width of the instruction,
inclusive.
"""


@opcode
def ASR(cpu_context, instruction):
    """Arithmetic shift right"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.asr(value, count, width=width)

    if instruction.flag_update:
        if count:  # C register is unaffected if the shift value is 0
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X >> 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def LSL(cpu_context, instruction):
    """Logical shift left"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.lsl(value, count, width=width)

    if instruction.flag_update:
        if count:
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X << 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def LSR(cpu_context, instruction):
    """Logical shift right"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.lsr(value, count, width=width)

    if instruction.flag_update:
        if count:
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X >> 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def ROR(cpu_context, instruction):
    """Rotate right"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.ror(value, count, width=width)

    if instruction.flag_update:
        if count:
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X ror 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def EOR(cpu_context, instruction):
    """XOR operands"""
    operands = instruction.operands
    result = operands[1].value ^ operands[2].value

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    operands[0].value = result


"""
Sign-extend and Zero-extend
The Sign-extend and Zero-extend instructions are implemented as aliases of the Bitfield move instructions.
"""


@opcode
def SXT(cpu_context, instruction):
    """Sign-extend"""
    operands = instruction.operands
    operands[0].value = utils.sign_extend(operands[1].value & 0xffff, 2, 4)


@opcode
def UXT(cpu_context, instruction):
    """Zero-extend"""
    operands = instruction.operands
    operands[0].value = operands[1].value & 0xffff


"""
Arithmetic (shifted register)
The Arithmetic (shifted register) instructions apply an optional shift operator to the second source register value
before performing the arithmetic operation. The register width of the instruction controls whether the new bits are
fed into the intermediate result on a right shift or rotate at bit[63] or bit[31].

The shift operators LSL, ASR, and LSR accept an immediate shift amount in the range 0 to one less than the register
width of the instruction, inclusive.
Omitting the shift operator implies LSL #0, which means that there is no shift. A disassembler must not output LSL
#0. However, a disassembler must output all other shifts by zero.

The current stack pointer, SP or WSP, cannot be used with this class of instructions. See Arithmetic (extended
register) on page C3-199 for arithmetic instructions that can operate on the current stack pointer.

Arithmetic (extended register)
The extended register instructions provide an optional sign-extension or zero-extension of a portion of the second
source register value, followed by an optional left shift by a constant amount of 1-4, inclusive.

The extended shift is described by the mandatory extend operator SXTB, SXTH, SXTW, UXTB, UXTH, or UXTW. This is
followed by an optional left shift amount. If the shift amount is not specified, the default shift amount is zero. A
disassembler must not output a shift amount of zero.

For 64-bit instruction forms, the additional operators UXTX and SXTX use all 64 bits of the second source register with
an optional shift. In that case, ARM recommends UXTX as the operator. If and only if at least one register is SP, ARM
recommends use of the LSL operator name, rather than UXTX, and when the shift amount is also zero then both the
operator and the shift amount can be omitted. UXTW and SXTW both use all 32 bits of the second source register with
an optional shift. In that case ARM recommends UXTW as the operator. If and only if at least one register is WSP,
ARM recommends use of the LSL operator name, rather than UXTW, and when the shift amount is also zero then both
the operator and the shift amount can be omitted.

For 32-bit instruction forms, the operators UXTW and SXTW both use all 32 bits of the second source register with an
optional shift. In that case, ARM recommends UXTW as the operator. If and only if at least one register is WSP, ARM
recommends use of the LSL operator name, rather than UXTW, and when the shift amount is also zero then both the
operator and the shift amount can be omitted.

The non-flag setting variants of the extended register instruction permit the use of the current stack pointer as either
the destination register and the first source register. The flag setting variants only permit the stack pointer to be used
as the first source register.

In the 64-bit form of these instructions, the final register operand is written as Wm for all except the UXTX/LSL and SXTX
extend operators. For example:

    CMP X4, W5, SXTW
    ADD X1, X2, W3, UXTB #2
    SUB SP, SP, X1 // SUB SP, SP, X1, UXTX #0

"""


@opcode("neg")
@opcode("ngc")
def NEG(cpu_context, instruction):
    """Negate (and set flags)"""
    operands = instruction.operands
    value = operands[1].value
    if instruction.root_mnem == "ngc":
        value += int(not cpu_context.registers.c)

    result = -value

    if instruction.flag_update:
        width = operands[1].width
        mask = utils.get_mask(width)
        cpu_context.registers.c = int(result & mask != 0)
        cpu_context.registers.z = int(result & mask == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.registers.v = int(utils.sign_bit(value, width) and not utils.sign_bit(result, width))
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("-0x%X -> 0x%X -> %s", value, result, operands[0].text)
    operands[0].value = result


"""
Flag manipulation instructions
The Flag manipulation instructions set the value of the NZCV condition flags directly.

The instructions SETF8 and SETF16 accept one source register and set the NZV condition flags based on the value of
the input register. The instruction RMIF accepts one source register and two immediate values, rotating the first
source register using the first immediate value and setting the NZCV condition flags masked by the second
immediate value.
"""


@opcode
def CFINV(cpu_context, instruction):
    """Invert value of the PSTATE.C bit"""
    cpu_context.registers.c = int(not cpu_context.registers.c)


@opcode
def RMIF(cpu_context, instruction):
    """Rotate, mask insert flags"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SETF8(cpu_context, instruction):
    """Evaluation of 8-bit flags"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SETF16(cpu_context, instruction):
    """Evaluation of 16-bit flags SETF8,"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Logical (shifted register)
The Logical (shifted register) instructions apply an optional shift operator to the second source register value before
performing the main operation. The register width of the instruction controls whether the new bits are fed into the
intermediate result on a right shift or rotate at bit[63] or bit[31].

The shift operators LSL, ASR, LSR, and ROR accept a constant immediate shift amount in the range 0 to one less than
the register width of the instruction, inclusive.

Omitting the shift operator and amount implies LSL #0, which means that there is no shift. A disassembler must not
output LSL #0. However, a disassembler must output all other shifts by zero.

Note
Apart from ANDS, TST, and BICS the logical instructions do not set the Condition flags, but the final result of a bit
operation can usually directly control a CBZ, CBNZ, TBZ, or TBNZ conditional branch.
"""


@opcode
def BIC(cpu_context, instruction):
    """Bitwise bit clear"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BICS(cpu_context, instruction):
    """Bitwise bit clear and set flags"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def EON(cpu_context, instruction):
    """Bitwise exclusive OR NOT"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MVN(cpu_context, instruction):
    """Bitwise NOT"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ORN(cpu_context, instruction):
    """Bitwise inclusive OR NOT"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Shift (register)
In the Shift (register) instructions, the shift amount is the positive value in the second source register modulo the
register size. The register width of the instruction controls whether the new bits are fed into the result on a right shift
or rotate at bit[63] or bit[31].
"""


@opcode
def ASRV(cpu_context, instruction):
    """Arithmetic shift right variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LSLV(cpu_context, instruction):
    """Logical shift left variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LSRV(cpu_context, instruction):
    """Logical shift right variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RORV(cpu_context, instruction):
    """Rotate right variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Multiply
The Multiply instructions write to a single 32-bit or 64-bit destination register, and are built around the fundamental
four operand multiply-add and multiply-subtract operation, together with 32-bit to 64-bit widening variants. A
64-bit to 128-bit widening multiple can be constructed with two instructions, using SMULH or UMULH to generate the
upper 64 bits.
"""


@opcode
def MADD(cpu_context, instruction):
    """Multiply-add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MSUB(cpu_context, instruction):
    """Multiply-subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MNEG(cpu_context, instruction):
    """Multiply-negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MUL(cpu_context, instruction):
    """Multiply"""
    operands = instruction.operands
    term_1 = operands[1].value
    term_2 = operands[2].value
    result = term_1 * term_2

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X * 0x%X = 0x%X", term_1, term_2, result)
    operands[0].value = result


@opcode
def SMADDL(cpu_context, instruction):
    """Signed multiply-add long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMSUBL(cpu_context, instruction):
    """Signed multiply-subtract long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMNEGL(cpu_context, instruction):
    """Signed multiply-negate long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMULL(cpu_context, instruction):
    """Signed multiply long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMULH(cpu_context, instruction):
    """Signed multiply high"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMADDL(cpu_context, instruction):
    """Unsigned multiply-add long"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    opvalue4 = operands[3].value
    result = (opvalue2 * opvalue3) + opvalue4

    logger.debug("(0x%X * 0x%X) + 0x%X = 0x%X", opvalue2, opvalue2, opvalue4, result)
    operands[0].value = result


@opcode
def UMSUBL(cpu_context, instruction):
    """Unsigned multiply-subtract long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMNEGL(cpu_context, instruction):
    """Unsigned multiply-negate long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMULL(cpu_context, instruction):
    """Unsigned multiply long"""
    operands = instruction.operands
    term_1 = operands[-2].value
    term_2 = operands[-1].value
    result = term_1 * term_2

    logger.debug("0x%X * 0x%X = 0x%X", term_1, term_2, result)

    if len(operands) > 3:
        operands[0].value = result & 0xffffffff
        operands[1].value = (result >> 32) & 0xffffffff
    else:
        operands[0].value = result


@opcode
def UMULH(cpu_context, instruction):
    """Unsigned multiply high"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Divide
The Divide instructions compute the quotient of a division, rounded towards zero. The remainder can then be
computed as (numerator - (quotient × denominator)), using the MSUB instruction.

If a signed integer division (INT_MIN / -1) is performed where INT_MIN is the most negative integer value
representable in the selected register size, then the result overflows the signed integer range. No indication of this
overflow is produced and the result that is written to the destination register is INT_MIN.

A division by zero results in a zero being written to the destination register, without any indication that the division
by zero occurred.
"""


@opcode
def SDIV(cpu_context, instruction):
    """Signed divide"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UDIV(cpu_context, instruction):
    """Unsigned divide"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
CRC32
The CRC32 instructions operate on the general-purpose register file to update a 32-bit CRC value from an input value
comprising 1, 2, 4, or 8 bytes. There are two different classes of CRC instructions, CRC32, and CRC32C, that support two
commonly used 32-bit polynomials, known as CRC-32 and CRC-32C.

To fit with common usage, the bit order of the values is reversed as part of the operation.

When bits[19:16] of ID_AA64ISAR0_EL1 are set to 0b0001, the CRC instructions are implemented.

These instructions are optional in an ARMv8.0 implementation.

All implementations of ARMv8.1 architecture and later are required to implement the CRC32 instructions.
"""


@opcode
def CRC32(cpu_context, instruction):
    """CRC-32 sum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CRC32C(cpu_context, instruction):
    """CRC-32C sum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Bit operation
"""


@opcode
def CLS(cpu_context, instruction):
    """Count leading sign bits"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CLZ(cpu_context, instruction):
    """Count leading zero bits"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RBIT(cpu_context, instruction):
    """Reverse bit order"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV(cpu_context, instruction):
    """Reverse bytes in register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV16(cpu_context, instruction):
    """Reverse bytes in halfwords"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV32(cpu_context, instruction):
    """Reverses bytes in words"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV64(cpu_context, instruction):
    """Reverse bytes in register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Conditional select
The Conditional select instructions select between the first or second source register, depending on the current state
of the Condition flags. When the named condition is true, the first source register is selected and its value is copied
without modification to the destination register. When the condition is false the second source register is selected
and its value might be optionally inverted, negated, or incremented by one, before writing to the destination register.

Other useful conditional set and conditional unary operations are implemented as aliases of the four Conditional
select instructions.
"""


@opcode
def CSEL(cpu_context, instruction):
    """Conditional select"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSINC(cpu_context, instruction):
    """Conditional select increment"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSINV(cpu_context, instruction):
    """Conditional select inversion"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSNEG(cpu_context, instruction):
    """Conditional select negation"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSET(cpu_context, instruction):
    """Conditional set"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSETM(cpu_context, instruction):
    """Conditional set mask"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CINC(cpu_context, instruction):
    """Conditional increment"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CINV(cpu_context, instruction):
    """Conditional invert"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CNEG(cpu_context, instruction):
    """Conditional negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Conditional comparison
The Conditional comparison instructions provide a conditional select for the NZCV Condition flags, setting the
flags to the result of an arithmetic comparison of its two source register values if the named input condition is true,
or to an immediate value if the input condition is false. There are register and immediate forms. The immediate form
compares the source register to a small 5-bit unsigned value.
"""


@opcode
def CCMN(cpu_context, instruction):
    """
    Conditional compare negative (register)
    Conditional compare negative (immediate)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CCMP(cpu_context, instruction):
    """
    Conditional compare (register)
    Conditional compare (immediate)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point move (register)
The Floating-point move (register) instructions copy a scalar floating-point value from one register to another
register without performing any conversion.

Some of the Floating-point move (register) instructions overlap with the functionality provided by the Advanced
SIMD instructions DUP, INS, and UMOV. However, ARM recommends using the FMOV instructions when operating on
scalar floating-point data to avoid the creation of scalar floating-point code that depends on the availability of the
Advanced SIMD instruction set.

Floating-point move (immediate)
The Floating-point move (immediate) instructions convert a small constant immediate floating-point value into a
half-precision, single-precision, or double-precision scalar floating-point value in a SIMD and floating-point
register.

The floating-point constant can be specified either in decimal notation, such as 12.0 or -1.2e1, or as a string
beginning with 0x followed by a hexadecimal representation of the IEEE 754 half-precision, single-precision, or
double-precision encoding. ARM recommends that a disassembler uses the decimal notation, provided that this
displays the value precisely.

Note
When ARMv8.2-FP16 is not implemented, the only half-precision instructions that are supported are floating-point
conversions between half-precision, single-precision, and double-precision.

The floating-point value must be expressible as (± n/16 × 2r), where n is an integer in the range 16 = n = 31 and r is
an integer in the range of -3 = r = 4, that is a normalized binary floating-point encoding with one sign bit, four bits
of fraction, and a 3-bit exponent.
"""


@opcode
def FMOV(cpu_context, instruction):
    """
    Floating-point move register without conversion
    Floating-point move to or from general-purpose register without conversion
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Convert floating-point precision
These instructions convert a floating-point scalar with one precision to a floating-point scalar with a different
precision, using the current rounding mode as specified by FPCR.RMode.
"""


@opcode
def FCVT(cpu_context, instruction):
    """Floating-point convert precision (scalar)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Convert between floating-point and integer or fixed-point
These instructions convert a floating-point scalar in a SIMD and floating-point register to or from a signed or
unsigned integer or fixed-point value in a general-purpose register. For a fixed-point value, a final immediate
operand indicates that the general-purpose register holds a fixed-point number and fbits indicates the number of
bits after the binary point. fbits is in the range 1- 32 inclusive for a 32-bit general-purpose register name, and 1-64
inclusive for a 64-bit general-purpose register name.

These instructions can cause the following floating-point exceptions:

Invalid Operation
    Occurs if the floating-point input is a NaN, infinity, or a numerical value that cannot be represented
    in the destination register. An out-of-range integer or fixed-point result is saturated to the size of the
    destination register.

Inexact Occurs if the numeric result that differs from the input value.

Input Denormal
    As Flush-to-zero on page A1-52 describes, when Flush-to-zero mode is enabled, occurs when zero
    replaces a double-precision or single-precision denormal input.

Note
When ARMv8.2-FP16 is implemented, a half-precision denormal input that is flushed to zero does
not generate an Input Denormal exception.
"""


@opcode
def FCVTAS(cpu_context, instruction):
    """Floating-point scalar convert to signed integer, rounding to nearest with ties to away (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTAU(cpu_context, instruction):
    """Floating-point scalar convert to unsigned integer, rounding to nearest with ties to away (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTMS(cpu_context, instruction):
    """Floating-point scalar convert to signed integer, rounding toward minus infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTMU(cpu_context, instruction):
    """Floating-point scalar convert to unsigned integer, rounding toward minus infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTNS(cpu_context, instruction):
    """Floating-point scalar convert to signed integer, rounding to nearest with ties to even (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTNU(cpu_context, instruction):
    """Floating-point scalar convert to unsigned integer, rounding to nearest with ties to even (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTPS(cpu_context, instruction):
    """Floating-point scalar convert to signed integer, rounding toward positive infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTPU(cpu_context, instruction):
    """Floating-point scalar convert to unsigned integer, rounding toward positive infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTZS(cpu_context, instruction):
    """
    Floating-point scalar convert to signed integer, rounding toward zero (scalar form)
    Floating-point scalar convert to signed fixed-point, rounding toward zero (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTZU(cpu_context, instruction):
    """
    Floating-point scalar convert to unsigned integer, rounding toward zero (scalar form)
    Floating-point scalar convert to unsigned fixed-point, rounding toward zero (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FJCVTZS(cpu_context, instruction):
    """Floating-point Javascript convert to signed fixed-point, rounding toward zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SCVTF(cpu_context, instruction):
    """
    Signed integer scalar convert to floating-point, using the current rounding mode (scalar form)
    Signed integer fixed-point convert to floating-point, using the current rounding mode (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UCVTF(cpu_context, instruction):
    """
    Unsigned integer scalar convert to floating-point, using the current rounding mode (scalar form)
    Unsigned integer fixed-point convert to floating-point, using the current rounding mode (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point round to integer
The Floating-point round to integer instructions round a floating-point value to an integer floating-point value of
the same size.

For these instructions:
• A zero input gives a zero result with the same sign.
• An infinite input gives an infinite result with the same sign.
• A NaN is propagated as in normal floating-point arithmetic.

These instructions can cause the following floating-point exceptions:

Invalid Operation
    Occurs in response to a floating-point input of a signaling NaN.

Inexact, FRINTX instruction only
    Occurs if the result is numeric and does not have the same numerical value as the input.

Input Denormal
    As Flush-to-zero on page A1-52 describes, when Flush-to-zero mode is enabled, occurs when zero
    replaces a double-precision or single-precision denormal input.

Note
When ARMv8.2-FP16 is implemented, a half-precision denormal input that is flushed to zero does
not generate an Input Denormal exception.
"""


@opcode
def FRINTA(cpu_context, instruction):
    """Floating-point round to integer, to nearest with ties to away"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTI(cpu_context, instruction):
    """Floating-point round to integer, using current rounding mode"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTM(cpu_context, instruction):
    """Floating-point round to integer, toward minus infinity"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTN(cpu_context, instruction):
    """Floating-point round to integer, to nearest with ties to even"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTP(cpu_context, instruction):
    """Floating-point round to integer, toward positive infinity"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTX(cpu_context, instruction):
    """Floating-point round to integer exact, using current rounding mode"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTZ(cpu_context, instruction):
    """Floating-point round to integer, toward zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point multiply-add
"""


@opcode
def FMADD(cpu_context, instruction):
    """Floating-point scalar fused multiply-add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMSUB(cpu_context, instruction):
    """Floating-point scalar fused multiply-subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNMADD(cpu_context, instruction):
    """Floating-point scalar negated fused multiply-add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNMSUB(cpu_context, instruction):
    """Floating-point scalar negated fused multiply-subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point arithmetic (one source)
"""


@opcode
def FABS(cpu_context, instruction):
    """Floating-point scalar absolute value"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNEG(cpu_context, instruction):
    """Floating-point scalar negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FSQRT(cpu_context, instruction):
    """Floating-point scalar square root"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point arithmetic (two sources)
"""


@opcode
def FADD(cpu_context, instruction):
    """Floating-point scalar add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FDIV(cpu_context, instruction):
    """Floating-point scalar divide"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMUL(cpu_context, instruction):
    """Floating-point scalar multiply"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNMUL(cpu_context, instruction):
    """Floating-point scalar multiply-negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FSUB(cpu_context, instruction):
    """Floating-point scalar subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point minimum and maximum
The min(x,y) and max(x,y) operations return a quiet NaN when either x or y is NaN.

As described in Flush-to-zero on page A1-52, in flush-to-zero mode, denormal operands are flushed to zero before
comparison, and if the result of the comparison is the flushed value, then a zero value is returned. Where both x and
y are zero, or denormal values flushed to zero, with different signs, then +0.0 is returned by max() and -0.0 by min().

The minNum(x,y) and maxNum(x,y) operations follow the IEEE 754-2008 standard and return the numerical operand
when one operand is numerical and the other a quiet NaN. Apart from this additional handling of a single quiet NaN
the result is then identical to min(x,y) and max(x,y).
"""


@opcode
def FMAX(cpu_context, instruction):
    """Floating-point scalar maximum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXNM(cpu_context, instruction):
    """Floating-point scalar maximum number"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMIN(cpu_context, instruction):
    """Floating-point scalar minimum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINNM(cpu_context, instruction):
    """Floating-point scalar minimum number"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point comparison
These instructions set the NZCV Condition flags in PSTATE, based on the result of a comparison of two operands.
If the floating-point comparisons are unordered, where one or both operands are a form of NaN, the C and V bits
are set to 1 and the N and Z bits are cleared to 0.

Note
The NZCV flags in the FPSR are associated with AArch32 state. The A64 floating-point comparison instructions
do not change the Condition flags in the FPSR.

For the conditional Floating-point comparison instructions, if the condition is TRUE, the flags are updated to the
result of the comparison, otherwise the flags are updated to the immediate value that is defined in the instruction
encoding.

The quiet compare instructions generate an Invalid Operation floating-point exception if either of the source
operands is a signaling NaN. The signaling compare instructions generate an Invalid Operation floating-point
exception if either of the source operands is any type of NaN.
"""


@opcode
def FCMP(cpu_context, instruction):
    """Floating-point quiet compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMPE(cpu_context, instruction):
    """Floating-point signaling compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCCMP(cpu_context, instruction):
    """Floating-point conditional quiet compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCCMPE(cpu_context, instruction):
    """Floating-point conditional signaling compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
Floating-point conditional select
"""


@opcode
def FCSEL(cpu_context, instruction):
    """Floating-point scalar conditional select"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD move
The functionality of some data movement instructions overlaps with that provided by the scalar floating-point FMOV
instructions described in Floating-point move (register) on page C3-207.
"""


@opcode
def DUP(cpu_context, instruction):
    """
    Duplicate vector element to vector or scalar
    Duplicate general-purpose register to vector
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def INSa(cpu_context, instruction):
    """
    Insert vector element from another vector element
    Insert vector element from general-purpose register INS (general) on page C7-16
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMOV(cpu_context, instruction):
    """Unsigned move vector element to general-purpose register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMOV(cpu_context, instruction):
    """Signed move vector element to general-purpose register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD arithmetic
"""


@opcode
def BIF(cpu_context, instruction):
    """Bitwise insert if false (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BIT(cpu_context, instruction):
    """Bitwise insert if true (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BSL(cpu_context, instruction):
    """Bitwise select (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FABD(cpu_context, instruction):
    """Floating-point absolute difference (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLA(cpu_context, instruction):
    """Floating-point fused multiply-add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLAL(cpu_context, instruction):
    """FMLAL2 Floating-point fused multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLS(cpu_context, instruction):
    """Floating-point fused multiply-subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLSL(cpu_context, instruction):
    """FMLSL2 Floating-point fused multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMULX(cpu_context, instruction):
    """Floating-point multiply extended (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRECPS(cpu_context, instruction):
    """Floating-point reciprocal step (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRSQRTS(cpu_context, instruction):
    """Floating-point reciprocal square root step (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MLA(cpu_context, instruction):
    """Multiply-add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MLS(cpu_context, instruction):
    """Multiply-subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def PMUL(cpu_context, instruction):
    """Polynomial multiply (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABA(cpu_context, instruction):
    """Signed absolute difference and accumulate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABD(cpu_context, instruction):
    """Signed absolute difference (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHADD(cpu_context, instruction):
    """Signed halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHSUB(cpu_context, instruction):
    """Signed halving subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMAX(cpu_context, instruction):
    """Signed maximum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMIN(cpu_context, instruction):
    """Signed minimum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQADD(cpu_context, instruction):
    """Signed saturating add (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMULH(cpu_context, instruction):
    """Signed saturating doubling multiply returning high half (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHL(cpu_context, instruction):
    """Signed saturating rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRDMLAH(cpu_context, instruction):
    """Signed saturating rounding doubling multiply accumulate returning high half"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRDMLSH(cpu_context, instruction):
    """Signed saturating rounding doubling multiply subtract returning high half"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRDMULH(cpu_context, instruction):
    """Signed saturating rounding doubling multiply returning high half (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHL(cpu_context, instruction):
    """Signed saturating shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSUB(cpu_context, instruction):
    """Signed saturating subtract (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRHADD(cpu_context, instruction):
    """Signed rounding halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRSHL(cpu_context, instruction):
    """Signed rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHL(cpu_context, instruction):
    """Signed shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABA(cpu_context, instruction):
    """Unsigned absolute difference and accumulate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABD(cpu_context, instruction):
    """Unsigned absolute difference (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UHADD(cpu_context, instruction):
    """Unsigned halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UHSUB(cpu_context, instruction):
    """Unsigned halving subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMAX(cpu_context, instruction):
    """Unsigned maximum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMIN(cpu_context, instruction):
    """Unsigned minimum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQADD(cpu_context, instruction):
    """Unsigned saturating add (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQRSHL(cpu_context, instruction):
    """Unsigned saturating rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSHL(cpu_context, instruction):
    """Unsigned saturating shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSUB(cpu_context, instruction):
    """Unsigned saturating subtract (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URHADD(cpu_context, instruction):
    """Unsigned rounding halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSHL(cpu_context, instruction):
    """Unsigned rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHL(cpu_context, instruction):
    """Unsigned shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD compare
The SIMD compare instructions compare vector or scalar elements according to the specified condition and set the
destination vector element to all ones if the condition holds, or to zero if the condition does not hold.

Note
Some of the comparisons, such as LS, LE, LO, and LT, can be made by reversing the operands and using the
opposite comparison, HS, GE, HI, or GT.
"""


@opcode
def CMEQ(cpu_context, instruction):
    """
    Compare bitwise equal (vector and scalar form)
    Compare bitwise equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMHS(cpu_context, instruction):
    """Compare unsigned higher or same (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMGE(cpu_context, instruction):
    """
    Compare signed greater than or equal (vector and scalar form)
    Compare signed greater than or equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMHI(cpu_context, instruction):
    """Compare unsigned higher (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMGT(cpu_context, instruction):
    """
    Compare signed greater than (vector and scalar form)
    Compare signed greater than zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMLE(cpu_context, instruction):
    """Compare signed less than or equal to zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMLT(cpu_context, instruction):
    """Compare signed less than zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMTST(cpu_context, instruction):
    """Compare bitwise test bits nonzero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMEQ(cpu_context, instruction):
    """
    Floating-point compare equal (vector and scalar form)
    Floating-point compare equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMGE(cpu_context, instruction):
    """
    Floating-point compare greater than or equal (vector and scalar form)
    Floating-point compare greater than or equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMGT(cpu_context, instruction):
    """
    Floating-point compare greater than (vector and scalar form)
    Floating-point compare greater than zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMLE(cpu_context, instruction):
    """Floating-point compare less than or equal to zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMLT(cpu_context, instruction):
    """Floating-point compare less than zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FACGE(cpu_context, instruction):
    """Floating-point absolute compare greater than or equal (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FACGT(cpu_context, instruction):
    """Floating-point absolute compare greater than (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD widening and narrowing arithmetic  pg 217
"""


@opcode
def ADDHN(cpu_context, instruction):
    """Add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ADDHN2(cpu_context, instruction):
    """Add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def PMULL(cpu_context, instruction):
    """Polynomial multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def PMULL2(cpu_context, instruction):
    """Polynomial multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RADDHN(cpu_context, instruction):
    """Rounding add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RADDHN2(cpu_context, instruction):
    """Rounding add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RSUBHN(cpu_context, instruction):
    """Rounding subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RSUBHN2(cpu_context, instruction):
    """Rounding subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABAL(cpu_context, instruction):
    """Signed absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABAL2(cpu_context, instruction):
    """Signed absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABDL(cpu_context, instruction):
    """Signed absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABDL2(cpu_context, instruction):
    """Signed absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDL(cpu_context, instruction):
    """Signed add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDL2(cpu_context, instruction):
    """Signed add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDW(cpu_context, instruction):
    """Signed add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDW2(cpu_context, instruction):
    """Signed add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLAL(cpu_context, instruction):
    """Signed multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLAL2(cpu_context, instruction):
    """Signed multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLSL(cpu_context, instruction):
    """Signed multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLSL2(cpu_context, instruction):
    """Signed multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMULL2(cpu_context, instruction):
    """Signed multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLAL(cpu_context, instruction):
    """Signed saturating doubling multiply-add long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLAL2(cpu_context, instruction):
    """Signed saturating doubling multiply-add long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLSL(cpu_context, instruction):
    """Signed saturating doubling multiply-subtract long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLSL2(cpu_context, instruction):
    """Signed saturating doubling multiply-subtract long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMULL(cpu_context, instruction):
    """Signed saturating doubling multiply long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMULL2(cpu_context, instruction):
    """Signed saturating doubling multiply long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBL(cpu_context, instruction):
    """Signed subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBL2(cpu_context, instruction):
    """Signed subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBW(cpu_context, instruction):
    """Signed subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBW2(cpu_context, instruction):
    """Signed subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SUBHN(cpu_context, instruction):
    """Subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SUBHN2(cpu_context, instruction):
    """Subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABAL(cpu_context, instruction):
    """Unsigned absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABAL2(cpu_context, instruction):
    """Unsigned absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABDL(cpu_context, instruction):
    """Unsigned absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABDL2(cpu_context, instruction):
    """Unsigned absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDL(cpu_context, instruction):
    """Unsigned add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDL2(cpu_context, instruction):
    """Unsigned add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDW(cpu_context, instruction):
    """Unsigned add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDW2(cpu_context, instruction):
    """Unsigned add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLAL(cpu_context, instruction):
    """Unsigned multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLAL2(cpu_context, instruction):
    """Unsigned multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLSL(cpu_context, instruction):
    """Unsigned multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLSL2(cpu_context, instruction):
    """Unsigned multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMULL2(cpu_context, instruction):
    """Unsigned multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBL(cpu_context, instruction):
    """Unsigned subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBL2(cpu_context, instruction):
    """Unsigned subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBW(cpu_context, instruction):
    """Unsigned subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBW2(cpu_context, instruction):
    """Unsigned subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD unary arithmetic
"""


@opcode
def ABS(cpu_context, instruction):
    """Absolute value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CNT(cpu_context, instruction):
    """Population count per byte (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTL(cpu_context, instruction):
    """Floating-point convert to higher precision long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTL2(cpu_context, instruction):
    """Floating-point convert to higher precision long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTN(cpu_context, instruction):
    """Floating-point convert to lower precision narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTN2(cpu_context, instruction):
    """Floating-point convert to lower precision narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTXN(cpu_context, instruction):
    """Floating-point convert to lower precision narrow, rounding to odd (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTXN2(cpu_context, instruction):
    """Floating-point convert to lower precision narrow, rounding to odd (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRECPE(cpu_context, instruction):
    """Floating-point reciprocal estimate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRECPX(cpu_context, instruction):
    """Floating-point reciprocal square root (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRSQRTE(cpu_context, instruction):
    """Floating-point reciprocal square root estimate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def NOT(cpu_context, instruction):
    """Bitwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADALP(cpu_context, instruction):
    """Signed add and accumulate long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDLP(cpu_context, instruction):
    """Signed add long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQABS(cpu_context, instruction):
    """Signed saturating absolute value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQNEG(cpu_context, instruction):
    """Signed saturating negate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTN(cpu_context, instruction):
    """Signed saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTN2(cpu_context, instruction):
    """Signed saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTUN(cpu_context, instruction):
    """Signed saturating extract unsigned narrow (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTUN2(cpu_context, instruction):
    """Signed saturating extract unsigned narrow (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SUQADD(cpu_context, instruction):
    """Signed saturating accumulate of unsigned value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SXTL(cpu_context, instruction):
    """Signed extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SXTL2(cpu_context, instruction):
    """Signed extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADALP(cpu_context, instruction):
    """Unsigned add and accumulate long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDLP(cpu_context, instruction):
    """Unsigned add long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQXTN(cpu_context, instruction):
    """Unsigned saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQXTN2(cpu_context, instruction):
    """Unsigned saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URECPE(cpu_context, instruction):
    """Unsigned reciprocal estimate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSQRTE(cpu_context, instruction):
    """Unsigned reciprocal square root estimate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USQADD(cpu_context, instruction):
    """Unsigned saturating accumulate of signed value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UXTL(cpu_context, instruction):
    """Unsigned extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UXTL2(cpu_context, instruction):
    """Unsigned extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def XTN(cpu_context, instruction):
    """Extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def XTN2(cpu_context, instruction):
    """Extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD by element arithmetic
"""


@opcode
def FMLAL2(cpu_context, instruction):
    """Floating-point fused multiply-add long (vector form) FMLAL,"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLSL2(cpu_context, instruction):
    """Floating-point fused multiply-subtract long (vector form) FMLSL,"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD permute
"""


@opcode
def EXT(cpu_context, instruction):
    """Extract vector from a pair of vectors"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def TRN1(cpu_context, instruction):
    """Transpose vectors (primary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def TRN2(cpu_context, instruction):
    """Transpose vectors (secondary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UZP1(cpu_context, instruction):
    """Unzip vectors (primary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UZP2(cpu_context, instruction):
    """Unzip vectors (secondary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ZIP1(cpu_context, instruction):
    """Zip vectors (primary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ZIP2(cpu_context, instruction):
    """Zip vectors (secondary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD immediate
"""


@opcode
def MOVI(cpu_context, instruction):
    """Move immediate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MVNI(cpu_context, instruction):
    """Move inverted immediate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD shift (immediate)
"""


@opcode
def RSHRN(cpu_context, instruction):
    """Rounding shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RSHRN2(cpu_context, instruction):
    """Rounding shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHL(cpu_context, instruction):
    """Shift left immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHLL(cpu_context, instruction):
    """Shift left long (by element size) (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHLL2(cpu_context, instruction):
    """Shift left long (by element size) (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHRN(cpu_context, instruction):
    """Shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHRN2(cpu_context, instruction):
    """Shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SLI(cpu_context, instruction):
    """Shift left and insert immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRN(cpu_context, instruction):
    """Signed saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRN2(cpu_context, instruction):
    """Signed saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRUN(cpu_context, instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRUN2(cpu_context, instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHLU(cpu_context, instruction):
    """Signed saturating shift left unsigned immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRN(cpu_context, instruction):
    """Signed saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRN2(cpu_context, instruction):
    """Signed saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRUN(cpu_context, instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRUN2(cpu_context, instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRI(cpu_context, instruction):
    """Shift right and insert immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRSHR(cpu_context, instruction):
    """Signed rounding shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRSRA(cpu_context, instruction):
    """Signed rounding shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHLL(cpu_context, instruction):
    """Signed shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHLL2(cpu_context, instruction):
    """Signed shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHR(cpu_context, instruction):
    """Signed shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSRA(cpu_context, instruction):
    """Signed integer shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQRSHRN(cpu_context, instruction):
    """Unsigned saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQRSHRN2(cpu_context, instruction):
    """Unsigned saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSHRN(cpu_context, instruction):
    """Unsigned saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSHRN2(cpu_context, instruction):
    """Unsigned saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSHR(cpu_context, instruction):
    """Unsigned rounding shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSRA(cpu_context, instruction):
    """Unsigned integer rounding shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHLL(cpu_context, instruction):
    """Unsigned shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHLL2(cpu_context, instruction):
    """Unsigned shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHR(cpu_context, instruction):
    """Unsigned shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USRA(cpu_context, instruction):
    """Unsigned shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD reduce (across vector lanes)
The SIMD reduce (across vector lanes) instructions perform arithmetic operations horizontally, that is across all
lanes of the input vector. They deliver a single scalar result.
"""


@opcode
def ADDV(cpu_context, instruction):
    """Add (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXNMV(cpu_context, instruction):
    """Floating-point maximum number (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXV(cpu_context, instruction):
    """Floating-point maximum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINNMV(cpu_context, instruction):
    """Floating-point minimum number (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINV(cpu_context, instruction):
    """Floating-point minimum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDLV(cpu_context, instruction):
    """Signed add long (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMAXV(cpu_context, instruction):
    """Signed maximum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMINV(cpu_context, instruction):
    """Signed minimum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDLV(cpu_context, instruction):
    """Unsigned add long (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMAXV(cpu_context, instruction):
    """Unsigned maximum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMINV(cpu_context, instruction):
    """Unsigned minimum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD pairwise arithmetic
The SIMD pairwise arithmetic instructions perform operations on pairs of adjacent elements and deliver a vector
result.
"""


@opcode
def ADDP(cpu_context, instruction):
    """Add pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FADDP(cpu_context, instruction):
    """Floating-point add pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXNMP(cpu_context, instruction):
    """Floating-point maximum number pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXP(cpu_context, instruction):
    """Floating-point maximum pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINNMP(cpu_context, instruction):
    """Floating-point minimum number pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINP(cpu_context, instruction):
    """Floating-point minimum pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMAXP(cpu_context, instruction):
    """Signed maximum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMINP(cpu_context, instruction):
    """Signed minimum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMAXP(cpu_context, instruction):
    """Unsigned maximum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMINP(cpu_context, instruction):
    """Unsigned minimum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD dot product
ARMv8.2-DotProd provides SIMD instructions that perform the dot product of the four 8-bit subelements of the
32-bit elements of one vector with the four 8-bit subelements of a second vector. It provides two forms of the
instructions, each with signed and unsigned versions:

Vector form The dot product is calculated for each element of the first vector with the corresponding element of
the second element.

Indexed form The dot product is calculated for each element of the first vector with the element of the second
vector that is indicated by the index argument to the instruction.

Note
That is, a single element from the second vector is used, and a the dot product is calculated between
each element of the first vector and this single element from the second vector.
"""


@opcode
def SDOT(cpu_context, instruction):
    """
    Signed dot product (vector form)
    Signed dot product (indexed form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UDOT(cpu_context, instruction):
    """
    Unsigned dot product (vector form)
    Unsigned dot product (indexed form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD table lookup
"""


@opcode
def TBL(cpu_context, instruction):
    """Table vector lookup"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def TBX(cpu_context, instruction):
    """Table vector lookup extension"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


"""
SIMD complex number arithmetic
ARMv8.3-CompNum provides SIMD instructions that perform arithmetic on complex numbers held in element
pairs in vector registers, where the less significant element of the pair contains the real component and the more
significant element contains the imaginary component.

These instructions provide double-precision and single-precision versions. If ARMv8.2-FP16 is implemented they
also provide half-precision versions, otherwise the half-precision encodings are UNDEFINED.
"""


@opcode
def FCADD(cpu_context, instruction):
    """Floating-point complex add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMLA(cpu_context, instruction):
    """Floating-point complex multiply accumulate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


# Global helper functions


# TODO: Move to Instruction.
def get_max_operand_size(operands):
    """
    Given the list of named tuples containing the operand value and bit width, determine the largest bit width.

    :param operands: list of Operand objects

    :return: largest operand width
    """
    return max(operand.width for operand in operands)
