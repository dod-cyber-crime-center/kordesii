
import logging

import idc
import idaapi
import idautils

from .. import utils
from ..cpu_context import Operand
from ..registry import registrar
from .. import functions

import logging

logger = logging.getLogger(__name__)


# Dictionary containing opcode names -> function
OPCODES = {}
opcode = registrar(OPCODES, name='opcode')


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
B.cond          Branch conditionally                1MB 
CBNZ            Compare and branch if nonzero       1MB
CBZ             Compare and branch if zero          1MB 
TBNZ            Test bit and branch if nonzero      32KB
TBZ             Test bit and branch if zero         32KB
"""

# TODO: How does IDA report the mnemonic for B.cond



@opcode
def CBNZ(cpu_context, ip, mnem, opvalues):
    """Compare and branch if nonzero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    

@opcode
def CBZ(cpu_context, ip, mnem, opvalues):
    """Compare and branch if zero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def TBNZ(cpu_context, ip, mnem, opvalues):
    """Test bit and branch if nonzero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def TBZ(cpu_context, ip, mnem, opvalues):
    """Test bit and branch if zero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Unconditional branch (immediate/register)

Unconditional branch (immediate) instructions change the flow of execution unconditionally by adding an immediate
offset with a range of 128MB to the value of the program counter that fetched the instruction.  The BL instruction
also writes the address of the sequentially following instruction to general-purpose register X30.

Unconditional branch (register) instructions change the flow of execution unconditionally by setting the program 
counter to the value in a general-purpose register.  The BLR instruction also writes the address of the sequentially
following instruction to general-purpose register X30.
"""

@opcode
def B(cpu_context, ip, mnem, opvalues):
    """Branch unconditionally"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode 
def BL(cpu_context, ip, mnem, opvalues):
    """Branch with link"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def BLR(cpu_context, ip, mnem, opvalues):
    """Branch with link to register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def BR(cpu_context, ip, mnem, opvalues):
    """Branch to register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    

"""
System register instructions

For detailed information about the System register instructions, see Chapter C5 The A64 System Instruction Class.
Table C3-7 shows the System register instructions.

Mnemonic        Instruction                                             See
MRS             Move System register to general-purpose register        MRS on page C6-1024
MSR             Move general-purpose register to System register        MSR (register) on page C6-1027
                Move immediate to PE state field                        MSR (immediate) on page C6-1025
"""

@opcode
def MRS(cpu_context, ip, mnem, opvalues):
    """Move System register to general-purpose register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def MSR(cpu_context, ip, mnem, opvalues):
    """
    Move general-purpose register to System register
    Move immediate to PE state field
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Load/Store register
The Load/Store register instructions support the following addressing modes:
* Base plus a scaled 12-bit unsigned immediate offset or base plus an unscaled 9-bit signed immediate offset.
* Base plus a 64-bit register offset, optionally scaled.
* Base plus a 32-bit extended register offset, optionally scaled.
* Pre-indexed by an unscaled 9-bit signed immediate offset.
* Post-indexed by an unscaled 9-bit signed immediate offset.
* PC-relative literal for loads of 32 bits or more.

If a Load instruction specifies writeback and the register being loaded is also the base register, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs the load using the specified addressing mode and the base register becomes
  UNKNOWN. In addition, if an exception occurs during the execution of such an instruction, the base address
  might be corrupted so that the instruction cannot be repeated.

If a Store instruction performs a writeback and the register that is stored is also the base register, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs the store to the designated register using the specified addressing mode, but the
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
* Base plus a scaled 12-bit unsigned immediate offset or base plus unscaled 9-bit signed immediate offset.
* Base plus 64-bit register offset, optionally scaled.
* Base plus 32-bit extended register offset, optionally scaled.
* Pre-indexed by an unscaled 9-bit signed immediate offset.
* Post-indexed by an unscaled 9-bit signed immediate offset.
* PC-relative literal for loads of 32 bits or more.

Note
The unscaled 9-bit signed immediate offset address mode requires its own instruction form

"""

@opcode
def LDR(cpu_context, ip, mnem, opvalues):
    """
    Load register (register offset)
    Load register (immediate offset)
    Load register (PC-relative literal)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDRB(cpu_context, ip, mnem, opvalues):
    """
    Load byte (register offset)
    Load byte (immediate offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    

@opcode
def LDRSB(cpu_context, ip, mnem, opvalues):
    """
    Load signed byte (register offset)
    Load signed byte (immediate offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDRH(cpu_context, ip, mnem, opvalues):
    """
    Load halfword (register offset)
    Load halfword (immediate offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDRSH(cpu_context, ip, mnem, opvalues):
    """
    Load signed halfword (register offset)
    Load signed halfword (immediate offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
@opcode
def LDRSW(cpu_context, ip, mnem, opvalues):
    """
    Load signed word (register offset)
    Load signed word (immediate offset)
    Load signed word (PC-relative offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
@opcode
def STR(cpu_context, ip, mnem, opvalues):
    """
    Store register (register offset)
    Store register (immediate offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def STRB(cpu_context, ip, mnem, opvalues):
    """
    Store byte (register offset)
    Store byte (immediate offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
@opcode
def STRH(cpu_context, ip, mnem, opvalues):
    """
    Store halfword (register offset)
    Store halfword (immediate offset)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


"""
Load/Store register (unscaled offset)
The Load/Store register instructions with an unscaled offset support only one addressing mode:
* Base plus an unscaled 9-bit signed immediate offset.

The Load/Store register (unscaled offset) instructions are required to disambiguate this instruction class from the
Load/Store register instruction forms that support an addressing mode of base plus a scaled, unsigned 12-bit
immediate offset, because that can represent some offset values in the same range.

The ambiguous immediate offsets are byte offsets that are both:
* In the range 0-255, inclusive.
* Naturally aligned to the access size.

Other byte offsets in the range -256 to 255 inclusive are unambiguous. An assembler program translating a
Load/Store instruction, for example LDR, is required to encode an unambiguous offset using the unscaled 9-bit offset
form, and to encode an ambiguous offset using the scaled 12-bit offset form. A programmer might force the
generation of the unscaled 9-bit form by using one of the mnemonics in Table C3-16. ARM recommends that a
disassembler outputs all unscaled 9-bit offset forms using one of these mnemonics, but unambiguous offsets can be
output using a Load/Store single register mnemonic, for example, LDR.

Load/Store scalar SIMD and floating-point register (unscaled offset)
The Load /Store scalar SIMD and floating-point register instructions support only one addressing mode:
* Base plus an unscaled 9-bit signed immediate offset.

The Load/Store scalar SIMD and floating-point register (unscaled offset) instructions are required to disambiguate
this instruction class from the Load/Store single SIMD and floating-point instruction forms that support an
addressing mode of base plus a scaled, unsigned 12-bit immediate offset. This is similar to the Load/Store register
(unscaled offset) instructions, that disambiguate this instruction class from the Load/Store register instruction
"""

@opcode
def LDUR(cpu_context, ip, mnem, opvalues):
    """Load register (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDURB(cpu_context, ip, mnem, opvalues):
    """Load byte (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDURSB(cpu_context, ip, mnem, opvalues):
    """Load signed byte (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDURH(cpu_context, ip, mnem, opvalues):
    """Load halfword (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
@opcode
def LDURSH(cpu_context, ip, mnem, opvalues):
    """Load signed halfword (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDURSW(cpu_context, ip, mnem, opvalues):
    """Load signed word (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def STUR(cpu_context, ip, mnem, opvalues):
    """Store register (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def STURB(cpu_context, ip, mnem, opvalues):
    """Store byte (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def STURH(cpu_context, ip, mnem, opvalues):
    """Store halfword (unscaled offset)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Load/Store Pair
The Load/Store Pair instructions support the following addressing modes:
* Base plus a scaled 7-bit signed immediate offset.
* Pre-indexed by a scaled 7-bit signed immediate offset.
* Post-indexed by a scaled 7-bit signed immediate offset.

If a Load Pair instruction specifies the same register for the two registers that are being loaded, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs all the loads using the specified addressing mode and the register that is loaded takes
  an UNKNOWN value.
  
If a Load Pair instruction specifies writeback and one of the registers being loaded is also the base register, then
behavior is CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs all of the loads using the specified addressing mode, and the base register becomes
  UNKNOWN. In addition, if an exception occurs during the instruction, the base address might be corrupted so
  that the instruction cannot be repeated.
  
If a Store Pair instruction performs a writeback and one of the registers being stored is also the base register, then
behavior is CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs all the stores of the registers indicated by the specified addressing mode, but the
  value stored for the base register is UNKNOWN.
  
Load/Store SIMD and Floating-point register pair
The Load/Store SIMD and floating-point register pair instructions support the following addressing modes:
* Base plus a scaled 7-bit signed immediate offset.
* Pre-indexed by a scaled 7-bit signed immediate offset.
* Post-indexed by a scaled 7-bit signed immediate offset.

If a Load pair instruction specifies the same register for the two registers that are being loaded, then behavior is
CONSTRAINED UNPREDICTABLE and one of the following behaviors must occur:
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs all of the loads using the specified addressing mode and the register being loaded
  takes an UNKNOWN value.
"""

@opcode
def LDP(cpu_context, ip, mnem, opvalues):
    """Load Pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDPSW(cpu_context, ip, mnem, opvalues):
    """Load Pair signed words"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def STP(cpu_context, ip, mnem, opvalues):
    """Store Pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Load/Store unprivileged
The Load/Store unprivileged instructions support only one addressing mode:
* Base plus an unscaled 9-bit signed immediate offset.

The accesses permissions that apply to accesses made at EL0 apply to the memory accesses made by a Load/Store
unprivileged instruction that is executed either:
* At EL1 when the Effective value of PSTATE.UAO is 0.
* At EL2 when both the Effective value of HCR_EL2.{E2H, TGE} is {1, 1} and the Effective value of
  PSTATE.UAO is 0.
  
Otherwise, memory accesses made by a Load/Store unprivileged instruction are subject to the access permissions
that apply to the Exception level at which the instruction is executed. These are the permissions that apply to the
corresponding Load/Store register instruction, see Load/Store register on page C3-177.

Note
This means that when the value of PSTATE.UAO is 1 the access permissions for a Load/Store unprivileged
instruction are always the same as those for the corresponding Load/Store register instruction.
"""

@opcode
def LDTR(cpu_context, ip, mnem, opvalues):
    """Load unprivileged register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
@opcode
def LDTRB(cpu_context, ip, mnem, opvalues):
    """Load unpriviledged byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
@opcode
def LDTRSB(cpu_context, ip, mnem, opvalues):
    """Load unprivileged signed byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDTRH(cpu_context, ip, mnem, opvalues):
    """Load unprivileged halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDTRSH(cpu_context, ip, mnem, opvalues):
    """Load unpriviledged signed halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDTRSW(cpu_context, ip, mnem, opvalues):
    """Load unprivileged signed word"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def STTR(cpu_context, ip, mnem, opvalues):
    """Store unprivileged register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STTRB(cpu_context, ip, mnem, opvalues):
    """Store unprivileged byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STTRH(cpu_context, ip, mnem, opvalues):
    """Store unprivileged halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


"""
Load-Exclusive/Store-Exclusive
The Load-Exclusive/Store-Exclusive instructions support only one addressing mode:
* Base register with no offset.

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
def LDXR(cpu_context, ip, mnem, opvalues):
    """Load Exclusive register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDXRB(cpu_context, ip, mnem, opvalues):
    """Load Exclusive byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDXRH(cpu_context, ip, mnem, opvalues):
    """Load Exclusive halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDXP(cpu_context, ip, mnem, opvalues):
    """Load Exclusive pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STXR(cpu_context, ip, mnem, opvalues):
    """Store Exclusive register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STXRB(cpu_context, ip, mnem, opvalues):
    """Store Exclusive byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STXRH(cpu_context, ip, mnem, opvalues):
    """Store Exclusive halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STXP(cpu_context, ip, mnem, opvalues):
    """Store Exclusive pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
    
"""
Load-Acquire/Store-Release
The Load-Acquire, Load-AcquirePC, and Store-Release instructions support only one addressing mode:
* Base register with no offset.

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
def LDAPR(cpu_context, ip, mnem, opvalues):
    """Load-Acquire RCpc Register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPRB(cpu_context, ip, mnem, opvalues):
    """Load-Acquire RCpc Register Byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPRH(cpu_context, ip, mnem, opvalues):
    """Load-Acquire RCpc Register Halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPUR(cpu_context, ip, mnem, opvalues):
    """Load-Acquire RCpc Register (unscaled)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPURB(cpu_context, ip, mnem, opvalues):
    """Load-Acquire RCpc Register Byte (unscaled)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPURH(cpu_context, ip, mnem, opvalues):
    """Load-Acquire RCpc Register Halfword (unscaled)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPURSB(cpu_context, ip, mnem, opvalues):
    """
    Load-Acquire RCpc Register Signed Byte (unscaled) 32-bit
    Load-Acquire RCpc Register Signed Byte (unscaled) 64-bit
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPURSH(cpu_context, ip, mnem, opvalues):
    """
    Load-Acquire RCpc Register Signed Halfword (unscaled) 32-bit
    Load-Acquire RCpc Register Signed Halfword (unscaled) 64-bit
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAPURSW(cpu_context, ip, mnem, opvalues):
    """Load-Acquire RCpc Register Signed Word (unscaled)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAR(cpu_context, ip, mnem, opvalues):
    """Load-Acquire Register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDARB(cpu_context, ip, mnem, opvalues):
    """Load-Acquire Byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDARH(cpu_context, ip, mnem, opvalues):
    """Load-Acquire Halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLR(cpu_context, ip, mnem, opvalues):
    """Store-Release Register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLRB(cpu_context, ip, mnem, opvalues):
    """Store-Release Byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLRH(cpu_context, ip, mnem, opvalues):
    """Store-Release Halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLUR(cpu_context, ip, mnem, opvalues):
    """Store-Release Register (unscaled)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLURB(cpu_context, ip, mnem, opvalues):
    """Store-Release Register Byte (unscaled)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLURH(cpu_context, ip, mnem, opvalues):
    """Store-Release Register Halfword (unscaled)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
@opcode
def LDAXR(cpu_context, ip, mnem, opvalues):
    """Load-Acquire Exclusive register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAXRB(cpu_context, ip, mnem, opvalues):
    """Load-Acquire Exclusive byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAXRH(cpu_context, ip, mnem, opvalues):
    """Load-Acquire Exclusive halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDAXP(cpu_context, ip, mnem, opvalues):
    """Load-Acquire Exclusive pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLXR(cpu_context, ip, mnem, opvalues):
    """Store-Release Exclusive register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLXRB(cpu_context, ip, mnem, opvalues):
    """Store-Release Exclusive byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLXRH(cpu_context, ip, mnem, opvalues):
    """Store-Release Exclusive halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLXP(cpu_context, ip, mnem, opvalues):
    """Store-Release Exclusive pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
The LoadLOAcquire/StoreLORelease instructions support only one addressing mode:
* Base register with no offset.

The LoadLOAcquire/StoreLORelease instructions can remove the requirement to use the explicit DMB memory
barrier instruction. For more information about the ordering of LoadLOAcquire/StoreLORelease, see
LoadLOAcquire, StoreLORelease on page B2-109.

The LoadLOAcquire/StoreLORelease instructions require natural alignment, and an unaligned address generates an
Alignment fault.
"""

@opcode
def LDLARB(cpu_context, ip, mnem, opvalues):
    """LoadLOAcquire byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDLARH(cpu_context, ip, mnem, opvalues):
    """LoadLOAcquire halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDLAR(cpu_context, ip, mnem, opvalues):
    """LoadLOAcquire register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLLRB(cpu_context, ip, mnem, opvalues):
    """StoreLORelease byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLLRH(cpu_context, ip, mnem, opvalues):
    """StoreLORelease halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STLLR(cpu_context, ip, mnem, opvalues):
    """StoreLORelease register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
The Load/Store SIMD and Floating-point Non-temporal pair instructions support only one addressing mode:
* Base plus a scaled 7-bit signed immediate offset.

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
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs all the loads using the specified addressing mode and the register that is loaded takes
  an UNKNOWN value.
  
Load/Store Non-temporal Pair
The Load/Store Non-temporal Pair instructions support only one addressing mode:
* Base plus a scaled 7-bit signed immediate offset.

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
* The instruction is treated as UNDEFINED.
* The instruction is treated as a NOP.
* The instruction performs all the loads using the specified addressing mode and the register that is loaded takes
  an UNKNOWN value.
"""

@opcode
def LDNP(cpu_context, ip, mnem, opvalues):
    """Load pair of scalar SIMD&FP registers"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STNP(cpu_context, ip, mnem, opvalues):
    """Store pair of scalar SIMD&FP registers"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    

"""
Load/Store Vector
The Vector Load/Store structure instructions support the following addressing modes:
* Base register only.
* Post-indexed by a 64-bit register.
* Post-indexed by an immediate, equal to the number of bytes transferred.

Load/Store vector instructions, like other Load/Store instructions, allow any address alignment, unless strict
alignment checking is enabled. If strict alignment checking is enabled, then alignment checking to the size of the
element is performed. However, unlike the Load/Store instructions that transfer general-purpose registers, the
Load/Store vector instructions do not guarantee atomicity, even when the address is naturally aligned to the size of
the element.
"""

@opcode
def LD1(cpu_context, ip, mnem, opvalues):
    """
    Load single 1-element structure to one lane of one register LD1 (single structure) on page C7-1637
    Load multiple 1-element structures to one register or to two, three, or four consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LD2(cpu_context, ip, mnem, opvalues):
    """
    Load single 2-element structure to one lane of two consecutive registers LD2 (single structure)
    Load multiple 2-element structures to two consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LD3(cpu_context, ip, mnem, opvalues):
    """
    Load single 3-element structure to one lane of three consecutive registers
    Load multiple 3-element structures to three consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LD4(cpu_context, ip, mnem, opvalues):
    """
    Load single 4-element structure to one lane of four consecutive registers
    Load multiple 4-element structures to four consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ST1(cpu_context, ip, mnem, opvalues):
    """
    Store single 1-element structure from one lane of one register
    Store multiple 1-element structures from one register, or from two, three, or four consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ST2(cpu_context, ip, mnem, opvalues):
    """
    Store single 2-element structure from one lane of two consecutive registers
    Store multiple 2-element structures from two consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ST3(cpu_context, ip, mnem, opvalues):
    """
    Store single 3-element structure from one lane of three consecutive registers
    Store multiple 3-element structures from three consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ST4(cpu_context, ip, mnem, opvalues):
    """
    Store single 4-element structure from one lane of four consecutive registers
    Store multiple 4-element structures from four consecutive registers
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LD1R(cpu_context, ip, mnem, opvalues):
    """Load single 1-element structure and replicate to all lanes of one register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LD2R(cpu_context, ip, mnem, opvalues):
    """Load single 2-element structure and replicate to all lanes of two registers"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LD3R(cpu_context, ip, mnem, opvalues):
    """Load single 3-element structure and replicate to all lanes of three registers"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LD4R(cpu_context, ip, mnem, opvalues):
    """Load single 4-element structure and replicate to all lanes of four registers"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Compare and Swap
The Compare and Swap instructions support only one addressing mode:
* Base register only.

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
def CAS(cpu_context, ip, mnem, opvalues):
    """Compare and swap"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CASB(cpu_context, ip, mnem, opvalues):
    """Compare and swap byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CASH(cpu_context, ip, mnem, opvalues):
    """Compare and swap halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CASP(cpu_context, ip, mnem, opvalues):
    """Compare and swap pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""Atomic memory operations
The atomic memory operation instructions support only one addressing mode:
* Base register only.

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
def LDADD(cpu_context, ip, mnem, opvalues):
    """Atomic add"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDADDB(cpu_context, ip, mnem, opvalues):
    """Atomic add on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDADDH(cpu_context, ip, mnem, opvalues):
    """Atomic add on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDCLR(cpu_context, ip, mnem, opvalues):
    """Atomic bit clear"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDCLRB(cpu_context, ip, mnem, opvalues):
    """Atomic bit clear on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDCLRH(cpu_context, ip, mnem, opvalues):
    """Atomic bit clear on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDEOR(cpu_context, ip, mnem, opvalues):
    """Atomic exclusive OR"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDEORB(cpu_context, ip, mnem, opvalues):
    """Atomic exclusive OR on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDEORH(cpu_context, ip, mnem, opvalues):
    """Atomic exclusive OR on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDSET(cpu_context, ip, mnem, opvalues):
    """Atomic bit set"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDSETB(cpu_context, ip, mnem, opvalues):
    """Atomic bit set on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDSETH(cpu_context, ip, mnem, opvalues):
    """Atomic bit set on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDMAX(cpu_context, ip, mnem, opvalues):
    """Atomic signed maximum"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDMAXB(cpu_context, ip, mnem, opvalues):
    """Atomic signed maximum on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDMAXH(cpu_context, ip, mnem, opvalues):
    """Atomic signed maximum on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDMIN(cpu_context, ip, mnem, opvalues):
    """Atomic signed minimum"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDMINB(cpu_context, ip, mnem, opvalues):
    """Atomic signed minimum on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDMINH(cpu_context, ip, mnem, opvalues):
    """Atomic signed minimum on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDUMAX(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned maximum"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDUMAXB(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned maximum on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDUMAXH(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned maximum on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDUMIN(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned minimum"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDUMINB(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned minimum on byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LDUMINH(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned minimum on halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STADD(cpu_context, ip, mnem, opvalues):
    """Atomic add, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STADDB(cpu_context, ip, mnem, opvalues):
    """Atomic add on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STADDH(cpu_context, ip, mnem, opvalues):
    """Atomic add on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STCLR(cpu_context, ip, mnem, opvalues):
    """Atomic bit clear, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STCLRB(cpu_context, ip, mnem, opvalues):
    """Atomic bit clear on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STCLRH(cpu_context, ip, mnem, opvalues):
    """Atomic bit clear on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STEOR(cpu_context, ip, mnem, opvalues):
    """Atomic exclusive OR, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STEORB(cpu_context, ip, mnem, opvalues):
    """Atomic exclusive OR on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STEORH(cpu_context, ip, mnem, opvalues):
    """Atomic exclusive OR on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STSET(cpu_context, ip, mnem, opvalues):
    """Atomic bit set, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STSETB(cpu_context, ip, mnem, opvalues):
    """Atomic bit set on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STSETH(cpu_context, ip, mnem, opvalues):
    """Atomic bit set on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STMAX(cpu_context, ip, mnem, opvalues):
    """Atomic signed maximum, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STMAXB(cpu_context, ip, mnem, opvalues):
    """Atomic signed maximum on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STMAXH(cpu_context, ip, mnem, opvalues):
    """Atomic signed maximum on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STMIN(cpu_context, ip, mnem, opvalues):
    """Atomic signed minimum, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STMINB(cpu_context, ip, mnem, opvalues):
    """Atomic signed minimum on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STMINH(cpu_context, ip, mnem, opvalues):
    """Atomic signed minimum on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STUMAX(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned maximum, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STUMAXB(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned maximum on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
@opcode
def STUMAXH(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned maximum on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STUMIN(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned minimum, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STUMINB(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned minimum on byte, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def STUMINH(cpu_context, ip, mnem, opvalues):
    """Atomic unsigned minimum on halfword, without return"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
Swap
The swap instructions support only one addressing mode:
* Base register only.

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
def SWP(cpu_context, ip, mnem, opvalues):
    """Swap"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SWPB(cpu_context, ip, mnem, opvalues):
    """Swap byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SWPH(cpu_context, ip, mnem, opvalues):
    """Swap halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Arithmetic (immediate)
The Arithmetic (immediate) instructions accept a 12-bit unsigned immediate value, optionally shifted left by 12 bits.

The Arithmetic (immediate) instructions that do not set Condition flags can read from and write to the current stack
pointer. The flag setting instructions can read from the stack pointer, but they cannot write to it.
"""

@opcode
def ADD(cpu_context, ip, mnem, opvalues):
    """Add"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ADDS(cpu_context, ip, mnem, opvalues):
    """Add and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SUB(cpu_context, ip, mnem, opvalues):
    """Subtract"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SUBS(cpu_context, ip, mnem, opvalues):
    """Subtract and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMP(cpu_context, ip, mnem, opvalues):
    """Compare"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMN(cpu_context, ip, mnem, opvalues):
    """Compare negative"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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
def AND(cpu_context, ip, mnem, opvalues):
    """Bitwise AND"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ANDS(cpu_context, ip, mnem, opvalues):
    """Bitwise AND and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def EOR(cpu_context, ip, mnem, opvalues):
    """Bitwise exclusive OR"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ORR(cpu_context, ip, mnem, opvalues):
    """Bitwise inclusive OR"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def TST(cpu_context, ip, mnem, opvalues):
    """Test bits"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Move (wide immediate)
The Move (wide immediate) instructions insert a 16-bit immediate, or inverted immediate, into a 16-bit aligned
position in the destination register. The value of the other bits in the destination register depends on the variant used.
The optional shift amount can be any multiple of 16 that is smaller than the register size.
"""

@opcode
def MOVZ(cpu_context, ip, mnem, opvalues):
    """Move wide with zero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MOVN(cpu_context, ip, mnem, opvalues):
    """Move wide with NOT"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MOVK(cpu_context, ip, mnem, opvalues):
    """Move wide with keep"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Move (immediate)
The Move (immediate) instructions are aliases for a single MOVZ, MOVN, or ORR (immediate with zero register),
instruction to load an immediate value into the destination register. An assembler must permit a signed or unsigned
immediate, as long as its binary representation can be generated using one of these instructions, and an assembler
error results if the immediate cannot be generated in this way. On disassembly, it is unspecified whether the
immediate is output as a signed or an unsigned value.

If there is a choice between the MOVZ, MOVN, and ORR instruction to encode the immediate, then an assembler must
prefer MOVZ to MOVN, and MOVZ or MOVN to ORR, to ensure reversability. A disassembler must output ORR (immediate with
zero register) MOVZ, and MOVN, as a MOV mnemonic except that the underlying instruction must be used when:
* ORR has an immediate that can be generated by a MOVZ or MOVN instruction.
* A MOVN instruction has an immediate that can be encoded by MOVZ.
* MOVZ #0 or MOVN #0 have a shift amount other than LSL #0.
"""

@opcode
def MOV(cpu_context, ip, mnem, opvalues):
    """
    Move (inverted wide immediate)
    Move (wide immediate)
    Move (bitmask immediate)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
PC-relative address calculation
The ADR instruction adds a signed, 21-bit immediate to the value of the program counter that fetched this instruction,
and then writes the result to a general-purpose register. This permits the calculation of any byte address within
1MB of the current PC.

The ADRP instruction shifts a signed, 21-bit immediate left by 12 bits, adds it to the value of the program counter with
the bottom 12 bits cleared to zero, and then writes the result to a general-purpose register. This permits the
calculation of the address at a 4KB aligned memory region. In conjunction with an ADD (immediate) instruction, or
a Load/Store instruction with a 12-bit immediate offset, this allows for the calculation of, or access to, any address
within 4GB of the current PC.

Note
The term page used in the ADRP description is short-hand for the 4KB memory region, and is not related to the virtual
memory translation granule size.
"""

@opcode
def ADRP(cpu_context, ip, mnem, opvalues):
    """Compute address of 4KB page at a PC-relative offset"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ADR(cpu_context, ip, mnem, opvalues):
    """Compute address of label at a PC-relative offset."""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Bitfield move
The Bitfield move instructions copy a field of constant width from bit 0 in the source register to a constant bit
position in the destination register, or from a constant bit position in the source register to bit 0 in the destination
register. The remaining bits in the destination register are set as follows:
* For BFM, the remaining bits are unchanged.
* For UBFM the lower bits, if any, and upper bits, if any, are set to zero.
* For SBFM, the lower bits, if any, are set to zero, and the upper bits, if any, are set to a copy of the
  most-significant bit in the copied field.
"""

@opcode
def BFM(cpu_context, ip, mnem, opvalues):
    """Bitfield move"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SBFM(cpu_context, ip, mnem, opvalues):
    """Signed bitfield move"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UBFM(cpu_context, ip, mnem, opvalues):
    """Unsigned bitfield move (32-bit)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
Bitfield insert and extract
The Bitfield insert and extract instructions are implemented as aliases of the Bitfield move instructions. Table C3-40
shows the Bitfield insert and extract aliases.
"""

@opcode
def BFC(cpu_context, ip, mnem, opvalues):
    """Bitfield insert clear"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def BFI(cpu_context, ip, mnem, opvalues):
    """Bitfield insert"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def BFXIL(cpu_context, ip, mnem, opvalues):
    """Bitfield extract and insert low"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SBFIZ(cpu_context, ip, mnem, opvalues):
    """Signed bitfield insert in zero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SBFX(cpu_context, ip, mnem, opvalues):
    """Signed bitfield extract"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UBFIZ(cpu_context, ip, mnem, opvalues):
    """Unsigned bitfield insert in zero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UBFX(cpu_context, ip, mnem, opvalues):
    """Unsigned bitfield extract"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


"""
Extract register
Depending on the register width of the operands, the Extract register instruction copies a 32-bit or 64-bit field from
a constant bit position within a double-width value formed by the concatenation of a pair of source registers to a
destination register.
"""

@opcode
def EXTR(cpu_context, ip, mnem, opvalues):
    """Extract register from pair"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
Shift (immediate)
Shifts and rotates by a constant amount are implemented as aliases of the Bitfield move or Extract register
instructions. The shift or rotate amount must be in the range 0 to one less than the register width of the instruction,
inclusive.
"""

@opcode
def ASR(cpu_context, ip, mnem, opvalues):
    """Arithmetic shift right"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LSL(cpu_context, ip, mnem, opvalues):
    """Logical shift left"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LSR(cpu_context, ip, mnem, opvalues):
    """Logical shift right"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ROR(cpu_context, ip, mnem, opvalues):
    """Rotate right"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
   
   
"""
Sign-extend and Zero-extend
The Sign-extend and Zero-extend instructions are implemented as aliases of the Bitfield move instructions.
"""

@opcode
def SXTB(cpu_context, ip, mnem, opvalues):
    """Sign-extend byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SXTH(cpu_context, ip, mnem, opvalues):
    """Sign-extend halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SXTW(cpu_context, ip, mnem, opvalues):
    """Sign-extend word"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UXTB(cpu_context, ip, mnem, opvalues):
    """Unsigned extend byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UXTH(cpu_context, ip, mnem, opvalues):
    """Unsigned extend halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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

@opcode
def NEG(cpu_context, ip, mnem, opvalues):
    """Negate"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def NEGS(cpu_context, ip, mnem, opvalues):
    """Negate and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Arithmetic with carry
The Arithmetic with carry instructions accept two source registers, with the carry flag as an additional input to the
calculation. They do not support shifting of the second source register.
"""

@opcode
def ADC(cpu_context, ip, mnem, opvalues):
    """Add with carry"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ADCS(cpu_context, ip, mnem, opvalues):
    """Add with carry and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SBC(cpu_context, ip, mnem, opvalues):
    """Subtract with carry"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SBCS(cpu_context, ip, mnem, opvalues):
    """Subtract with carry and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def NGC(cpu_context, ip, mnem, opvalues):
    """Negate with carry"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def NGCS(cpu_context, ip, mnem, opvalues):
    """Negate with carry and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    

"""
Flag manipulation instructions
The Flag manipulation instructions set the value of the NZCV condition flags directly.

The instructions SETF8 and SETF16 accept one source register and set the NZV condition flags based on the value of
the input register. The instruction RMIF accepts one source register and two immediate values, rotating the first
source register using the first immediate value and setting the NZCV condition flags masked by the second
immediate value.
"""

@opcode
def CFINV(cpu_context, ip, mnem, opvalues):
    """Invert value of the PSTATE.C bit"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RMIF(cpu_context, ip, mnem, opvalues):
    """Rotate, mask insert flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SETF8(cpu_context, ip, mnem, opvalues):
    """Evaluation of 8-bit flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SETF16(cpu_context, ip, mnem, opvalues):
    """Evaluation of 16-bit flags SETF8,"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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
def BIC(cpu_context, ip, mnem, opvalues):
    """Bitwise bit clear"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def BICS(cpu_context, ip, mnem, opvalues):
    """Bitwise bit clear and set flags"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def EON(cpu_context, ip, mnem, opvalues):
    """Bitwise exclusive OR NOT"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MVN(cpu_context, ip, mnem, opvalues):
    """Bitwise NOT"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ORN(cpu_context, ip, mnem, opvalues):
    """Bitwise inclusive OR NOT"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


"""
Shift (register)
In the Shift (register) instructions, the shift amount is the positive value in the second source register modulo the
register size. The register width of the instruction controls whether the new bits are fed into the result on a right shift
or rotate at bit[63] or bit[31].
"""

@opcode
def ASRV(cpu_context, ip, mnem, opvalues):
    """Arithmetic shift right variable"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LSLV(cpu_context, ip, mnem, opvalues):
    """Logical shift left variable"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def LSRV(cpu_context, ip, mnem, opvalues):
    """Logical shift right variable"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RORV(cpu_context, ip, mnem, opvalues):
    """Rotate right variable"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Multiply
The Multiply instructions write to a single 32-bit or 64-bit destination register, and are built around the fundamental
four operand multiply-add and multiply-subtract operation, together with 32-bit to 64-bit widening variants. A
64-bit to 128-bit widening multiple can be constructed with two instructions, using SMULH or UMULH to generate the
upper 64 bits.
"""

@opcode
def MADD(cpu_context, ip, mnem, opvalues):
    """Multiply-add"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MSUB(cpu_context, ip, mnem, opvalues):
    """Multiply-subtract"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MNEG(cpu_context, ip, mnem, opvalues):
    """Multiply-negate"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MUL(cpu_context, ip, mnem, opvalues):
    """Multiply"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMADDL(cpu_context, ip, mnem, opvalues):
    """Signed multiply-add long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMSUBL(cpu_context, ip, mnem, opvalues):
    """Signed multiply-subtract long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMNEGL(cpu_context, ip, mnem, opvalues):
    """Signed multiply-negate long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMULL(cpu_context, ip, mnem, opvalues):
    """Signed multiply long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMULH(cpu_context, ip, mnem, opvalues):
    """Signed multiply high"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMADDL(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply-add long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMSUBL(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply-subtract long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMNEGL(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply-negate long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMULL(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMULH(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply high"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
Divide
The Divide instructions compute the quotient of a division, rounded towards zero. The remainder can then be
computed as (numerator - (quotient  denominator)), using the MSUB instruction.

If a signed integer division (INT_MIN / -1) is performed where INT_MIN is the most negative integer value
representable in the selected register size, then the result overflows the signed integer range. No indication of this
overflow is produced and the result that is written to the destination register is INT_MIN.

A division by zero results in a zero being written to the destination register, without any indication that the division
by zero occurred.
"""

@opcode
def SDIV(cpu_context, ip, mnem, opvalues):
    """Signed divide"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UDIV(cpu_context, ip, mnem, opvalues):
    """Unsigned divide"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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
def CRC32B(cpu_context, ip, mnem, opvalues):
    """CRC-32 sum from byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CRC32H(cpu_context, ip, mnem, opvalues):
    """CRC-32 sum from halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CRC32W(cpu_context, ip, mnem, opvalues):
    """CRC-32 sum from word"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CRC32X(cpu_context, ip, mnem, opvalues):
    """CRC-32 sum from doubleword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CRC32CB(cpu_context, ip, mnem, opvalues):
    """CRC-32C sum from byte"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CRC32CH(cpu_context, ip, mnem, opvalues):
    """CRC-32C sum from halfword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CRC32CW(cpu_context, ip, mnem, opvalues):
    """CRC-32C sum from word"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CRC32CX(cpu_context, ip, mnem, opvalues):
    """CRC-32C sum from doubleword"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Bit operation
"""

@opcode
def CLS(cpu_context, ip, mnem, opvalues):
    """Count leading sign bits"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CLZ(cpu_context, ip, mnem, opvalues):
    """Count leading zero bits"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RBIT(cpu_context, ip, mnem, opvalues):
    """Reverse bit order"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def REV(cpu_context, ip, mnem, opvalues):
    """Reverse bytes in register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def REV16(cpu_context, ip, mnem, opvalues):
    """Reverse bytes in halfwords"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def REV32(cpu_context, ip, mnem, opvalues):
    """Reverses bytes in words"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def REV64(cpu_context, ip, mnem, opvalues):
    """Reverse bytes in register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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
def CSEL(cpu_context, ip, mnem, opvalues):
    """Conditional select"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CSINC(cpu_context, ip, mnem, opvalues):
    """Conditional select increment"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CSINV(cpu_context, ip, mnem, opvalues):
    """Conditional select inversion"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CSNEG(cpu_context, ip, mnem, opvalues):
    """Conditional select negation"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CSET(cpu_context, ip, mnem, opvalues):
    """Conditional set"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CSETM(cpu_context, ip, mnem, opvalues):
    """Conditional set mask"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CINC(cpu_context, ip, mnem, opvalues):
    """Conditional increment"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CINV(cpu_context, ip, mnem, opvalues):
    """Conditional invert"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CNEG(cpu_context, ip, mnem, opvalues):
    """Conditional negate"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Conditional comparison
The Conditional comparison instructions provide a conditional select for the NZCV Condition flags, setting the
flags to the result of an arithmetic comparison of its two source register values if the named input condition is true,
or to an immediate value if the input condition is false. There are register and immediate forms. The immediate form
compares the source register to a small 5-bit unsigned value.
"""

@opcode
def CCMN(cpu_context, ip, mnem, opvalues):
    """
    Conditional compare negative (register)
    Conditional compare negative (immediate)
    """    
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CCMP(cpu_context, ip, mnem, opvalues):
    """
    Conditional compare (register)
    Conditional compare (immediate)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
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

The floating-point value must be expressible as ( n/16  2r), where n is an integer in the range 16 = n = 31 and r is
an integer in the range of -3 = r = 4, that is a normalized binary floating-point encoding with one sign bit, four bits
of fraction, and a 3-bit exponent.
"""

@opcode
def FMOV(cpu_context, ip, mnem, opvalues):
    """
    Floating-point move register without conversion
    Floating-point move to or from general-purpose register without conversion
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Convert floating-point precision
These instructions convert a floating-point scalar with one precision to a floating-point scalar with a different
precision, using the current rounding mode as specified by FPCR.RMode.
"""

@opcode
def FCVT(cpu_context, ip, mnem, opvalues):
    """Floating-point convert precision (scalar)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
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
def FCVTAS(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to signed integer, rounding to nearest with ties to away (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTAU(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to unsigned integer, rounding to nearest with ties to away (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTMS(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to signed integer, rounding toward minus infinity (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTMU(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to unsigned integer, rounding toward minus infinity (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTNS(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to signed integer, rounding to nearest with ties to even (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTNU(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to unsigned integer, rounding to nearest with ties to even (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTPS(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to signed integer, rounding toward positive infinity (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTPU(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar convert to unsigned integer, rounding toward positive infinity (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTZS(cpu_context, ip, mnem, opvalues):
    """
    Floating-point scalar convert to signed integer, rounding toward zero (scalar form)
    Floating-point scalar convert to signed fixed-point, rounding toward zero (scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTZU(cpu_context, ip, mnem, opvalues):
    """
    Floating-point scalar convert to unsigned integer, rounding toward zero (scalar form)
    Floating-point scalar convert to unsigned fixed-point, rounding toward zero (scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FJCVTZS(cpu_context, ip, mnem, opvalues):
    """Floating-point Javascript convert to signed fixed-point, rounding toward zero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SCVTF(cpu_context, ip, mnem, opvalues):
    """
    Signed integer scalar convert to floating-point, using the current rounding mode (scalar form)
    Signed integer fixed-point convert to floating-point, using the current rounding mode (scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UCVTF(cpu_context, ip, mnem, opvalues):
    """
    Unsigned integer scalar convert to floating-point, using the current rounding mode (scalar form)
    Unsigned integer fixed-point convert to floating-point, using the current rounding mode (scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
Floating-point round to integer
The Floating-point round to integer instructions round a floating-point value to an integer floating-point value of
the same size.

For these instructions:
* A zero input gives a zero result with the same sign.
* An infinite input gives an infinite result with the same sign.
* A NaN is propagated as in normal floating-point arithmetic.

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
def FRINTA(cpu_context, ip, mnem, opvalues):
    """Floating-point round to integer, to nearest with ties to away"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRINTI(cpu_context, ip, mnem, opvalues):
    """Floating-point round to integer, using current rounding mode"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRINTM(cpu_context, ip, mnem, opvalues):
    """Floating-point round to integer, toward minus infinity"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRINTN(cpu_context, ip, mnem, opvalues):
    """Floating-point round to integer, to nearest with ties to even"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRINTP(cpu_context, ip, mnem, opvalues):
    """Floating-point round to integer, toward positive infinity"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRINTX(cpu_context, ip, mnem, opvalues):
    """Floating-point round to integer exact, using current rounding mode"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRINTZ(cpu_context, ip, mnem, opvalues):
    """Floating-point round to integer, toward zero"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Floating-point multiply-add
"""

@opcode
def FMADD(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar fused multiply-add"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMSUB(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar fused multiply-subtract"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FNMADD(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar negated fused multiply-add"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FNMSUB(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar negated fused multiply-subtract"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Floating-point arithmetic (one source)
"""

@opcode
def FABS(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar absolute value"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FNEG(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar negate"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FSQRT(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar square root"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Floating-point arithmetic (two sources)
"""

@opcode
def FADD(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar add"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FDIV(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar divide"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMUL(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar multiply"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FNMUL(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar multiply-negate"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FSUB(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar subtract"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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
def FMAX(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar maximum"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMAXNM(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar maximum number"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMIN(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar minimum"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMINNM(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar minimum number"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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
def FCMP(cpu_context, ip, mnem, opvalues):
    """Floating-point quiet compare"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCMPE(cpu_context, ip, mnem, opvalues):
    """Floating-point signaling compare"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCCMP(cpu_context, ip, mnem, opvalues):
    """Floating-point conditional quiet compare"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCCMPE(cpu_context, ip, mnem, opvalues):
    """Floating-point conditional signaling compare"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
Floating-point conditional select
"""

@opcode
def FCSEL(cpu_context, ip, mnem, opvalues):
    """Floating-point scalar conditional select"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD move
The functionality of some data movement instructions overlaps with that provided by the scalar floating-point FMOV
instructions described in Floating-point move (register) on page C3-207.
"""

@opcode
def DUP(cpu_context, ip, mnem, opvalues):
    """
    Duplicate vector element to vector or scalar
    Duplicate general-purpose register to vector
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def INSa(cpu_context, ip, mnem, opvalues):
    """
    Insert vector element from another vector element
    Insert vector element from general-purpose register INS (general) on page C7-16
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMOV(cpu_context, ip, mnem, opvalues):
    """Unsigned move vector element to general-purpose register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMOV(cpu_context, ip, mnem, opvalues):
    """Signed move vector element to general-purpose register"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD arithmetic
"""

@opcode
def BIF(cpu_context, ip, mnem, opvalues):
    """Bitwise insert if false (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def BIT(cpu_context, ip, mnem, opvalues):
    """Bitwise insert if true (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def BSL(cpu_context, ip, mnem, opvalues):
    """Bitwise select (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FABD(cpu_context, ip, mnem, opvalues):
    """Floating-point absolute difference (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMLA(cpu_context, ip, mnem, opvalues):
    """Floating-point fused multiply-add (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMLAL(cpu_context, ip, mnem, opvalues):
    """FMLAL2 Floating-point fused multiply-add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMLS(cpu_context, ip, mnem, opvalues):
    """Floating-point fused multiply-subtract (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMLSL(cpu_context, ip, mnem, opvalues):
    """FMLSL2 Floating-point fused multiply-subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMULX(cpu_context, ip, mnem, opvalues):
    """Floating-point multiply extended (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRECPS(cpu_context, ip, mnem, opvalues):
    """Floating-point reciprocal step (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRSQRTS(cpu_context, ip, mnem, opvalues):
    """Floating-point reciprocal square root step (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MLA(cpu_context, ip, mnem, opvalues):
    """Multiply-add (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MLS(cpu_context, ip, mnem, opvalues):
    """Multiply-subtract (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def PMUL(cpu_context, ip, mnem, opvalues):
    """Polynomial multiply (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SABA(cpu_context, ip, mnem, opvalues):
    """Signed absolute difference and accumulate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SABD(cpu_context, ip, mnem, opvalues):
    """Signed absolute difference (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SHADD(cpu_context, ip, mnem, opvalues):
    """Signed halving add (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SHSUB(cpu_context, ip, mnem, opvalues):
    """Signed halving subtract (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMAX(cpu_context, ip, mnem, opvalues):
    """Signed maximum (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMIN(cpu_context, ip, mnem, opvalues):
    """Signed minimum (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQADD(cpu_context, ip, mnem, opvalues):
    """Signed saturating add (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQDMULH(cpu_context, ip, mnem, opvalues):
    """Signed saturating doubling multiply returning high half (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRSHL(cpu_context, ip, mnem, opvalues):
    """Signed saturating rounding shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRDMLAH(cpu_context, ip, mnem, opvalues):
    """Signed saturating rounding doubling multiply accumulate returning high half"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRDMLSH(cpu_context, ip, mnem, opvalues):
    """Signed saturating rounding doubling multiply subtract returning high half"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRDMULH(cpu_context, ip, mnem, opvalues):
    """Signed saturating rounding doubling multiply returning high half (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQSHL(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQSUB(cpu_context, ip, mnem, opvalues):
    """Signed saturating subtract (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SRHADD(cpu_context, ip, mnem, opvalues):
    """Signed rounding halving add (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SRSHL(cpu_context, ip, mnem, opvalues):
    """Signed rounding shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSHL(cpu_context, ip, mnem, opvalues):
    """Signed shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UABA(cpu_context, ip, mnem, opvalues):
    """Unsigned absolute difference and accumulate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UABD(cpu_context, ip, mnem, opvalues):
    """Unsigned absolute difference (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UHADD(cpu_context, ip, mnem, opvalues):
    """Unsigned halving add (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UHSUB(cpu_context, ip, mnem, opvalues):
    """Unsigned halving subtract (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMAX(cpu_context, ip, mnem, opvalues):
    """Unsigned maximum (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMIN(cpu_context, ip, mnem, opvalues):
    """Unsigned minimum (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQADD(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating add (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQRSHL(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating rounding shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQSHL(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQSUB(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating subtract (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def URHADD(cpu_context, ip, mnem, opvalues):
    """Unsigned rounding halving add (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def URSHL(cpu_context, ip, mnem, opvalues):
    """Unsigned rounding shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USHL(cpu_context, ip, mnem, opvalues):
    """Unsigned shift left (register) (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
SIMD compare
The SIMD compare instructions compare vector or scalar elements according to the specified condition and set the
destination vector element to all ones if the condition holds, or to zero if the condition does not hold.

Note
Some of the comparisons, such as LS, LE, LO, and LT, can be made by reversing the operands and using the
opposite comparison, HS, GE, HI, or GT.
"""

@opcode
def CMEQ(cpu_context, ip, mnem, opvalues):
    """
    Compare bitwise equal (vector and scalar form)
    Compare bitwise equal to zero (vector and scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMHS(cpu_context, ip, mnem, opvalues):
    """Compare unsigned higher or same (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMGE(cpu_context, ip, mnem, opvalues):
    """
    Compare signed greater than or equal (vector and scalar form)
    Compare signed greater than or equal to zero (vector and scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMHI(cpu_context, ip, mnem, opvalues):
    """Compare unsigned higher (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMGT(cpu_context, ip, mnem, opvalues):
    """
    Compare signed greater than (vector and scalar form)
    Compare signed greater than zero (vector and scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMLE(cpu_context, ip, mnem, opvalues):
    """Compare signed less than or equal to zero (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMLT(cpu_context, ip, mnem, opvalues):
    """Compare signed less than zero (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CMTST(cpu_context, ip, mnem, opvalues):
    """Compare bitwise test bits nonzero (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCMEQ(cpu_context, ip, mnem, opvalues):
    """
    Floating-point compare equal (vector and scalar form)
    Floating-point compare equal to zero (vector and scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCMGE(cpu_context, ip, mnem, opvalues):
    """
    Floating-point compare greater than or equal (vector and scalar form)
    Floating-point compare greater than or equal to zero (vector and scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCMGT(cpu_context, ip, mnem, opvalues):
    """
    Floating-point compare greater than (vector and scalar form)
    Floating-point compare greater than zero (vector and scalar form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCMLE(cpu_context, ip, mnem, opvalues):
    """Floating-point compare less than or equal to zero (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCMLT(cpu_context, ip, mnem, opvalues):
    """Floating-point compare less than zero (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FACGE(cpu_context, ip, mnem, opvalues):
    """Floating-point absolute compare greater than or equal (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FACGT(cpu_context, ip, mnem, opvalues):
    """Floating-point absolute compare greater than (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD widening and narrowing arithmetic  pg 217
"""

@opcode
def ADDHN(cpu_context, ip, mnem, opvalues):
    """Add returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ADDHN2(cpu_context, ip, mnem, opvalues):
    """Add returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def PMULL(cpu_context, ip, mnem, opvalues):
    """Polynomial multiply long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def PMULL2(cpu_context, ip, mnem, opvalues):
    """Polynomial multiply long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RADDHN(cpu_context, ip, mnem, opvalues):
    """Rounding add returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RADDHN2(cpu_context, ip, mnem, opvalues):
    """Rounding add returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RSUBHN(cpu_context, ip, mnem, opvalues):
    """Rounding subtract returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RSUBHN2(cpu_context, ip, mnem, opvalues):
    """Rounding subtract returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SABAL(cpu_context, ip, mnem, opvalues):
    """Signed absolute difference and accumulate long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SABAL2(cpu_context, ip, mnem, opvalues):
    """Signed absolute difference and accumulate long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SABDL(cpu_context, ip, mnem, opvalues):
    """Signed absolute difference long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SABDL2(cpu_context, ip, mnem, opvalues):
    """Signed absolute difference long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SADDL(cpu_context, ip, mnem, opvalues):
    """Signed add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SADDL2(cpu_context, ip, mnem, opvalues):
    """Signed add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SADDW(cpu_context, ip, mnem, opvalues):
    """Signed add wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SADDW2(cpu_context, ip, mnem, opvalues):
    """Signed add wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMLAL(cpu_context, ip, mnem, opvalues):
    """Signed multiply-add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMLAL2(cpu_context, ip, mnem, opvalues):
    """Signed multiply-add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMLSL(cpu_context, ip, mnem, opvalues):
    """Signed multiply-subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMLSL2(cpu_context, ip, mnem, opvalues):
    """Signed multiply-subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMULL2(cpu_context, ip, mnem, opvalues):
    """Signed multiply long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQDMLAL(cpu_context, ip, mnem, opvalues):
    """Signed saturating doubling multiply-add long (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQDMLAL2(cpu_context, ip, mnem, opvalues):
    """Signed saturating doubling multiply-add long (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQDMLSL(cpu_context, ip, mnem, opvalues):
    """Signed saturating doubling multiply-subtract long (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQDMLSL2(cpu_context, ip, mnem, opvalues):
    """Signed saturating doubling multiply-subtract long (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQDMULL(cpu_context, ip, mnem, opvalues):
    """Signed saturating doubling multiply long (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQDMULL2(cpu_context, ip, mnem, opvalues):
    """Signed saturating doubling multiply long (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSUBL(cpu_context, ip, mnem, opvalues):
    """Signed subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSUBL2(cpu_context, ip, mnem, opvalues):
    """Signed subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSUBW(cpu_context, ip, mnem, opvalues):
    """Signed subtract wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSUBW2(cpu_context, ip, mnem, opvalues):
    """Signed subtract wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SUBHN(cpu_context, ip, mnem, opvalues):
    """Subtract returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SUBHN2(cpu_context, ip, mnem, opvalues):
    """Subtract returning high, narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UABAL(cpu_context, ip, mnem, opvalues):
    """Unsigned absolute difference and accumulate long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UABAL2(cpu_context, ip, mnem, opvalues):
    """Unsigned absolute difference and accumulate long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UABDL(cpu_context, ip, mnem, opvalues):
    """Unsigned absolute difference long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UABDL2(cpu_context, ip, mnem, opvalues):
    """Unsigned absolute difference long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UADDL(cpu_context, ip, mnem, opvalues):
    """Unsigned add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UADDL2(cpu_context, ip, mnem, opvalues):
    """Unsigned add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UADDW(cpu_context, ip, mnem, opvalues):
    """Unsigned add wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UADDW2(cpu_context, ip, mnem, opvalues):
    """Unsigned add wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMLAL(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply-add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMLAL2(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply-add long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMLSL(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply-subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMLSL2(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply-subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMULL2(cpu_context, ip, mnem, opvalues):
    """Unsigned multiply long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USUBL(cpu_context, ip, mnem, opvalues):
    """Unsigned subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USUBL2(cpu_context, ip, mnem, opvalues):
    """Unsigned subtract long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USUBW(cpu_context, ip, mnem, opvalues):
    """Unsigned subtract wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USUBW2(cpu_context, ip, mnem, opvalues):
    """Unsigned subtract wide (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
SIMD unary arithmetic
"""

@opcode
def ABS(cpu_context, ip, mnem, opvalues):
    """Absolute value (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def CNT(cpu_context, ip, mnem, opvalues):
    """Population count per byte (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTL(cpu_context, ip, mnem, opvalues):
    """Floating-point convert to higher precision long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTL2(cpu_context, ip, mnem, opvalues):
    """Floating-point convert to higher precision long (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTN(cpu_context, ip, mnem, opvalues):
    """Floating-point convert to lower precision narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTN2(cpu_context, ip, mnem, opvalues):
    """Floating-point convert to lower precision narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTXN(cpu_context, ip, mnem, opvalues):
    """Floating-point convert to lower precision narrow, rounding to odd (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCVTXN2(cpu_context, ip, mnem, opvalues):
    """Floating-point convert to lower precision narrow, rounding to odd (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRECPE(cpu_context, ip, mnem, opvalues):
    """Floating-point reciprocal estimate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRECPX(cpu_context, ip, mnem, opvalues):
    """Floating-point reciprocal square root (scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FRSQRTE(cpu_context, ip, mnem, opvalues):
    """Floating-point reciprocal square root estimate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def NOT(cpu_context, ip, mnem, opvalues):
    """Bitwise"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SADALP(cpu_context, ip, mnem, opvalues):
    """Signed add and accumulate long pairwise (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SADDLP(cpu_context, ip, mnem, opvalues):
    """Signed add long pairwise (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQABS(cpu_context, ip, mnem, opvalues):
    """Signed saturating absolute value (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQNEG(cpu_context, ip, mnem, opvalues):
    """Signed saturating negate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQXTN(cpu_context, ip, mnem, opvalues):
    """Signed saturating extract narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQXTN2(cpu_context, ip, mnem, opvalues):
    """Signed saturating extract narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQXTUN(cpu_context, ip, mnem, opvalues):
    """Signed saturating extract unsigned narrow (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQXTUN2(cpu_context, ip, mnem, opvalues):
    """Signed saturating extract unsigned narrow (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SUQADD(cpu_context, ip, mnem, opvalues):
    """Signed saturating accumulate of unsigned value (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SXTL(cpu_context, ip, mnem, opvalues):
    """Signed extend long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SXTL2(cpu_context, ip, mnem, opvalues):
    """Signed extend long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UADALP(cpu_context, ip, mnem, opvalues):
    """Unsigned add and accumulate long pairwise (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UADDLP(cpu_context, ip, mnem, opvalues):
    """Unsigned add long pairwise (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQXTN(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating extract narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQXTN2(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating extract narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def URECPE(cpu_context, ip, mnem, opvalues):
    """Unsigned reciprocal estimate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def URSQRTE(cpu_context, ip, mnem, opvalues):
    """Unsigned reciprocal square root estimate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USQADD(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating accumulate of signed value (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UXTL(cpu_context, ip, mnem, opvalues):
    """Unsigned extend long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UXTL2(cpu_context, ip, mnem, opvalues):
    """Unsigned extend long"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def XTN(cpu_context, ip, mnem, opvalues):
    """Extract narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def XTN2(cpu_context, ip, mnem, opvalues):
    """Extract narrow (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
SIMD by element arithmetic
"""

@opcode
def FMLAL2(cpu_context, ip, mnem, opvalues):
    """Floating-point fused multiply-add long (vector form) FMLAL,"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMLSL2(cpu_context, ip, mnem, opvalues):
    """Floating-point fused multiply-subtract long (vector form) FMLSL,"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD permute
"""

@opcode
def EXT(cpu_context, ip, mnem, opvalues):
    """Extract vector from a pair of vectors"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def TRN1(cpu_context, ip, mnem, opvalues):
    """Transpose vectors (primary)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def TRN2(cpu_context, ip, mnem, opvalues):
    """Transpose vectors (secondary)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UZP1(cpu_context, ip, mnem, opvalues):
    """Unzip vectors (primary)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UZP2(cpu_context, ip, mnem, opvalues):
    """Unzip vectors (secondary)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ZIP1(cpu_context, ip, mnem, opvalues):
    """Zip vectors (primary)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def ZIP2(cpu_context, ip, mnem, opvalues):
    """Zip vectors (secondary)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
SIMD immediate
"""

@opcode
def MOVI(cpu_context, ip, mnem, opvalues):
    """Move immediate"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def MVNI(cpu_context, ip, mnem, opvalues):
    """Move inverted immediate"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD shift (immediate)
"""

@opcode
def RSHRN(cpu_context, ip, mnem, opvalues):
    """Rounding shift right narrow immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def RSHRN2(cpu_context, ip, mnem, opvalues):
    """Rounding shift right narrow immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SHL(cpu_context, ip, mnem, opvalues):
    """Shift left immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SHLL(cpu_context, ip, mnem, opvalues):
    """Shift left long (by element size) (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SHLL2(cpu_context, ip, mnem, opvalues):
    """Shift left long (by element size) (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SHRN(cpu_context, ip, mnem, opvalues):
    """Shift right narrow immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SHRN2(cpu_context, ip, mnem, opvalues):
    """Shift right narrow immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SLI(cpu_context, ip, mnem, opvalues):
    """Shift left and insert immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRSHRN(cpu_context, ip, mnem, opvalues):
    """Signed saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRSHRN2(cpu_context, ip, mnem, opvalues):
    """Signed saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRSHRUN(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQRSHRUN2(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQSHLU(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift left unsigned immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQSHRN(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQSHRN2(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQSHRUN(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SQSHRUN2(cpu_context, ip, mnem, opvalues):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SRI(cpu_context, ip, mnem, opvalues):
    """Shift right and insert immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SRSHR(cpu_context, ip, mnem, opvalues):
    """Signed rounding shift right immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SRSRA(cpu_context, ip, mnem, opvalues):
    """Signed rounding shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSHLL(cpu_context, ip, mnem, opvalues):
    """Signed shift left long immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSHLL2(cpu_context, ip, mnem, opvalues):
    """Signed shift left long immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSHR(cpu_context, ip, mnem, opvalues):
    """Signed shift right immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SSRA(cpu_context, ip, mnem, opvalues):
    """Signed integer shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQRSHRN(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQRSHRN2(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQSHRN(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UQSHRN2(cpu_context, ip, mnem, opvalues):
    """Unsigned saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def URSHR(cpu_context, ip, mnem, opvalues):
    """Unsigned rounding shift right immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def URSRA(cpu_context, ip, mnem, opvalues):
    """Unsigned integer rounding shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USHLL(cpu_context, ip, mnem, opvalues):
    """Unsigned shift left long immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USHLL2(cpu_context, ip, mnem, opvalues):
    """Unsigned shift left long immediate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USHR(cpu_context, ip, mnem, opvalues):
    """Unsigned shift right immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def USRA(cpu_context, ip, mnem, opvalues):
    """Unsigned shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD reduce (across vector lanes)
The SIMD reduce (across vector lanes) instructions perform arithmetic operations horizontally, that is across all
lanes of the input vector. They deliver a single scalar result.
"""

@opcode
def ADDV(cpu_context, ip, mnem, opvalues):
    """Add (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMAXNMV(cpu_context, ip, mnem, opvalues):
    """Floating-point maximum number (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMAXV(cpu_context, ip, mnem, opvalues):
    """Floating-point maximum (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMINNMV(cpu_context, ip, mnem, opvalues):
    """Floating-point minimum number (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMINV(cpu_context, ip, mnem, opvalues):
    """Floating-point minimum (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SADDLV(cpu_context, ip, mnem, opvalues):
    """Signed add long (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMAXV(cpu_context, ip, mnem, opvalues):
    """Signed maximum (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMINV(cpu_context, ip, mnem, opvalues):
    """Signed minimum (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UADDLV(cpu_context, ip, mnem, opvalues):
    """Unsigned add long (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMAXV(cpu_context, ip, mnem, opvalues):
    """Unsigned maximum (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMINV(cpu_context, ip, mnem, opvalues):
    """Unsigned minimum (across vector)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))

    
"""
SIMD pairwise arithmetic
The SIMD pairwise arithmetic instructions perform operations on pairs of adjacent elements and deliver a vector
result.
"""

@opcode
def ADDP(cpu_context, ip, mnem, opvalues):
    """Add pairwise (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FADDP(cpu_context, ip, mnem, opvalues):
    """Floating-point add pairwise (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMAXNMP(cpu_context, ip, mnem, opvalues):
    """Floating-point maximum number pairwise (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMAXP(cpu_context, ip, mnem, opvalues):
    """Floating-point maximum pairwise (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMINNMP(cpu_context, ip, mnem, opvalues):
    """Floating-point minimum number pairwise (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FMINP(cpu_context, ip, mnem, opvalues):
    """Floating-point minimum pairwise (vector and scalar form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMAXP(cpu_context, ip, mnem, opvalues):
    """Signed maximum pairwise"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def SMINP(cpu_context, ip, mnem, opvalues):
    """Signed minimum pairwise"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMAXP(cpu_context, ip, mnem, opvalues):
    """Unsigned maximum pairwise"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UMINP(cpu_context, ip, mnem, opvalues):
    """Unsigned minimum pairwise"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
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
def SDOT(cpu_context, ip, mnem, opvalues):
    """
    Signed dot product (vector form)
    Signed dot product (indexed form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def UDOT(cpu_context, ip, mnem, opvalues):
    """
    Unsigned dot product (vector form)
    Unsigned dot product (indexed form)
    """
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD table lookup
"""

@opcode
def TBL(cpu_context, ip, mnem, opvalues):
    """Table vector lookup"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def TBX(cpu_context, ip, mnem, opvalues):
    """Table vector lookup extension"""
    logger.debug("{} instruction not currently implemented.".format(mnem))
    
    
"""
SIMD complex number arithmetic
ARMv8.3-CompNum provides SIMD instructions that perform arithmetic on complex numbers held in element
pairs in vector registers, where the less significant element of the pair contains the real component and the more
significant element contains the imaginary component.

These instructions provide double-precision and single-precision versions. If ARMv8.2-FP16 is implemented they
also provide half-precision versions, otherwise the half-precision encodings are UNDEFINED.
"""

@opcode
def FCADD(cpu_context, ip, mnem, opvalues):
    """Floating-point complex add"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


@opcode
def FCMLA(cpu_context, ip, mnem, opvalues):
    """Floating-point complex multiply accumulate (vector form)"""
    logger.debug("{} instruction not currently implemented.".format(mnem))


# Global helper functions

def get_max_operand_size(operands):
    """
    Given the list of named tuples containing the operand value and bit width, determine the largest bit width.

    :param operands: list of Operand objects

    :return: largest operand width
    """
    return max(operand.width for operand in operands)


def get_min_operand_size(operands):
    """
    Given the list of named tuples containing the operand value and bit width, determine the smallest bit width.

    :param operands: list of Operand objects

    :return: smallest operand width
    """
    return min(operand.width for operand in operands)
