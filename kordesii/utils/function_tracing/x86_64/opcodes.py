"""
CPU EMULATOR HANDLED INSTRUCTIONS

Add any instructions that need to be handled below.  The function should be declared as such

# Using the same function for multiple instructions:
@opcode("add")
@opcode("adc")
def _add(cpu_context, ip, mnem, operands):
    print "IN ADD"

# Using a single function for an opcode
@opcode
def MOV(cpu_context, ip, mnem, operands):
    print "IN MOV"

WARNING:
    Do NOT rely on the flags registers being correct.  There are places were flags are NOT being updated when they
    should, and the very fact that CALL instructions are skipped could cause flags to be incorrect.
"""

import logging
import re

import idc
import idaapi
import idautils


from .. import utils
from ..cpu_context import Operand
from .. import functions
from ..registry import registrar


# Dictionary containing opcode names -> function
OPCODES = {}
opcode = registrar(OPCODES, name='opcode')


logger = logging.getLogger(__name__)


@opcode("adc")
@opcode("add")
def _add(cpu_context, ip, mnem, operands):
    """
    Handle both ADC and ADD here since the only difference is the flags.
    """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    result = opvalue1 + opvalue2
    if mnem == "adc":
        result += cpu_context.registers.cf
    width = get_max_operand_size(operands)

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int(result > mask)
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit(~(opvalue1 ^ opvalue2) & (opvalue2 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("{} 0x{:X} :: {} + {} = {}".format(mnem, ip, opvalue1, opvalue2, result))
    operands[0].value = result & mask


@opcode
def AND(cpu_context, ip, mnem, operands):
    """ AND logic operator """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    result = opvalue1 & opvalue2
    width = get_max_operand_size(operands)

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("AND 0x{:X} :: {} & {} = {}".format(ip, opvalue1, opvalue2, result))
    operands[0].value = result


@opcode
def BSWAP(cpu_context, ip, mnem, operands):
    """ byte Swap """
    opvalue1 = operands[0].value
    width = operands[0].width
    result = swap_bytes(opvalue1, width)
    logger.debug("BSWAP 0x{:X} :: {} -> {}".format(ip, opvalue1, result))
    operands[0].value = result


def _sanitize_func_name(func_name):
    """Sanitizes the IDA function names to it's core name."""
    # remove the extra "_" IDA likes to add to the function name.
    if func_name.startswith('_'):
        func_name = func_name[1:]

    # Remove the numbered suffix IDA likes to add to duplicate function names.
    func_name = re.sub('_[0-9]+$', '', func_name)

    return func_name


@opcode
def CALL(cpu_context, ip, mnem, operands):
    """
    CALL function

    Attempt to determine the number of arguments passed to the function which are purged on return
    """
    # Function pointer can be a memory reference or immediate.
    func_ea = operands[0].addr or operands[0].value
    func_name = utils.get_function_name(func_ea)

    logger.debug("CALL 0x{:X} :: call {}".format(ip, func_name or '0x{:X}'.format(func_ea)))

    # TODO: Should we be placing the ip on the stack to simulate the retn address?

    # If a valid function pointer, collect call history and emulate effects.
    if operands[0].is_func_ptr:
        args = cpu_context.get_function_args(func_ea)
        cpu_context.func_calls[ip] = (func_name, args)

        # Emulate the effects of any known builtin functions.
        func = functions.get(func_ea)
        if not func:
            func = functions.get(func_name)
            if not func:
                # Try one more time with a sanitized name.
                func_name = _sanitize_func_name(func_name)
                func = functions.get(func_name)

        if func:
            try:
                logger.debug(' :: {}({})'.format(func_name, ', '.join(map(repr, args))))
                ret = func(cpu_context, func_name, args)
                # Set return value to rax
                if ret is not None:
                    logger.debug(' :: Setting {!r} into rax'.format(ret))
                    cpu_context.registers.rax = ret
            except RuntimeError:
                raise  # Allow RuntimeError exceptions to be thrown.
            except Exception as e:
                logger.debug(
                    '{:#08x} :: Failed to emulate builtin function: {}() with error: {}'.format(
                        ip, func_name, e))

    if idc.__EA64__:
        return

    # For the called function, attempt to locate the function end and examine the "retn" instruction which
    # will contain the number of bytes to add back to SP.
    try:
        is_loaded = idc.is_loaded(func_ea)
    except TypeError:
        is_loaded = False

    # For non-loaded files, reset esp based on number of stack arguments.
    # (We are assuming the callee is responsible for resetting the stack)
    if not is_loaded:
        try:
            func_data = utils.get_function_data(func_ea)
            for arg in func_data:
                loc_type = arg.argloc.atype()
                # Where was this parameter passed?
                if loc_type == 1:  # ALOC_STACK
                    # reset esp for each stack argument.
                    cpu_context.registers.rsp += cpu_context.byteness
        except RuntimeError:
            # If we can't get function data for non-loaded functions, then we have no way of knowing how to handle
            # the stack...
            logger.debug(
                "{:#08x} :: Cannot identify function information for value {:#08x}. "
                "Stack pointer will not be adjusted.".format(ip, func_ea))
            return
    else:
        # Get address of retn instruction
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end == idc.BADADDR:
            # If we can't get a valid function, then pull the stack adjustment using idc.get_sp_delta()
            # on the next instruction.
            sp_adjust = idc.get_sp_delta(idc.next_head(ip))
            cpu_context.registers.rsp += sp_adjust

        else:
            # Find a "retn" and see if we need to adjust rsp.
            # All retn's should have the same operand so finding any of them will work.
            ea = func_end
            while ea > func_ea:
                if idc.print_insn_mnem(ea) == "retn":
                    sp_adjust = idc.get_operand_value(ea, 0)
                    # if retn doesn't adjust the stack, -1 is returned
                    if sp_adjust != -1:
                        cpu_context.registers.rsp += sp_adjust
                    return
                ea = idc.prev_head(ea)


@opcode
def CDQ(cpu_context, ip, mnem, operands):
    """ Convert DWORD to QWORD with sign extension """
    if cpu_context.registers.eax >> 31:
        result = 0xFFFFFFFF
    else:
        result = 0x0

    logger.debug("CDQ 0x{:X} :: Setting register EDX to 0x{:X}".format(ip, result))
    cpu_context.registers.edx = result


@opcode
def CLC(cpu_context, ip, mnem, operands):
    """ Clear Carry Flag """
    cpu_context.registers.cf = 0


@opcode
def CLD(cpu_context, ip, mnem, operands):
    """ Clear Direction Flag """
    cpu_context.registers.df = 0


@opcode
def CMP(cpu_context, ip, mnem, operands):
    """ Compare to values """
    width = get_min_operand_size(operands)
    mask = utils.get_mask(width)
    opvalue1 = operands[0].value & mask
    opvalue2 = operands[1].value & mask
    result = opvalue1 - opvalue2

    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("CMP 0x{:X} :: {} <-> {} = {}".format(ip, opvalue1, opvalue2, result))


@opcode
def CMPS(cpu_context, ip, mnem, operands):
    """
    Nothing really to do for CMPS
    """
    pass


@opcode
def CMPSB(cpu_context, ip, mnem, operands):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CMPSW(cpu_context, ip, mnem, operands):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CMPSD(cpu_context, ip, mnem, operands):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CVTDQ2PD(cpu_context, ip, mnem, operands):
    """ Convert Packed Doubleword Integers to Packed Double-Precision Floating-Point Values """
    opvalue2 = operands[1].value
    dword0 = opvalue2 & 0xFFFFFFFF
    dword1 = (opvalue2 & 0xFFFFFFFF) >> 32
    dpfp0 = utils.float_to_int(dword0)
    dpfp1 = utils.float_to_int(dword1)
    result = (dpfp1 << 64) | dpfp0
    logger.debug("{} 0x{:X} :: {} -> {}, {} -> {} --> {}".format(mnem, ip, dword0, dpfp0, dword1, dpfp1, result))
    operands[0].value = result


@opcode
def CVTSI2SD(cpu_context, ip, mnem, operands):
    """ Convert Doubleword Int to Scalar Double-Precision Floating-Point """
    opvalue2 = operands[1].value
    result = utils.float_to_int(opvalue2)
    logger.debug("{} 0x{:X} :: int {} -> float equivalent {}".format(mnem, ip, opvalue2, result))
    operands[0].value = result


@opcode
def CVTTSD2SI(cpu_context, ip, mnem, operands):
    """ Convert with Truncation Scalar Double-Precision Floating-Point Value to Signed Integer """
    opvalue2 = operands[1].value
    # width = operands[0].width
    result = int(utils.int_to_float(opvalue2))
    logger.debug("{} 0x{:X} :: float {} -> int equivalent {}".format(mnem, ip, opvalue2, result))
    operands[0].value = result


@opcode
def DEC(cpu_context, ip, mnem, operands):
    """ Decrement """
    opvalue1 = operands[0].value
    width = operands[0].width
    mask = utils.get_mask(width)
    result = opvalue1 - 1

    cpu_context.registers.af = int(result & 0x0F == 0x0F)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(
        utils.sign_bit(opvalue1, width) and not utils.sign_bit(result, width))
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], operands)

    logger.debug("DEC 0x{:X} :: {} - 1 = {}".format(ip, opvalue1, result))
    operands[0].value = result & mask


@opcode("div")
@opcode("idiv")
def DIV(cpu_context, ip, mnem, operands):
    """
    Divide

    rax / op1 -> rax (rdx holds remainder)
    """
    RAX_REG_SIZE_MAP = {8: "RAX", 4: "EAX", 2: "AX", 1: "AL"}
    RDX_REG_SIZE_MAP = {8: "RDX", 4: "EDX", 2: "DX"}

    divisor = operands[0].value
    width = operands[0].width
    if divisor == 0:
        # Log the instruction for a DIV / 0 error
        logger.debug("{} 0x{:X} :: DIV / 0".format(mnem, ip))
        return

    # We actually need to do some doctoring with DIV as operand 0 is implied as the EAX register of
    # a certain size.
    rax_str = RAX_REG_SIZE_MAP[width]
    dividend = cpu_context.registers[rax_str]

    result = (dividend // divisor) & utils.get_mask(width)
    remainder = (dividend % divisor) & utils.get_mask(width)
    logger.debug("DIV 0x{:X} :: {} / {} = {}".format(ip, dividend, divisor, result))
    if width == 1:
        # Result stored in AL, remainder stored in AH
        cpu_context.registers.al = result
        cpu_context.registers.ah = remainder
    else:
        rdx_str = RDX_REG_SIZE_MAP[width]
        cpu_context.registers[rax_str] = result
        cpu_context.registers[rdx_str] = remainder


@opcode
def DIVSD(cpu_context, ip, mnem, operands):
    """
    Divide Scalar Double-Precision Floating-Point Value

    op1 / op2 -> op1
    """
    opvalue1 = utils.int_to_float(operands[0].value)
    opvalue2 = utils.int_to_float(operands[1].value)
    # Because there is no guarantee that the registers/memory have been properly initialized, ignore DIV / 0 errors.
    if opvalue2 == 0:
        # Log DIV / 0 error
        logger.debug("{} 0x{:X} :: DIV / 0".format(mnem, ip))
        return

    result = opvalue1 / opvalue2
    logger.debug("{} 0x{:X} :: {} / {} = {}".format(mnem, ip, opvalue1, opvalue2, result))
    result = utils.float_to_int(result)
    operands[0].value = result


def _mul(cpu_context, ip, mnem, operands):
    """
    Handle MUL instruction and 1-operand IMUL instruction as the same.
    """
    RAX_REG_SIZE_MAP = {8: "RAX", 4: "EAX", 2: "AX", 1: "AL"}
    RDX_REG_SIZE_MAP = {8: "RDX", 4: "EDX", 2: "DX"}

    dx_reg = None
    dx_result = None
    width = get_max_operand_size(operands)
    mask = utils.get_mask(width)
    multiplier1 = cpu_context.reg_read(RAX_REG_SIZE_MAP[width])
    multiplier2 = operands[0].value
    result = multiplier1 * multiplier2
    flags = ["cf", "of"]

    if width == 1:
        ax_reg = RAX_REG_SIZE_MAP[2]
        ax_result = result
        if mnem.upper() == "MUL":
            cpu_context.registers.cf = 0
            cpu_context.registers.of = 0
    else:
        ax_reg = RAX_REG_SIZE_MAP[width]
        dx_reg = RDX_REG_SIZE_MAP[width]
        dx_result = ((result & (utils.get_mask(width) << (width * 8))) >> (width * 8))
        ax_result = (result & utils.get_mask(width))
        if mnem.upper() == "MUL":
            if result >> (width * 8):
                cpu_context.registers.cf = 1
                cpu_context.registers.of = 1
            else:
                cpu_context.registers.cf = 0
                cpu_context.registers.of = 0

    if mnem.upper() == "IMUL":
        cpu_context.registers.cf = int(not (
            (not utils.sign_bit(multiplier1, width) and multiplier2 & mask == 0)
             or (utils.sign_bit(multiplier1, width) and multiplier2 & mask == mask)
        ))
        cpu_context.registers.of = cpu_context.registers.cf
        cpu_context.registers.zf = int(multiplier1 & mask == 0)
        cpu_context.registers.sf = utils.sign_bit(multiplier1, width)
        cpu_context.registers.pf = get_parity(multiplier1)
        flags.extend(["zf", "sf", "pf"])

    cpu_context.jcccontext.update_flag_opnds(flags, operands)
    logger.debug("{} 0x{:X} :: {} * {} = {} || EAX -> {} || EDX -> {}".format(
        mnem.upper(),
        ip, multiplier1,
        multiplier2,
        result,
        ax_result,
        dx_result if dx_reg else ''))

    cpu_context.registers[ax_reg] = ax_result
    if dx_reg:
        cpu_context.registers[dx_reg] = dx_result

# TODO: Clean up mul, imul, and _mul
@opcode
def IMUL(cpu_context, ip, mnem, operands):
    """ Signed Multiplication

    ; Single operand form
    imul    ecx     ; Signed multiply the value in ecx with the value in eax (et.al)

    ; Two operand form
    imul    edi, edx    ; Signed multiply the destination operand (op 0) with the source operand (op 1)

    ; Three operand form
    imul    eax, edi, 5 ; Signed multiple source operand (op 1) with the immediate value (op 2) and store in
                        ; the destination operand (op 0)

    """
    width = get_max_operand_size(operands)
    op_count = len(operands)
    if op_count == 1:
        _mul(cpu_context, ip, mnem, operands)
        return
    elif op_count == 2:
        multiplier1 = operands[0].value
        multiplier2 = operands[1].value
    elif op_count == 3:
        multiplier1 = operands[1].value
        multiplier2 = operands[2].value
    else:
        raise Exception("0x{:X}: Invalid sequence for IMUL instruction".format(ip))

    mask = utils.get_mask(width)
    result = multiplier1 * multiplier2

    cpu_context.registers.cf = int(not (
            (not utils.sign_bit(multiplier1, width) and multiplier2 & mask == 0)
            or (utils.sign_bit(multiplier1, width) and multiplier2 & mask == mask)
    ))
    cpu_context.registers.of = cpu_context.registers.cf
    cpu_context.registers.zf = int(multiplier1 & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(multiplier1, width)
    cpu_context.registers.pf = get_parity(multiplier1)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("IMUL 0x{:X} :: {} * {} = {}".format(ip, multiplier1, multiplier2, result))
    operands[0].value = result


@opcode
def INC(cpu_context, ip, mnem, operands):
    """ Increment """
    opvalue1 = operands[0].value

    result = opvalue1 + 1
    width = operands[0].width
    mask = utils.get_mask(width)

    logger.debug("INC 0x{:X} :: {} + 1 = {}".format(ip, opvalue1, result))
    operands[0].value = result

    cpu_context.registers.af = int(result & 0x0F == 0)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(
        not utils.sign_bit(opvalue1, width) and utils.sign_bit(result, width))
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], operands)


@opcode
def JMP(cpu_context, ip, mnem, operands):
    """ Unconditional jump """
    jump_target = operands[0].value
    cpu_context.ip = jump_target


# TODO: Not all Jcc instructions are implemented here.
# TODO: Currently, these Jcc instructions assume that the instruction that modified the flags had 2 opcodes.
#   This is not always the case, (e.g. 'inc'). Also, we should probably figure out a way to move the
#   bulk of the code into a helper function.

# For the following jump instructions, the logic is basically the same
#   1. Get all the CodeRefs from the current IP (should only ever be 2)
#   2. Remove the EA that is the target of the Jcc instruction to we know where the non-jump target is
#   3. Determine the location where our condition takes us and set condition_target_ea to that
#   4. Set the value for the alternate path
# Note that since we aren't currently handling instructions which may cause conditional jumps, we need to
# determine if we have test_opnds and abort fixing the context if we don't.
@opcode("ja")
@opcode("jnbe")
def JA_JNBE(cpu_context, ip, mnem, operands):
    """ Jump Above (CF=0 && ZF=0) """
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition would take use based on our emulation and the value for the alt branch
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf", "zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf == 0 and cpu_context.registers.zf == 0:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 <= opnd1 on this branch. Set the alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))

@opcode("jae")
@opcode("jnb")
@opcode("jnc")
def JAE_JNB(cpu_context, ip, mnem, operands):
    """ Jump Above or Equal / Jump Not Below / Jump Not Carry (CF=0) """
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf == 0:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 < opnd1 on this branch. Set the alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jb")
@opcode("jc")
@opcode("jnae")
def JB_JNAE(cpu_context, ip, mnem, operands):
    """ Jump Below / Jump Carry / Jump Not Above or Equal (CF=1) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than the second operand of the compare operation.
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf:
        # opnd0 < opnd1 on this branch.  Set the alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 >= opnd1 on this branch. Set the alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jbe")
@opcode("jna")
def JBE_JNA(cpu_context, ip, mnem, operands):
    """ Jump Below or Equal / Jump Not Above (CF=1 || ZF=1) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than or equal to the second operand of the compare operation.
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["cf", "zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf or cpu_context.registers.zf:
        # opnd0 <= opnd1 on this branch.  Set the alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("je")
@opcode("jz")
def JE_JZ(cpu_context, ip, mnem, operands):
    """ Jump Equal / Jump Zero (ZF=1) """
    # Jump target contains the known data which is either 0 or the value of the second operand of the compare operation.
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition would take use based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    # There is additional logic that must be conducted for this jump.  If the src and dst operands are the same, then
    # the check was likely to determine if the value was 0 or not 0.  Else, the check was determining if src and dst
    # were equal.
    if cpu_context.registers.zf:
        # Indicates emulation likely produced two operands which were equal, or an operand which was 0, so set the
        # alternate branch to equal the value of operand 1 + 1.  Or the comparison was to check if an operand was 0.
        # eg:  cmp    eax, 0x3D     ; eax = 0x3D
        #      cmp    eax, 0x00     ; eax = 0
        #      test   rax, rax      ; rax = 0
        cpu_context.jcccontext.condition_target_ea = jump_target
        # There is no need to check if the operands are the same here.  If the check was for equality, then adding
        # 1 to the second operand will make the check not equal.  If the check was for 0 (both operands were the same),
        # simply adding 1 to 0 will make the test fail.
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # Indicates emulation likely produced two operands which were not equal, or an operand which was not 0, so set
        # the alternate branch to equal the value of operand 1.  Or the comparison was to check if an operand was 0.
        # eg:  cmp    eax, 0x3D     ; eax = 0
        #      cmp    eax, 0x00     ; eax = 7
        #      test   rax, rax      ; rax = 10
        cpu_context.jcccontext.condition_target_ea = next_inst
        # Need to determine if both operands are the same.  If they are, then the check was actually to determine
        # if the value was 0.  In this case, to make the test succeed, just set the value to 0.  Otherwise the test
        # was to compare two different operands for equality, so just set the first operand to the value of the second.
        if operand0.text == operand1.text:
            cpu_context.jcccontext.alt_branch_data = 0
        else:
            cpu_context.jcccontext.alt_branch_data = operand1.value

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jg")
@opcode("jnle")
def JG_JNLE(cpu_context, ip, mnem, operands):
    """ Jump Greater / Jump Not Less or Equal (ZF=0 && SF=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than the second operand of the compare operation.
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf", "sf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.zf == 0 and cpu_context.registers.sf == cpu_context.registers.of:
        # opnd0 > opnd1 on this branch.  Set alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 <= opnd1on this branch.  Set alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jge")
@opcode("jnl")
def JGE_JNL(cpu_context, ip, mnem, operands):
    """ Jump Greater or Equal (SF=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than or equal to the second operand of the compare operation.
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["sf", "of"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.sf == cpu_context.registers.of:
        # opnd0 >= opnd1 on this branch. Set alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 < opnd1 on this branch. Set alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jl")
@opcode("jnge")
def JL_JNGE(cpu_context, ip, mnem, operands):
    """ Jump Less (SF!=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than the second operand of the compare operation.
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["sf", "of"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.sf != cpu_context.registers.of:
        # opnd0 < opnd1 on this branch.  Set alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd1 >= opnd1 on this branch.  Set alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jle")
@opcode("jng")
def JLE_JNG(cpu_context, ip, mnem, operands):
    """ Jump Less or Equal (ZF=1 || SF!=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than or equal to the second operand of the compare operation.
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    # Set the location where the condition we would take used based on our emulation
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf", "sf", "of"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.zf or cpu_context.registers.sf != cpu_context.registers.of:
        # opnd0 <= opnd2 on this branch.  Set alternate branch value opnd1 > opnd2
        cpu_context.jcccontext.condition_target_ea = jump_target
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 > opnd2 on this branch.  Set alternate branch value opnd0 <= opnd2
        cpu_context.jcccontext.condition_target_ea = next_inst
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jne")
@opcode("jnz")
def JNE_JNZ(cpu_context, ip, mnem, operands):
    """ Jump Not Equal (ZF=0) """
    # Whatever the operation, it either set ZF or it didn't... Typically, the assumption can probably be made that
    # either the operands were equal such that a subtraction resulted in 0, or they weren't.
    # TODO: Does the compare instruction have an effect on which operand is the value to be used?
    jump_target = operands[0].value
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    code_refs.remove(jump_target)
    next_inst = code_refs[0]

    ## Set the target for which to modify the context, it will be the only address left in code_refs
    test_operands = cpu_context.jcccontext.get_flag_opnds(["zf"])
    if len(test_operands) != 2:
        return

    operand0, operand1 = test_operands[:2]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    # There is additional logic that must be conducted for this jump.  If the src and dst operands are the same, then
    # the check was likely determine if the value was 0 or not 0.  Else, the check was determining if src and dst were
    # not equal.
    if not cpu_context.registers.zf:
        # Indicates emulation likely produced two operands which were not equal, or an operand which was not 0, so set
        # the alternate branch to equal the value of operand 1 (which would also be 0).  Or the comparison was to check
        # if an operand was 0.
        # eg:  cmp    eax, 0x3D     ; eax = 0
        #      cmp    eax, 0x00     ; eax = 7
        #      test   rax, rax      ; rax = 10
        cpu_context.jcccontext.condition_target_ea = jump_target
        # Need to determine if the operands are the same operand (indicating a test for 0).  If the operands are the
        # same operand, then set the value to 0.  If the operands were not the same operand, the test was for
        # equality, so set the values to the same value.
        if operand0.text == operand1.text:
            cpu_context.jcccontext.alt_branch_data = 0
        else:
            cpu_context.jcccontext.alt_branch_data = operand1.value
    else:
        # Indicates emulation likely produced two operands which were equal, or an operand was 0, so set the
        # alternate branch to the value of operand 1 + 1.  Or the comparison was to check if an operand was 0.
        # eg:  cmp    eax, 0x00     ; eax = 0
        #      cmp    eax, 0x3D     ; eax = 0x3D
        #      test   rax, rax      ; rax = 0
        cpu_context.jcccontext.condition_target_ea = next_inst
        # There is no need to check if the operands were the same.  If the operands were the same, the test was to
        # determine if the operand was 0, so just adding 1 to the operand will be enough to create the false condition.
        # If the operands weren't the same, the check was to determine if the operands were equal, so adding 1 to
        # the second operand will be enough to make the condition false.
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode
def JNO(cpu_context, ip, mnem, operands):
    """ Jump Not Overflow (OF=0) """
    pass

@opcode("jnp")
@opcode("jpo")
def JNP_JPO(cpu_context, ip, mnem, operands):
    """ Jump Not Parity (PF=0) """
    pass

@opcode
def JNS(cpu_context, ip, mnem, operands):
    """ Jump Not Sign (SF=0) """
    pass

@opcode
def JO(cpu_context, ip, mnem, operands):
    """ Jump Overflow (OF=1) """
    pass

@opcode("jp")
@opcode("jpe")
def JP_JPE(cpu_context, ip, mnem, operands):
    """ Jump Parity (PF=1) """
    pass

@opcode
def JS(cpu_context, ip, mnem, operands):
    """ Jump Sign (SF=1) """
    pass


@opcode
def LEA(cpu_context, ip, mnem, operands):
    """
    Handle the LEA instruction.
    """
    address = operands[1].addr
    logger.debug("{} 0x{:X} :: Copy address 0x{:X} into {}".format(mnem, ip, address, operands[0].text))
    operands[0].value = address


@opcode("mov")
@opcode("movzx")
@opcode("movapd")
@opcode("movaps")
@opcode("movdqa")
@opcode("movdqu")
@opcode("movupd")
@opcode("movups")
def _mov(cpu_context, ip, mnem, operands):
    """
    Handle the MOV, MOVZX, MOVA*, MOVD*, MOVU* instructions in the same manner.

    MOVZX is a zero extend, but this logic makes no real sense in python.

    NOTE: Since the widths are already taken into account when the operand values are retrieved
    or set, the logic for most mov* instructions are the same.
    """
    opvalue2 = operands[1].value
    logger.debug("{} 0x{:X} :: Copy {} into {}".format(mnem, ip, opvalue2, operands[0].text))
    operands[0].value = opvalue2


@opcode("movsx")
@opcode("movsxd")
def _movsx(cpu_context, ip, mnem, operands):
    """ Move with Sign Extend """
    opvalue2 = operands[1].value
    logger.debug("MOVSX 0x{:X} :: Sign-extend {} into {}".format(ip, opvalue2, operands[0].text))
    size = utils.sign_extend(opvalue2, operands[1].width, operands[0].width)
    operands[0].value = size


@opcode("movs")  # I don't believe IDA will ever use just "movs", but it's here just incase.
@opcode("movsb")
@opcode("movsw")
@opcode("movsd")
def movs(cpu_context, ip, mnem, operands):
    """
    Move Scalar Double-Precision Floating-Point Value
    OR
    Move Data from String to String
    """
    # movsd op1 op2
    if mnem == "movsd" and len(operands) == 2:
        op1, op2 = operands
        data = op2.value
        if op1.is_register:
            # When moving into an XMM register, the high 64 bits needs to remain untouched.
            data = (data & 0xFFFFFFFFFFFFFFFF0000000000000000) | data
        logger.debug("{} 0x{:X} :: {} -> {}".format(mnem, ip, op2.value, data))
        op1.value = data

    # movs*
    else:
        if cpu_context.bitness == 16:
            src = "SI"
            dst = "DI"
        else:
            src = "ESI"
            dst = "EDI"
        # IDA sometimes provides a single "fake" operand to help determine the size.
        width = operands[0].width if operands else 4

        size = {"movs": width, "movsb": 1, "movsw": 2, "movsd": 4}[mnem]
        src_ptr = cpu_context.registers[src]
        dst_ptr = cpu_context.registers[dst]
        logger.debug("{} 0x{:X} :: 0x{:X} -> 0x{:X}".format(mnem, ip, src_ptr, dst_ptr))
        cpu_context.mem_copy(src_ptr, dst_ptr, size)

        # update ESI/EDI registers
        if cpu_context.registers.df:
            cpu_context.registers[src] -= size
            cpu_context.registers[dst] -= size
        else:
            cpu_context.registers[src] += size
            cpu_context.registers[dst] += size


@opcode
def MOVD(cpu_context, ip, mnem, operands):
    """ Move Dword """
    opvalue2 = operands[1].value & 0xFFFFFFFF
    logger.debug("{} 0x{:X} :: Copy {} into {}".format(mnem, ip, opvalue2, operands[0].text))
    operands[0].value = opvalue2


@opcode
def MOVQ(cpu_context, ip, mnem, operands):
    """ Move Quadword """
    opvalue2 = operands[1].value & 0xFFFFFFFFFFFFFFFF
    logger.debug("{} 0x{:X} :: Copy {} into {}".format(mnem, ip, opvalue2, operands[0].text))
    operands[0].value = opvalue2


@opcode
def MUL(cpu_context, ip, mnem, operands):
    """ Multiplication """
    _mul(cpu_context, ip, mnem, operands)


@opcode
def NEG(cpu_context, ip, mnem, operands):
    """ Negate """
    opvalue1 = operands[0].value
    result = -opvalue1
    width = operands[0].width
    mask = utils.get_mask(width)

    cpu_context.registers.cf = int(result & mask != 0)
    cpu_context.registers.af = int(result & 0x0F != 0)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit(opvalue1, width) and not utils.sign_bit(result, width))
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of"], operands)

    logger.debug("NEG 0x{:X} :: {} - {}".format(ip, opvalue1, result))
    operands[0].value = result


@opcode
def NOT(cpu_context, ip, mnem, operands):
    """ NOT Logic Operator """
    opvalue1 = operands[0].value
    result = ~opvalue1
    logger.debug("NOT 0x{:X} :: {} -> {}".format(ip, opvalue1, result))
    operands[0].value = result


@opcode
def OR(cpu_context, ip, mnem, operands):
    """ OR Logic Operator """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 | opvalue2

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("OR 0x{:X} :: {} | {} = {}".format(ip, opvalue1, opvalue2, result))
    operands[0].value = result


@opcode
def POP(cpu_context, ip, mnem, operands):
    """ POP stack value """
    result = utils.struct_unpack(cpu_context.mem_read(cpu_context.registers.rsp, cpu_context.byteness))
    cpu_context.registers.rsp += cpu_context.byteness
    logger.debug("POP 0x{:X} :: Popped value {} into {}".format(ip, result, operands[0].text))
    operands[0].value = result


@opcode("popa")
@opcode("popad")
def POPA(cpu_context, ip, mnem, operands):
    """
    POPA (valid only for x86)

    NOTE: This function will return None.  This is one instance where accessing the registers directly makes more
            sense.
    """
    # We are using a helper function anyway, so we'll use the 64-bit names for the registers
    logger.debug("POPA 0x{:X}".format(ip))
    reg_order = ["EDI", "ESI", "EBP", "ESP", "EBX", "EDX", "ECX", "EAX"]
    for reg in reg_order:
        if reg == "ESP":
            # Skip next 4 or 2 bytes
            if mnem == "popad":
                cpu_context.registers.esp += 4
            else:
                cpu_context.registers.esp += 2
        else:
            # reg <- Pop()
            val = utils.struct_unpack(cpu_context.mem_read(cpu_context.registers.esp, cpu_context.byteness))
            cpu_context.registers[reg] = val
            cpu_context.registers.esp += 4


@opcode
def PUSH(cpu_context, ip, mnem, operands):
    """ PUSH """
    operand = operands[0]
    logger.debug("PUSH 0x{:X} :: Pushing {} onto stack".format(ip, operand.value))
    cpu_context.registers.rsp -= cpu_context.byteness
    cpu_context.mem_write(cpu_context.registers.esp, utils.struct_pack(operand.value, width=operand.width))

@opcode
def PUSHA(cpu_context, ip, mnem, operands):
    """
    PUSHA (valid only for x86)
    """
    reg_order = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
    # Store the original ESP value to push
    orig_esp = cpu_context.registers.esp
    logger.debug("PUSHA 0x{:X}".format(ip))
    for reg in reg_order:
        cpu_context.registers.esp -= 4
        pushed_value = orig_esp if reg == "ESP" else cpu_context.registers[reg]
        logger.debug("PUSHA 0x{:X} :: Pushing {} onto stack".format(ip, pushed_value))
        cpu_context.mem_write(cpu_context.registers.esp, utils.struct_pack(pushed_value))


@opcode
def RCR(cpu_context, ip, mnem, operands):
    """ Rotate Carry Right """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 9, 17, 33 when the width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F) % ((width * 8) + 1)
    else:
        # This is undefined behavior
        return

    if opvalue2 == 1:
        cpu_context.registers.of = get_msb(opvalue1, width) ^ cpu_context.registers.cf

    while tempcount:
        tempcf = get_lsb(opvalue2)
        opvalue1 = (opvalue1 / 2) + (cpu_context.registers.cf * 2 ** width)
        cpu_context.registers.cf = tempcf
        tempcount -= 1

    cpu_context.jcccontext.update_flag_opnds(["cf"], operands)
    logger.debug("RCR 0x{:X} :: Rotate {} right by {} -> {}".format(
        ip,
        operands[0].value,
        opvalue2,
        opvalue1)
    )
    operands[0].value = opvalue1


@opcode
def RCL(cpu_context, ip, mnem, operands):
    """ Rotate Carry Left """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 9, 17, 33 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F) % ((width * 8) + 1)
    else:
        # This is undefined behavior
        return

    while tempcount:
        tempcf = get_msb(opvalue1, width)
        opvalue1 = (opvalue1 * 2) + cpu_context.registers.cf
        cpu_context.registers.cf = tempcf
        tempcount -= 1

    if opvalue2 == 1:
        cpu_context.registers.of = get_msb(opvalue1, width) ^ cpu_context.registers.cf

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("RCL 0x{:X} :: Rotate {} left by {} -> {}".format(
        ip,
        operands[0].value,
        opvalue2,
        opvalue1)
    )
    operands[0].value = opvalue1


@opcode
def ROL(cpu_context, ip, mnem, operands):
    """ Rotate Left """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 8, 16, 32 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F) % (width * 8)
    else:
        # This is undefined behavior
        return

    if tempcount > 0:
        while tempcount:
            tempcf = get_msb(opvalue1, width)
            opvalue1 = (opvalue1 * 2) + tempcf
            tempcount -= 1

        cpu_context.registers.cf = get_lsb(opvalue1)
        if opvalue2 == 1:
            cpu_context.registers.of = get_msb(opvalue1, width) ^ cpu_context.registers.cf

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("ROL 0x{:X} :: Rotate {} left by {} -> {}".format(
        ip,
        operands[0].value,
        opvalue2,
        opvalue1)
    )
    operands[0].value = opvalue1


@opcode
def ROR(cpu_context, ip, mnem, operands):
    """ Rotate Right """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 8, 16, 32 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F) % (width * 8)
    else:
        # This is undefined behavior
        return

    if tempcount > 0:
        while tempcount:
            tempcf = get_lsb(opvalue2)
            opvalue1 = (opvalue1 / 2) + (tempcf * 2 ** width)
            tempcount -= 1

        cpu_context.registers.cf = get_msb(opvalue1, width)
        if opvalue2 == 1:
            cpu_context.registers.of = get_msb(opvalue1, width) ^ (get_msb(opvalue1, width) - 1)

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("ROR 0x{:X} :: Rotate {} right by {} -> {}".format(
        ip,
        operands[0].value,
        opvalue2,
        opvalue1)
    )
    operands[0].value = opvalue1


@opcode("sal")
@opcode("shl")
def sal_shl(cpu_context, ip, mnem, operands):
    """ Shift Arithmetic Left """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1

    if opvalue2:
        tempcount = opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F  # 0x3F Because we want to allow for 64-bit code
        while tempcount:
            cpu_context.registers.cf = get_msb(result, width)
            result *= 2
            tempcount -= 1

        result &= utils.get_mask(width)

        bit_count = width * 8
        if opvalue2 <= bit_count:
            cpu_context.registers.cf = (opvalue1 >> (bit_count - opvalue2)) & 0x01
        else:
            cpu_context.registers.cf = 0
        cpu_context.registers.sf = utils.sign_bit(result, width)
        if opvalue2 == 1:
            cpu_context.registers.of = utils.sign_bit(opvalue1 ^ result, width)
        else:
            cpu_context.registers.of = utils.sign_bit((opvalue1 << (opvalue2 - 1)) ^ result, width)

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], operands)
    logger.debug("SAL 0x{:X} :: Shift {} left by {} -> {}".format(ip, opvalue1, opvalue2, result))
    operands[0].value = result


@opcode
def SAR(cpu_context, ip, mnem, operands):
    """ Shift Arithmetic Right """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1
    if opvalue2:
        tempcount = opvalue2 & 0x3F if cpu_context.bitness == 64 else 0x1F  # 0x3F Because we want to allow for 64-bit code
        msb = get_msb(opvalue1, cpu_context.byteness)
        while tempcount:
            cpu_context.registers.cf = get_lsb(result)
            result = result / 2
            tempcount -= 1

        bit_count = width * 8
        if opvalue2 < bit_count:
            cpu_context.registers.cf = (opvalue1 >> (opvalue2 - 1)) & 0x01
        else:
            cpu_context.registers.cf = utils.sign_bit(opvalue1, width)
        cpu_context.registers.zf = int(result == 0)
        cpu_context.registers.sf = utils.sign_bit(result, width)
        cpu_context.registers.of = 0
        cpu_context.registers.pf = get_parity(result)

        result |= (msb << cpu_context.bitness)

    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)
    logger.debug("SAR 0x{:X} :: Shift {} right by {} -> {}".format(ip, opvalue1, opvalue2, result))
    operands[0].value = result


@opcode
def SBB(cpu_context, ip, mnem, operands):
    """ Subtract with Borrow/Carry """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 - (opvalue2 + cpu_context.registers.cf)

    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], operands)
    logger.debug("SBB 0x{:X} :: {} - {} = {}".format(
        ip, opvalue1, (opvalue2 + cpu_context.registers.cf), result))
    operands[0].value = result


# TODO: Do we need SCAS* implemented????


@opcode
def SETNA(cpu_context, ip, mnem, operands):
    """ Set if Not Above """
    result = int(cpu_context.registers.zf or cpu_context.registers.cf)
    logger.debug("SETNA 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETLE(cpu_context, ip, mnem, operands):
    """ Set if Less than or Equal """
    result = int(cpu_context.registers.zf or (cpu_context.registers.sf != cpu_context.registers.of))
    logger.debug("SETLE 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETGE(cpu_context, ip, mnem, operands):
    """ Set if Greater than or Equal """
    result = int(cpu_context.registers.sf == cpu_context.registers.of)
    logger.debug("SETGE 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETG(cpu_context, ip, mnem, operands):
    """ Set if Greather than """
    result = int(cpu_context.registers.zf and (cpu_context.registers.sf == cpu_context.registers.of))
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETE(cpu_context, ip, mnem, operands):
    """ Set if Equal """
    result = int(cpu_context.registers.zf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, operands[0].text, result))
    operands[0].value = result
    # cpu_context.set_operand_value(0, result)


@opcode
def SETC(cpu_context, ip, mnem, operands):
    """ Set if Carry """
    result = int(cpu_context.registers.cf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETBE(cpu_context, ip, mnem, operands):
    """ Set if Below or Equal """
    result = int(cpu_context.registers.cf and cpu_context.registers.zf)
    logger.debug("SETBE 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETB(cpu_context, ip, mnem, operands):
    """ Set if Below """
    SETC(cpu_context, ip, mnem, operands)


@opcode
def SETAE(cpu_context, ip, mnem, operands):
    """ Set if Above or Equal """
    SETC(cpu_context, ip, mnem, operands)


@opcode
def SETA(cpu_context, ip, mnem, operands):
    """ Set if Above """
    result = int(not (cpu_context.registers.cf | cpu_context.registers.zf))
    logger.debug("SETA 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETPS(cpu_context, ip, mnem, operands):
    """ Set if Not??? Parity """
    result = int(cpu_context.registers.sf)
    logger.debug("SETPS 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETPO(cpu_context, ip, mnem, operands):
    """ Set if Parity Odd """
    result = int(cpu_context.registers.pf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETPE(cpu_context, ip, mnem, operands):
    """ Set if Parity Event """
    SETPO(cpu_context, ip, mnem, operands)


@opcode
def SETP(cpu_context, ip, mnem, operands):
    """ Set if Parity """
    SETPO(cpu_context, ip, mnem, operands)


@opcode
def SETO(cpu_context, ip, mnem, operands):
    """ Set if Overflow """
    result = int(cpu_context.registers.of)
    logger.debug("SETO 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNS(cpu_context, ip, mnem, operands):
    """ Set if Not Sign """
    result = int(not cpu_context.registers.sf)
    logger.debug("SETNS 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNP(cpu_context, ip, mnem, operands):
    """ Set if Not Parity """
    result = int(not cpu_context.registers.pf)
    logger.debug("SETNP 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNO(cpu_context, ip, mnem, operands):
    """ Set if Not Overflow """
    result = int(not cpu_context.registers.of)
    logger.debug("SETNO 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNL(cpu_context, ip, mnem, operands):
    """ Set if Not Less """
    result = int(cpu_context.registers.sf == cpu_context.registers.of)
    logger.debug("SETNL 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result
    # cpu_context.set_operand_value(0, result)


@opcode
def SETNGE(cpu_context, ip, mnem, operands):
    """ Set if Not Greater Than or Equal """
    result = int(cpu_context.registers.sf != cpu_context.registers.of)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNG(cpu_context, ip, mnem, operands):
    """ Set if Not Greater """
    result = int(cpu_context.registers.zf or (cpu_context.registers.sf != cpu_context.registers.of))
    logger.debug("SETNG 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNE(cpu_context, ip, mnem, operands):
    """ Set if Not Equal """
    result = int(not cpu_context.registers.zf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNC(cpu_context, ip, mnem, operands):
    """ Set if Not Carry """
    result = int(not cpu_context.registers.cf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNBE(cpu_context, ip, mnem, operands):
    """ Set if Not Below or Equal """
    result = int(not (cpu_context.registers.cf | cpu_context.registers.zf))
    logger.debug("SETNBE 0x{:X} :: Setting {} to {}".format(ip, operands[0].text, result))
    operands[0].value = result


@opcode
def SETNB(cpu_context, ip, mnem, operands):
    """ Set if Not Below """
    SETNC(cpu_context, ip, mnem, operands)


@opcode
def SETNAE(cpu_context, ip, mnem, operands):
    """ Set if Not Above or Equal """
    SETC(cpu_context, ip, mnem, operands)


@opcode
def SETL(cpu_context, ip, mnem, operands):
    """ Set if Less Than """
    SETNGE(cpu_context, ip, mnem, operands)


@opcode
def SETNLE(cpu_context, ip, mnem, operands):
    """ Set if Not Less Than or Equal """
    SETG(cpu_context, ip, mnem, operands)


@opcode
def SETNZ(cpu_context, ip, mnem, operands):
    """ Set if Not Zero """
    SETNE(cpu_context, ip, mnem, operands)


@opcode
def SETZ(cpu_context, ip, mnem, operands):
    """ Set if Zero """
    SETE(cpu_context, ip, mnem, operands)


@opcode
def SHR(cpu_context, ip, mnem, operands):
    """ Shift Right """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)

    if not opvalue2:
        return

    result = opvalue1
    tempcount = opvalue2 & (0x3F if cpu_context.bitness == 64 else 0x1F)
    while tempcount:
        cpu_context.registers.cf = get_lsb(result)
        result /= 2
        tempcount -= 1

    cpu_context.registers.cf = (opvalue1 >> (opvalue2 - 1)) & 0x01
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    if opvalue2 == 1:
        cpu_context.registers.of = utils.sign_bit(opvalue1, width)
    else:
        cpu_context.registers.of = 0

    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)
    logger.debug("SHR 0x{:X} :: Shift {} right by {} -> {}".format(ip, opvalue1, opvalue2, result))
    operands[0].value = result


@opcode("stosb")
@opcode("stosw")
@opcode("stosd")
@opcode("stosq")
def STOSx(cpu_context, ip, mnem, operands):
    """ STOre value in {R,E}AX, AX, AL in the address pointed to by {R,E}DI"""
    # Make a mapping for the opcode to define what registers we are working with.
    RAX_REG_SIZE_MAP = {8: "RAX", 4: "EAX", 2: "AX", 1: "AL"}
    RDI_REG_SIZE_MAP = {8: "RDI", 4: "EDI"}

    # Recreate the dst and src operands, since IDA hides them.
    # (We can't use operands, because they are fake and hidden.)
    dst_opnd = Operand(cpu_context, ip, 0)
    dst_opnd.text = RDI_REG_SIZE_MAP.get(dst_opnd.width, "EDI")
    dst_opnd.type = idc.o_reg
    src_opnd = Operand(cpu_context, ip, 1)
    src_opnd.text = RAX_REG_SIZE_MAP[src_opnd.width]
    src_opnd.type = idc.o_reg

    logger.debug("{} 0x{:X} :: Storing {} at 0x{}".format(mnem, ip, src_opnd.value, dst_opnd.value))
    data = utils.struct_pack(src_opnd.value, width=src_opnd.width)
    cpu_context.mem_write(dst_opnd.value, data)
    if cpu_context.registers.df:
        dst_opnd.value -= src_opnd.width
    else:
        dst_opnd.value += src_opnd.width


@opcode
def SUB(cpu_context, ip, mnem, operands):
    """ Subtract """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 - opvalue2

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("SUB 0x{:X} :: {} - {} = {}".format(ip, opvalue1, opvalue2, result))
    operands[0].value = result


@opcode
def TEST(cpu_context, ip, mnem, operands):
    """ Test values for equality """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 & opvalue2

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], operands)

    logger.debug("TEST 0x{:X} :: {} & {} -> {}".format(ip, opvalue1, opvalue2, result))


@opcode
def XCHG(cpu_context, ip, mnem, operands):
    """ Exchange two values """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    logger.debug("XCHG 0x{:X} :: exchange {} and {}".format(ip, opvalue1, opvalue2))
    operands[1].value = opvalue1
    operands[0].value = opvalue2


@opcode("xor")
@opcode("pxor")
def _xor(cpu_context, ip, mnem, operands):
    """ XOR """
    opvalue1 = operands[0].value
    opvalue2 = operands[1].value
    width = get_max_operand_size(operands)
    result = opvalue1 ^ opvalue2

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], operands)

    logger.debug("{} 0x{:X} :: {} ^ {} = {}".format(mnem, ip, opvalue1, opvalue2, result))
    operands[0].value = result


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


def get_msb(value, size):
    """
    Get most significant bit.

    :param value: value to obtain msb from

    :size: bit width of value in bytes

    :return: most significant bit
    """
    return value >> ((8 * size) - 1)


def get_lsb(value):
    """
    Get least significant bit.

    :param value: value to obtain lsb from

    :return: least significant bit
    """
    return value & 0x1


def swap_bytes(value, size):
    """
    Swaps a set of bytes based on size

    :param value: value to swap

    :param size: width of value in bytes

    :return: swapped
    """
    if size == 1:
        return value

    if size == 2:
        return ((value & 0xFF) << 8) | ((value & 0xFF00) >> 8)

    if size == 4:
        return (((value & 0xFF) << 24) | (((value & 0xFF00) >> 8) << 16) |
                (((value & 0xFF0000) >> 16) << 8) | ((value & 0xFF000000) >> 24))

    if size == 8:
        return (((value & 0xFF) << 56) | (((value & 0xFF00) >> 8) << 48) |
                (((value & 0xFF0000) >> 16) << 40) | (((value & 0xFF000000) >> 24) << 32) |
                (((value & 0xFF00000000) >> 32) << 24) | (((value & 0xFF0000000000) >> 40) << 16) |
                (((value & 0xFF000000000000) >> 48) << 8) | ((value & 0xFF00000000000000) >> 56))


parity_lookup_table = [
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
]


def get_parity(value):
    """Returns the parity of the given value."""
    return parity_lookup_table[value & 0xFF]
