"""
CPU EMULATOR HANDLED INSTRUCTIONS

Add any instructions that need to be handled below.  The function should be declared as such

# Using the same function for multiple instructions:
@opcode("add")
@opcode("adc")
def _add(cpu_context, ip, mnem, opvalues):
    print "IN ADD"

# Using a single function for an opcode
@opcode
def MOV(cpu_context, ip, mnem, opvalues):
    print "IN MOV"

WARNING:
    Do NOT rely on the flags registers being correct.  There are places were flags are NOT being updated when they
    should, and the very fact that CALL instructions are skipped could cause flags to be incorrect.
"""

import logging

import idc
import idaapi
import idautils

from . import utils
from .cpu_emulator import opcode, get_max_operand_size, get_min_operand_size, BUILTINS


logger = logging.getLogger(__name__)



@opcode("adc")
@opcode("add")
def _add(cpu_context, ip, mnem, opvalues):
    """
    Handle both ADC and ADD here since the only difference is the flags.
    """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    result = opvalue1 + opvalue2
    if mnem == "adc":
        result += cpu_context.registers.cf
    width = get_max_operand_size(opvalues)

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int(result > mask)
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit(~(opvalue1 ^ opvalue2) & (opvalue2 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("{} 0x{:X} :: {} + {} = {}".format(mnem, ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result & mask, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def AND(cpu_context, ip, mnem, opvalues):
    """ AND logic operator """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    result = opvalue1 & opvalue2
    width = get_max_operand_size(opvalues)

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("AND 0x{:X} :: {} & {} = {}".format(ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def BSWAP(cpu_context, ip, mnem, opvalues):
    """ byte Swap """
    opvalue1 = opvalues[0].value
    width = opvalues[0].width
    result = swap_bytes(opvalue1, width)
    logger.debug("BSWAP 0x{:X} :: {} -> {}".format(ip, opvalue1, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def CALL(cpu_context, ip, mnem, opvalues):
    """
    CALL function

    Attempt to determine the number of arguments passed to the function which are purged on return
    """
    func_ea = opvalues[0].value

    if not isinstance(func_ea, (int, long)):
        logger.debug("CALL 0x{:X} :: call {!r}".format(ip, func_ea))
        logger.debug("Invalid function: {!r}".format(func_ea))
        return

    # For the called function, attempt to locate the function end and examine the "retn" instruction which
    # will contain the number of bytes to add back to SP.
    # opvalue1 = idc.get_operand_value(ip, 0)
    logger.debug("CALL 0x{:X} :: call 0x{:X}".format(ip, func_ea))

    try:
        is_loaded = idc.is_loaded(func_ea)
    except TypeError:
        is_loaded = False

    # TODO: Disabled until we can keep track of pointer history.
    # # Emulate the effects of any known builtin functions.
    # func_name = idaapi.get_func_name(func_ea)
    # builtin_func = BUILTINS.get(func_name)
    # if builtin_func:
    #     try:
    #         args = cpu_context.get_function_args(func_ea)
    #         builtin_func(cpu_context, ip, func_name, args)
    #     except Exception as e:
    #         cpu_logger.warn(
    #             'Failed to emulate builtin function: {}() at {:#08x} with error: {}'.format(
    #                 func_name, ip, e))

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
                    cpu_context.reg_write("RSP", cpu_context.reg_read("RSP") + cpu_context._byteness)
        except:
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
            logger.debug(
                "{:#08x} :: Could not retrieve retn instruction for called function: {:#08x}. "
                "Stack pointer will not be adjusted.".format(ip, func_ea))
            return

        # Find a "retn" and see if we need to adjust rsp.
        # (All retn's should have the same operand so finding any of them will work).
        # look for retn address
        ea = func_end
        while ea > func_ea:
            if idc.print_insn_mnem(ea) == "retn":
                sp_adjust = idc.get_operand_value(ea, 0)
                # if retn doesn't adjust the stack, -1 is returned
                if sp_adjust != -1:
                    cpu_context.reg_write("RSP", cpu_context.reg_read("RSP") + sp_adjust)
                return
            ea = idc.prev_head(ea)


@opcode
def CDQ(cpu_context, ip, mnem, opvalues):
    """ Convert DWORD to QWORD with sign extension """
    opvalue1 = cpu_context.reg_read("EAX")
    if opvalue1 >> 31:
        result = 0xFFFFFFFF
    else:
        result = 0x0

    logger.debug("CDQ 0x{:X} :: Setting register EDX to 0x{:X}".format(ip, result))
    cpu_context.reg_write("EDX", result)


@opcode
def CLC(cpu_context, ip, mnem, opvalues):
    """ Clear Carry Flag """
    cpu_context.registers.cf = 0


@opcode
def CLD(cpu_context, ip, mnem, opvalues):
    """ Clear Direction Flag """
    cpu_context.registers.df = 0


@opcode
def CMP(cpu_context, ip, mnem, opvalues):
    """ Compare to values """
    width = get_min_operand_size(opvalues)
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    result = opvalue1 - opvalue2

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("CMP 0x{:X} :: {} <-> {} = {}".format(ip, opvalue1, opvalue2, result))


@opcode
def CMPS(cpu_context, ip, mnem, opvalues):
    """
    Nothing really to do for CMPS
    """
    pass


@opcode
def CMPSB(cpu_context, ip, mnem, opvalues):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CMPSW(cpu_context, ip, mnem, opvalues):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CMPSD(cpu_context, ip, mnem, opvalues):
    """
    TODO: Does this really need to be implemented for our purposes???
    """
    pass


@opcode
def CVTDQ2PD(cpu_context, ip, mnem, opvalues):
    """ Convert Packed Doubleword Integers to Packed Double-Precision Floating-Point Values """
    opvalue2 = opvalues[1].value
    dword0 = opvalue2 & 0xFFFFFFFF
    dword1 = (opvalue2 & 0xFFFFFFFF) >> 32
    dpfp0 = utils.float_to_int(dword0)
    dpfp1 = utils.float_to_int(dword1)
    result = (dpfp1 << 64) | dpfp0
    logger.debug("{} 0x{:X} :: {} -> {}, {} -> {} --> {}".format(mnem, ip, dword0, dpfp0, dword1, dpfp1, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def CVTSI2SD(cpu_context, ip, mnem, opvalues):
    """ Convert Doubleword Int to Scalar Double-Precision Floating-Point """
    opvalue2 = opvalues[1].value
    width = opvalues[1].width
    result = utils.float_to_int(opvalue2)
    logger.debug("{} 0x{:X} :: int {} -> float equivalent {}".format(mnem, ip, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def CVTTSD2SI(cpu_context, ip, mnem, opvalues):
    """ Convert with Truncation Scalar Double-Precision Floating-Point Value to Signed Integer """
    opvalue2 = opvalues[1].value
    width = opvalues[0].width
    result = int(utils.int_to_float(opvalue2))
    logger.debug("{} 0x{:X} :: float {} -> int equivalent {}".format(mnem, ip, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def DEC(cpu_context, ip, mnem, opvalues):
    """ Decrement """
    opvalue1 = opvalues[0].value
    width = opvalues[0].width
    mask = utils.get_mask(width)
    result = opvalue1 - 1

    cpu_context.registers.af = int(result & 0x0F == 0x0F)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(
        utils.sign_bit(opvalue1, width) and not utils.sign_bit(result, width))
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("DEC 0x{:X} :: {} - 1 = {}".format(ip, opvalue1, result))
    cpu_context.set_operand_value(ip, result & mask, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode("div")
@opcode("idiv")
def DIV(cpu_context, ip, mnem, opvalues):
    """
    Divide

    NOTE: op1 / op2
    """
    RAX_REG_SIZE_MAP = {8: "RAX", 4: "EAX", 2: "AX", 1: "AL"}
    RDX_REG_SIZE_MAP = {8: "RDX", 4: "EDX", 2: "DX"}
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    # We actually need to do some doctoring with DIV as operand 0 is implied as the EAX register of
    # a certain size.
    opvalue1 = cpu_context.reg_read(RAX_REG_SIZE_MAP[width])
    if opvalue2 != 0:
        result = (opvalue1 / opvalue2) & utils.get_mask(width)
        remainder = (opvalue1 % opvalue2) & utils.get_mask(width)
        logger.debug("DIV 0x{:X} :: {} / {} = {}".format(ip, opvalue1, opvalue2, result))
        if width == 1:
            # Result stored in AL, remainder stored in AH
            result = ((remainder << 8) | result)
            cpu_context.set_operand_value(ip, result, RAX_REG_SIZE_MAP[width], idc.o_reg)
        else:
            cpu_context.set_operand_value(ip, result, RAX_REG_SIZE_MAP[width], idc.o_reg)
            cpu_context.set_operand_value(ip, remainder, RDX_REG_SIZE_MAP[width], idc.o_reg)

    else:
        # Log the instruction for a DIV / 0 error
        logger.debug("{} 0x{:X} :: DIV / 0".format(mnem, ip))


@opcode
def DIVSD(cpu_context, ip, mnem, opvalues):
    """
    Divide Scalar Double-Precision Floating-Point Value

    op1 / op2 -> op1
    """
    opvalue1 = utils.int_to_float(opvalues[0].value)
    opvalue2 = utils.int_to_float(opvalues[1].value)
    # Because there is no guarantee that the registers/memory have been properly initialized, ignore DIV / 0 errors.
    if opvalue2 != 0:
        result = opvalue1 / opvalue2
        logger.debug("{} 0x{:X} :: {} / {} = {}".format(mnem, ip, opvalue1, opvalue2, result))
        result = utils.float_to_int(result)
        cpu_context.set_operand_value(
            ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0), width=opvalues[1].width)

    else:
        # Log DIV / 0 error
        logger.debug("{} 0x{:X} :: DIV / 0".format(mnem, ip))


def _mul(cpu_context, ip, mnem, opvalues):
    """
    Handle MUL instruction and 1-operand IMUL instruction as the same.
    """
    RAX_REG_SIZE_MAP = {8: "RAX", 4: "EAX", 2: "AX", 1: "AL"}
    RDX_REG_SIZE_MAP = {8: "RDX", 4: "EDX", 2: "DX"}

    # Sanitize our opvalues list by removing any None values.
    opvalues = [opvalue for opvalue in opvalues if opvalue.value is not None]
    dx_reg = None
    dx_result = None
    width = get_max_operand_size(opvalues)
    mask = utils.get_mask(width)
    multiplier1 = cpu_context.reg_read(RAX_REG_SIZE_MAP[width])
    multiplier2 = opvalues[0].value
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

    cpu_context.jcccontext.update_flag_opnds(flags, opvalues)
    logger.debug("{} 0x{:X} :: {} * {} = {} || EAX -> {} || EDX -> {}".format(
        mnem.upper(),
        ip, multiplier1,
        multiplier2,
        result,
        ax_result,
        dx_result if dx_reg else ''))
    cpu_context.set_operand_value(ip, ax_result, ax_reg, idc.o_reg)
    if dx_reg:
        cpu_context.set_operand_value(ip, dx_result, dx_reg, idc.o_reg)

# TODO: Clean up mul, imul, and _mul
@opcode
def IMUL(cpu_context, ip, mnem, opvalues):
    """ Signed Multiplication

    ; Single operand form
    imul    ecx     ; Signed multiply the value in ecx with the value in eax (et.al)
                    ; IDA will identify 2 operands, but only operand 1 will contain a value so 0 and 2 will be None

    ; Two operand form
    imul    edi, edx    ; Signed multiply the destination operand (op 0) with the source operand (op 1)
                        ; IDA will identify 3 operands, but operand 2 will be None

    ; Three operand form
    imul    eax, edi, 5 ; Signed multiple source operand (op 1) with the immediate value (op 2) and store in
                        ; the destination operand (op 0)

    """

    # IDA is awesome in the fact that it isn't consistent as to what operands are assigned values.  One instance it
    # may be operand 0 and 1, another might be 0 and 2, etc...However, since we are assigning a None to operands where
    # idc.print_operand returns "" (an empty string), then we can just remove all the opvalue list items which have a value
    # of None and this will give us our number of operands.
    RAX_REG_SIZE_MAP = {8: "RAX", 4: "EAX", 2: "AX", 1: "AL"}
    width = get_max_operand_size(opvalues)
    opvalues = [opvalue for opvalue in opvalues if opvalue.value is not None]
    op_count = len(opvalues)
    if op_count == 1:
        # if opvalues[0].value is None and opvalues[2].value is None: # Single operand form
        _mul(cpu_context, ip, mnem, opvalues)
        return
    # else:
    #    if opvalues[0].value and opvalues[1].value and opvalues[2].value is None: # Two operand form
    elif op_count == 2:
        destination = idc.print_operand(ip, 0)
        multiplier1 = opvalues[0].value
        multiplier2 = opvalues[1].value
        # elif opvalues[0].value and opvalues[1].value and opvalues[2].value: # Three operand form
    elif op_count == 3:
        destination = idc.print_operand(ip, 0)
        multiplier1 = opvalues[1].value
        multiplier2 = opvalues[2].value
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
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("IMUL 0x{:X} :: {} * {} = {}".format(ip, multiplier1, multiplier2, result))
    # Notably, IDA knows that EAX is the destination for the single operand form, and properly returns
    # idc.o_reg for idc.get_operand_type (though for IMUL the destination MUST be a register, so it could technically
    # be hard coded here...
    cpu_context.set_operand_value(ip, result, destination, idc.get_operand_type(ip, 0))


@opcode
def INC(cpu_context, ip, mnem, opvalues):
    """ Increment """
    opvalue1 = opvalues[0].value
    logger.debug("INC 0x{:X} :: {} + 1 = {}".format(ip, opvalue1, opvalue1 + 1))
    cpu_context.set_operand_value(ip, opvalue1 + 1, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))

    result = opvalue1 + 1
    width = opvalues[0].width
    mask = utils.get_mask(width)

    cpu_context.registers.af = int(result & 0x0F == 0)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(
        not utils.sign_bit(opvalue1, width) and utils.sign_bit(result, width))
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], opvalues)


# TODO: Not all Jcc instructions are implemented here.

# For the following jump instructions, the logic is basically the same
#   1. Get all the CodeRefs from the current IP (should only ever be 2)
#   2. Remove the EA that is the target of the Jcc instruction to we know where the non-jump target is
#   3. Determine the location where our condition takes us and set condition_target_ea to that
#   4. Set the value for the alternet path
# Note that since we aren't currently handling instructions which may cause conditional jumps, we need to
# determine if we have test_opnds and abort fixing the context if we don't.
@opcode("ja")
@opcode("jnbe")
def JA_JNBE(cpu_context, ip, mnem, opvalues):
    """ Jump Above (CF=0 && ZF=0) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition would take use based on our emulation and the value for the alt branch
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["cf", "zf"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf == 0 and cpu_context.registers.zf == 0:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 <= opnd1 on this branch. Set the alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))

@opcode("jae")
@opcode("jnb")
@opcode("jnc")
def JAE_JNB(cpu_context, ip, mnem, opvalues):
    """ Jump Above or Equal / Jump Not Below / Jump Not Carry (CF=0) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than or equal to the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition would take use based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["cf"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf == 0:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 < opnd1 on this branch. Set the alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jb")
@opcode("jc")
@opcode("jnae")
def JB_JNAE(cpu_context, ip, mnem, opvalues):
    """ Jump Below / Jump Carry / Jump Not Above or Equal (CF=1) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition would take use based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["cf"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf:
        # opnd0 < opnd1 on this branch.  Set the alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 >= opnd1 on this branch. Set the alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jbe")
@opcode("jna")
def JBE_JNA(cpu_context, ip, mnem, opvalues):
    """ Jump Below or Equal / Jump Not Above (CF=1 || ZF=1) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than or equal to the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition would take use based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["cf", "zf"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.cf or cpu_context.registers.zf:
        # opnd0 <= opnd1 on this branch.  Set the alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 > opnd1 on this branch.  Set the alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("je")
@opcode("jz")
def JE_JZ(cpu_context, ip, mnem, opvalues):
    """ Jump Equal / Jump Zero (ZF=1) """
    # Jump target contains the known data which is either 0 or the value of the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition would take use based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["zf"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.zf:
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        # if JZ, that means our values were 0, so make opnd0 != 0
        if mnem == "jz":
            cpu_context.jcccontext.alt_branch_data = 1
        # if JE, then opnd0 == opnd1, so make opnd0 != opnd1
        else:
            cpu_context.jcccontext.alt_branch_data = operand0.value + 1
    else:
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        # if JZ, that means our values weren't 0, so make opnd0 == 0
        if mnem == "jz":
            cpu_context.jcccontext.alt_branch_data = 0
        # if JE, opnd0 != opnd1, so make opnd0 == opnd1
        else:
            cpu_context.jcccontext.alt_branch_data = operand1.value

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jg")
@opcode("jnle")
def JG_JNLE(cpu_context, ip, mnem, opvalues):
    """ Jump Greater / Jump Not Less or Equal (ZF=0 && SF=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition we would take used based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["zf", "sf"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.zf == 0 and cpu_context.registers.sf == cpu_context.registers.of:
        # opnd0 > opnd1 on this branch.  Set alternate branch value opnd0 <= opnd1
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.vlaue - 1
    else:
        # opnd0 <= opnd1on this branch.  Set alternate branch value opnd0 > opnd1
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jge")
@opcode("jnl")
def JGE_JNL(cpu_context, ip, mnem, opvalues):
    """ Jump Greater or Equal (SF=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is larger than or equal to the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition we would take used based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["sf", "of"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.sf == cpu_context.registers.of:
        # opnd0 >= opnd1 on this branch. Set alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1
    else:
        # opnd0 < opnd1 on this branch. Set alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jl")
@opcode("jnge")
def JL_JNGE(cpu_context, ip, mnem, opvalues):
    """ Jump Less (SF!=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition we would take used based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["sf", "of"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.sf != cpu_context.registers.of:
        # opnd0 < opnd1 on this branch.  Set alternate branch value opnd0 >= opnd1
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd1 >= opnd1 on this branch.  Set alternate branch value opnd0 < opnd1
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jle")
@opcode("jng")
def JLE_JNG(cpu_context, ip, mnem, opvalues):
    """ Jump Less or Equal (ZF=1 || SF!=OF) """
    # Don't know the data for either path specifically, but inferences can be made that the jump target will contain
    # a value in the first operand that is less than or equal to the second operand of the compare operation.
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    # Set the location where the condition we would take used based on our emulation
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["zf", "sf", "of"])
    if not test_opvalues:
        return

    operand0, operand1 = test_opvalues[0], test_opvalues[1]
    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if cpu_context.registers.zf or cpu_context.registers.sf != cpu_context.registers.of:
        # opnd0 <= opnd2 on this branch.  Set alternate branch value opnd1 > opnd2
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        cpu_context.jcccontext.alt_branch_data = operand1.value + 1
    else:
        # opnd0 > opnd2 on this branch.  Set alternate branch value opnd0 <= opnd2
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        cpu_context.jcccontext.alt_branch_data = operand1.value - 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{:X} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode("jne")
@opcode("jnz")
def JNE_JNZ(cpu_context, ip, mnem, opvalues):
    """ Jump Not Equal (ZF=0) """
    # Jump target contains unknown data.  Non-jump path contains either 0 or the value of the second operand of the
    # compare operation.
    # TODO: Does the compare instruction have an effect on which operand is the value to be used?
    code_refs = list(idautils.CodeRefsFrom(ip, 1))
    # Remove the EA of the path for which we won't know what the value should be (the target of the jmp)
    code_refs.remove(opvalues[0].value)
    ## Set the target for which to modify the context, it will be the only address left in code_refs
    test_opvalues = cpu_context.jcccontext.get_flag_opnds(["zf"])
    if not test_opvalues:
        return

    operand0 = test_opvalues[0]
    if len(test_opvalues) > 1:
        operand1 = test_opvalues[1]

    cpu_context.jcccontext.alt_branch_data_dst = operand0
    if not cpu_context.registers.zf:
        cpu_context.jcccontext.condition_target_ea = opvalues[0].value
        # if JNE, this branch would NOT have been taken if opnd0 == opnd1, so create that condition
        if mnem == "jne":
            cpu_context.jcccontext.alt_branch_data = operand1.value
        # if JNZ, this branch would NOT have been taken if opnd0 == 0, so create that condition
        else:
            cpu_context.jcccontext.alt_branch_data = 0
    else:
        cpu_context.jcccontext.condition_target_ea = code_refs[0]
        # if JNE, this means that opnd0 == opnd1, so make opnd0 != opnd1
        if mnem == "jne":
            cpu_context.jcccontext.alt_branch_data = operand1.value + 1
        # if JNZ, this means that opnd0 == 0, so make opnd0 != 0
        else:
            cpu_context.jcccontext.alt_branch_data = 1

    logger.debug("{} 0x{:X} :: Primary branch 0x{:X}, using value 0x{} for alternate branch".format(
        mnem, ip, cpu_context.jcccontext.condition_target_ea, cpu_context.jcccontext.alt_branch_data))


@opcode
def JNO(cpu_context, ip, mnem, opvalues):
    """ Jump Not Overflow (OF=0) """
    pass

@opcode("jnp")
@opcode("jpo")
def JNP_JPO(cpu_context, ip, mnem, opvalues):
    """ Jump Not Parity (PF=0) """
    pass

@opcode
def JNS(cpu_context, ip, mnem, opvalues):
    """ Jump Not Sign (SF=0) """
    pass

@opcode
def JO(cpu_context, ip, mnem, opvalues):
    """ Jump Overflow (OF=1) """
    pass

@opcode("jp")
@opcode("jpe")
def JP_JPE(cpu_context, ip, mnem, opvalues):
    """ Jump Parity (PF=1) """
    pass

@opcode
def JS(cpu_context, ip, mnem, opvalues):
    """ Jump Sign (SF=1) """
    pass


@opcode("movapd")
@opcode("movaps")
@opcode("movupd")
@opcode("movups")
def MOVAPS(cpu_context, ip, mnem, opvalues):
    """
    Handle the MOVAPD, MOVAPS, MOVUPD, and MOVUPS instructions in the same manner, a move on a single-precision floating
    point value

    MOVAPS: Move Aligned Packed Single-Precision Floating-Point Values
    """
    opvalues = [opvalue for opvalue in opvalues if opvalue.value is not None]
    opvalue2 = opvalues[1].value
    # We need to use the size of the source when accessing XMM registers.
    width = opvalues[1].width
    logger.debug("{} 0x{:X} :: Copy {} into {}".format(mnem, ip, opvalue2, idc.print_operand(ip, 0)))
    set_operand_value(cpu_context, ip, opvalue2, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0), width=width)


@opcode("lea")
@opcode("mov")
@opcode("movzx")
def _mov_lea(cpu_context, ip, mnem, opvalues):
    """
    Handle the MOV, MOVZX, and LEA instructions in the same manner.

    MOVZX is a zero extend, but this logic makes no real sense in python.
    """
    opvalue2 = opvalues[1].value
    width = opvalues[0].width
    logger.debug("{} 0x{:X} :: Copy {} into {}".format(mnem, ip, opvalue2, idc.print_operand(ip, 0)))
    cpu_context.set_operand_value(ip, opvalue2, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0), width=width)


# TODO: Do we need to handle MOVS* for our purpose?

@opcode("movsx")
@opcode("movsxd")
def _movsx(cpu_context, ip, mnem, opvalues):
    """ Move with Sign Extend """
    opvalue2 = opvalues[1].value
    logger.debug("MOVSX 0x{:X} :: Sign-extend {} into {}".format(ip, opvalue2, idc.print_operand(ip, 0)))
    size = utils.sign_extend(opvalue2, opvalues[1].width, opvalues[0].width)
    cpu_context.set_operand_value(ip, size, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode("movs")  # I don't believe IDA will ever use just "movs", but it's here just incase.
@opcode("movsb")
@opcode("movsw")
@opcode("movsd")
def movs(cpu_context, ip, mnem, opvalues):
    """
    Move Scalar Double-Precision Floating-Point Value
    OR
    Move Data from String to String
    """
    # movsd op1 op2
    if mnem == "movsd" and len(opvalues) == 2:
        op1, op2 = opvalues
        data = op2.value
        if op1.type == idc.o_reg:
            # When moving into an XMM register, the high 64 bits needs to remain untouched.
            data = (data & 0xFFFFFFFFFFFFFFFF0000000000000000) | data
        logger.debug("{} 0x{:X} :: {} -> {}".format(mnem, ip, op2.value, data))
        cpu_context.set_operand_value(ip, data, op1.text, op1.type)

    # movs*
    else:
        if cpu_context._bitness == 16:
            src = "SI"
            dst = "DI"
        else:
            src = "ESI"
            dst = "EDI"
        # IDA sometimes provides a single "fake" operand to help determine the size.
        width = opvalues[0].width if opvalues else 4

        size = {"movs": width, "movsb": 1, "movsw": 2, "movsd": 4}[mnem]
        src_ptr = cpu_context.registers[src]
        dst_ptr = cpu_context.registers[dst]
        logger.debug("{} 0x{:X} :: 0x{:X} -> 0x{:X}".format(mnem, ip, src_ptr, dst_ptr))
        data = cpu_context.mem_read(src_ptr, size)
        cpu_context.mem_write(dst_ptr, data)

        # update ESI/EDI registers
        if cpu_context.registers.df:
            cpu_context.registers[src] -= size
            cpu_context.registers[dst] -= size
        else:
            cpu_context.registers[src] += size
            cpu_context.registers[dst] += size


@opcode
def MOVQ(cpu_context, ip, mnem, opvalues):
    """ Move Quadword """
    opvalue2 = opvalues[1].value & 0xFFFFFFFFFFFFFFFF
    logger.debug("{} 0x{:X} :: Copy {} into {}".format(mnem, ip, opvalue2, idc.print_operand(ip, 0)))
    cpu_context.set_operand_value(ip, opvalue2, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def MUL(cpu_context, ip, mnem, opvalues):
    """ Multiplication """
    _mul(cpu_context, ip, mnem, opvalues)


@opcode
def NEG(cpu_context, ip, mnem, opvalues):
    """ Negate """
    opvalue1 = opvalues[0].value
    result = -opvalue1
    width = opvalues[0].width
    mask = utils.get_mask(width)

    cpu_context.registers.cf = int(result & mask != 0)
    cpu_context.registers.af = int(result & 0x0F != 0)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit(opvalue1, width) and not utils.sign_bit(result, width))
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of"], opvalues)

    logger.debug("NEG 0x{:X} :: {} - {}".format(ip, opvalue1, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def NOT(cpu_context, ip, mnem, opvalues):
    """ NOT Logic Operator """
    opvalue1 = opvalues[0].value
    width = get_max_operand_size(opvalues)
    result = ~opvalue1
    logger.debug("NOT 0x{:X} :: {} -> {}".format(ip, opvalue1, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def OR(cpu_context, ip, mnem, opvalues):
    """ OR Logic Operator """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    result = opvalue1 | opvalue2

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("OR 0x{:X} :: {} | {} = {}".format(ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def POP(cpu_context, ip, mnem, opvalues):
    """ POP stack value """
    result = utils.struct_unpack(cpu_context.mem_read(cpu_context.reg_read("RSP"), cpu_context._byteness))
    cpu_context.reg_write("RSP", cpu_context.reg_read("RSP") + cpu_context._byteness)
    logger.debug("POP 0x{:X} :: Popped value {} into {}".format(ip, result, idc.print_operand(ip, 0)))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode("popa")
@opcode("popad")
def POPA(cpu_context, ip, mnem, opvalues):
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
                cpu_context.res_write("ESP", cpu_context.reg_read("ESP") + 4)
            else:
                cpu_context.res_write("ESP", cpu_context.reg_read("ESP") + 2)
        else:
            # reg <- Pop()
            val = utils.struct_unpack(cpu_context.mem_read(cpu_context.reg_read("ESP"), cpu_context._byteness))
            cpu_context.reg_write(reg, val)
            cpu_context.res_write("ESP", cpu_context.reg_read("ESP") + 4)


@opcode
def PUSH(cpu_context, ip, mnem, opvalues):
    """ PUSH """
    operand = opvalues[0]
    logger.debug("PUSH 0x{:X} :: Pushing {} onto stack".format(ip, operand.value))
    cpu_context.reg_write("RSP", cpu_context.reg_read("RSP") - cpu_context._byteness)
    cpu_context.mem_write(cpu_context.reg_read("ESP"), utils.struct_pack(operand.value, width=operand.width))


@opcode
def PUSHA(cpu_context, ip, mnem, opvalues):
    """
    PUSHA (valid only for x86)
    """
    reg_order = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
    # Store the original ESP value to push
    temp_esp = cpu_context.reg_read("ESP")
    logger.debug("PUSHA 0x{:X}".format(ip))
    for reg in reg_order:
        cpu_context.reg_write("ESP", cpu_context.reg_read("ESP") - 4)
        if reg == "ESP":  # Push the original ESP value, not the current value
            cpu_context.mem_write(cpu_context.reg_read("ESP"), utils.struct_pack(temp_esp))
            continue

        cpu_context.mem_write(cpu_context.reg_read("ESP"), utils.struct_pack(cpu_context.reg_read(reg)))


@opcode
def RCR(cpu_context, ip, mnem, opvalues):
    """ Rotate Carry Right """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 9, 17, 33 when the width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F) % ((width * 8) + 1)
    else:
        # This is undefined behavior
        return

    if opvalue2 == 1:
        cpu_context.registers.of = get_msb(opvalue1, width) ^ cpu_context.registers.CF

    while tempcount:
        tempcf = get_lsb(opvalue2)
        opvalue1 = (opvalue1 / 2) + (cpu_context.registers.cf * 2 ** width)
        cpu_context.registers.cf = tempcf
        tempcount -= 1

    cpu_context.jcccontext.update_flag_opnds(["cf"], opvalues)
    logger.debug("RCR 0x{:X} :: Rotate {} right by {} -> {}".format(
        ip,
        opvalues[0].value,
        opvalue2,
        opvalue1)
    )
    cpu_context.set_operand_value(ip, opvalue1, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def RCL(cpu_context, ip, mnem, opvalues):
    """ Rotate Carry Left """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 9, 17, 33 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F) % ((width * 8) + 1)
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

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], opvalues)
    logger.debug("RCL 0x{:X} :: Rotate {} left by {} -> {}".format(
        ip,
        opvalues[0].value,
        opvalue2,
        opvalue1)
    )
    cpu_context.set_operand_value(ip, opvalue1, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def ROL(cpu_context, ip, mnem, opvalues):
    """ Rotate Left """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 8, 16, 32 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F) % (width * 8)
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

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], opvalues)
    logger.debug("ROL 0x{:X} :: Rotate {} left by {} -> {}".format(
        ip,
        opvalues[0].value,
        opvalue2,
        opvalue1)
    )
    cpu_context.set_operand_value(ip, opvalue1, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def ROR(cpu_context, ip, mnem, opvalues):
    """ Rotate Right """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)

    # Because we want to allow for 64-bit code, we'll use 0x3F as our mask.
    if width == 8:
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F)
    elif width in [1, 2, 4]:
        # Basically MOD by 8, 16, 32 when width is 1 byte, 2 bytes or 4 bytes
        tempcount = (opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F) % (width * 8)
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

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], opvalues)
    logger.debug("ROR 0x{:X} :: Rotate {} right by {} -> {}".format(
        ip,
        opvalues[0].value,
        opvalue2,
        opvalue1)
    )
    cpu_context.set_operand_value(ip, opvalue1, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode("sal")
@opcode("shl")
def sal_shl(cpu_context, ip, mnem, opvalues):
    """ Shift Arithmetic Left """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    result = opvalue1

    if opvalue2:
        tempcount = opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F  # 0x3F Because we want to allow for 64-bit code
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

    cpu_context.jcccontext.update_flag_opnds(["cf", "of"], opvalues)
    logger.debug("SAL 0x{:X} :: Shift {} left by {} -> {}".format(ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SAR(cpu_context, ip, mnem, opvalues):
    """ Shift Arithmetic Right """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    result = opvalue1
    if opvalue2:
        tempcount = opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F  # 0x3F Because we want to allow for 64-bit code
        msb = get_msb(opvalue1, cpu_context._byteness)
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

        result |= (msb << cpu_context._bitness)

    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], opvalues)
    logger.debug("SAR 0x{:X} :: Shift {} right by {} -> {}".format(ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SBB(cpu_context, ip, mnem, opvalues):
    """ Subtract with Borrow/Carry """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    result = opvalue1 - (opvalue2 + cpu_context.registers.cf)

    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["af", "zf", "sf", "of", "pf"], opvalues)
    logger.debug("SBB 0x{:X} :: {} - {} = {}".format(
        ip, opvalue1, (opvalue2 + cpu_context.registers.cf), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


# TODO: Do we need SCAS* implemented????


@opcode
def SETNA(cpu_context, ip, mnem, opvalues):
    """ Set if Not Above """
    result = int(cpu_context.registers.zf or cpu_context.registers.cf)
    logger.debug("SETNA 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETLE(cpu_context, ip, mnem, opvalues):
    """ Set if Less than or Equal """
    result = int(cpu_context.registers.zf or (cpu_context.registers.sf != cpu_context.registers.of))
    logger.debug("SETLE 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETGE(cpu_context, ip, mnem, opvalues):
    """ Set if Greater than or Equal """
    result = int(cpu_context.registers.sf == cpu_context.registers.of)
    logger.debug("SETGE 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETG(cpu_context, ip, mnem, opvalues):
    """ Set if Greather than """
    result = int(cpu_context.registers.zf and (cpu_context.registers.sf == cpu_context.registers.of))
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETE(cpu_context, ip, mnem, opvalues):
    """ Set if Equal """
    result = int(cpu_context.registers.zf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETC(cpu_context, ip, mnem, opvalues):
    """ Set if Carry """
    result = int(cpu_context.registers.cf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETBE(cpu_context, ip, mnem, opvalues):
    """ Set if Below or Equal """
    result = int(cpu_context.registers.cf and cpu_context.registers.zf)
    logger.debug("SETBE 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETB(cpu_context, ip, mnem, opvalues):
    """ Set if Below """
    SETC(cpu_context, ip, mnem, opvalues)


@opcode
def SETAE(cpu_context, ip, mnem, opvalues):
    """ Set if Above or Equal """
    SETC(cpu_context, ip, mnem, opvalues)


@opcode
def SETA(cpu_context, ip, mnem, opvalues):
    """ Set if Above """
    result = int(not (cpu_context.registers.cf | cpu_context.registers.zf))
    logger.debug("SETA 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETPS(cpu_context, ip, mnem, opvalues):
    """ Set if Not??? Parity """
    result = int(cpu_context.registers.sf)
    logger.debug("SETPS 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETPO(cpu_context, ip, mnem, opvalues):
    """ Set if Parity Odd """
    result = int(cpu_context.registers.pf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETPE(cpu_context, ip, mnem, opvalues):
    """ Set if Parity Event """
    SETPO(cpu_context, ip, mnem, opvalues)


@opcode
def SETP(cpu_context, ip, mnem, opvalues):
    """ Set if Parity """
    SETPO(cpu_context, ip, mnem, opvalues)


@opcode
def SETO(cpu_context, ip, mnem, opvalues):
    """ Set if Overflow """
    result = int(cpu_context.registers.of)
    logger.debug("SETO 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNS(cpu_context, ip, mnem, opvalues):
    """ Set if Not Sign """
    result = int(not cpu_context.registers.sf)
    logger.debug("SETNS 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNP(cpu_context, ip, mnem, opvalues):
    """ Set if Not Parity """
    result = int(not cpu_context.registers.pf)
    logger.debug("SETNP 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNO(cpu_context, ip, mnem, opvalues):
    """ Set if Not Overflow """
    result = int(not cpu_context.registers.of)
    logger.debug("SETNO 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNL(cpu_context, ip, mnem, opvalues):
    """ Set if Not Less """
    result = int(cpu_context.registers.sf == cpu_context.registers.of)
    logger.debug("SETNL 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNGE(cpu_context, ip, mnem, opvalues):
    """ Set if Not Greater Than or Equal """
    result = int(cpu_context.registers.sf != cpu_context.registers.of)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNG(cpu_context, ip, mnem, opvalues):
    """ Set if Not Greater """
    result = int(cpu_context.registers.zf or (cpu_context.registers.sf != cpu_context.registers.of))
    logger.debug("SETNG 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNE(cpu_context, ip, mnem, opvalues):
    """ Set if Not Equal """
    result = int(not cpu_context.registers.zf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNC(cpu_context, ip, mnem, opvalues):
    """ Set if Not Carry """
    result = int(not cpu_context.registers.cf)
    logger.debug("{} 0x{:X} :: Setting {} to {}".format(mnem.upper(), ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNBE(cpu_context, ip, mnem, opvalues):
    """ Set if Not Below or Equal """
    result = int(not (cpu_context.registers.cf | cpu_context.registers.zf))
    logger.debug("SETNBE 0x{:X} :: Setting {} to {}".format(ip, idc.print_operand(ip, 0), result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SETNB(cpu_context, ip, mnem, opvalues):
    """ Set if Not Below """
    SETNC(cpu_context, ip, mnem, opvalues)


@opcode
def SETNAE(cpu_context, ip, mnem, opvalues):
    """ Set if Not Above or Equal """
    SETC(cpu_context, ip, mnem, opvalues)


@opcode
def SETL(cpu_context, ip, mnem, opvalues):
    """ Set if Less Than """
    SETNGE(cpu_context, ip, mnem, opvalues)


@opcode
def SETNLE(cpu_context, ip, mnem, opvalues):
    """ Set if Not Less Than or Equal """
    SETG(cpu_context, ip, mnem, opvalues)


@opcode
def SETNZ(cpu_context, ip, mnem, opvalues):
    """ Set if Not Zero """
    SETNE(cpu_context, ip, mnem, opvalues)


@opcode
def SETZ(cpu_context, ip, mnem, opvalues):
    """ Set if Zero """
    SETE(cpu_context, ip, mnem, opvalues)


@opcode
def SHR(cpu_context, ip, mnem, opvalues):
    """ Shift Right """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)

    if not opvalue2:
        return

    result = opvalue1
    tempcount = opvalue2 & 0x3F if cpu_context._bitness == 64 else 0x1F  # Because we want to allow for 64-bit code
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
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], opvalues)
    logger.debug("SHR 0x{:X} :: Shift {} right by {} -> {}".format(ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def SUB(cpu_context, ip, mnem, opvalues):
    """ Subtract """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    result = opvalue1 - opvalue2

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("SUB 0x{:X} :: {} - {} = {}".format(ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode
def TEST(cpu_context, ip, mnem, opvalues):
    """ Test values for equality """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    result = opvalue1 & opvalue2

    mask = utils.get_mask(width)
    cpu_context.registers.cf = int((opvalue1 & mask) < (opvalue2 & mask))
    cpu_context.registers.af = int((opvalue1 ^ opvalue2 ^ result) & 0x10)
    cpu_context.registers.zf = int(result & mask == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = int(utils.sign_bit((opvalue1 ^ opvalue2) & (opvalue1 ^ result), width) == 0)
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "af", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("TEST 0x{:X} :: {} & {} -> {}".format(ip, opvalue1, opvalue2, result))


@opcode
def XCHG(cpu_context, ip, mnem, opvalues):
    """ Exchange two values """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    logger.debug("XCHG 0x{:X} :: exchange {} and {}".format(ip, opvalue1, opvalue2))
    cpu_context.set_operand_value(ip, opvalue1, idc.print_operand(ip, 1), idc.get_operand_type(ip, 1))
    cpu_context.set_operand_value(ip, opvalue2, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


@opcode("xor")
@opcode("pxor")
def _xor(cpu_context, ip, mnem, opvalues):
    """ XOR """
    opvalue1 = opvalues[0].value
    opvalue2 = opvalues[1].value
    width = get_max_operand_size(opvalues)
    result = opvalue1 ^ opvalue2

    cpu_context.registers.cf = 0
    cpu_context.registers.zf = int(result == 0)
    cpu_context.registers.sf = utils.sign_bit(result, width)
    cpu_context.registers.of = 0
    cpu_context.registers.pf = get_parity(result)
    cpu_context.jcccontext.update_flag_opnds(["cf", "zf", "sf", "of", "pf"], opvalues)

    logger.debug("{} 0x{:X} :: {} ^ {} = {}".format(mnem, ip, opvalue1, opvalue2, result))
    cpu_context.set_operand_value(ip, result, idc.print_operand(ip, 0), idc.get_operand_type(ip, 0))


# Global helper functions
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
