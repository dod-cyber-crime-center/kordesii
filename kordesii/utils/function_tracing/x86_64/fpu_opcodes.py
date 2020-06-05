"""
FPU instructions.
"""

import logging
import operator

from .opcodes import opcode
from .. import utils


logger = logging.getLogger(__name__)


# TODO: Handle stack fault exceptions.
# TODO: Handle overflow and division by zero exceptions.
# TODO: Support proper rounding support and REAL4, REAL8, REAL10 data types.
# TODO: Add missing opcodes.


@opcode("fadd")
@opcode("fiadd")
@opcode("faddp")
@opcode("fdiv")
@opcode("fdivr")
@opcode("fidiv")
@opcode("fidivr")
@opcode("fdivp")
@opcode("fdivrp")
@opcode("fmul")
@opcode("fimul")
@opcode("fmulp")
@opcode("fsub")
@opcode("fsubr")
@opcode("fisub")
@opcode("fisubr")
@opcode("fsubp")
@opcode("fsubrp")
def _compute(cpu_context, ip, mnem, operands):
    """Perform add/sub/mul/div computation on floating point numbers."""
    # Determine operator.
    if "add" in mnem:
        op, op_str = operator.add, "+"
    elif "sub" in mnem:
        op, op_str = operator.sub, "-"
    elif "div" in mnem:
        op, op_str = operator.div, "/"
    elif "mul" in mnem:
        op, op_str = operator.mul, "*"
    else:
        raise RuntimeError("Invalid mnem: %s", mnem)

    # Collect terms.
    if not operands:
        term1 = cpu_context.registers.st0
        term2 = cpu_context.registers.st1
    elif len(operands) == 1:
        term1 = cpu_context.registers.st0
        term2 = operands[0].value
    elif len(operands) == 2:
        term1 = operands[0].value
        term2 = operands[1].value
    else:
        logger.debug("Unexpected number of operands: %d", len(operands))
        return

    # "r" means to reverse terms.
    if mnem.endswith(("r", "rp")):
        term1, term2 = term2, term1

    # Compute.
    try:
        result = op(term1, term2)
    except OverflowError:
        logger.debug("OVERFLOW Detected. TODO")
        result = cpu_context.registers.fpu.NaN
    except ZeroDivisionError:
        logger.debug("ZERO DIVISION detected. TODO")
        result = cpu_context.registers.fpu.NaN
    except TypeError:
        # (occurs if one of the terms was None)
        logger.debug("EMPTY value detected. TODO")
        result = cpu_context.registers.fpu.NaN

    # Store results.
    if not operands:
        cpu_context.registers.st1 = result  # storing in st1 so it's available after pop.
    elif len(operands) == 1:
        cpu_context.registers.st0 = result
    else:
        operands[0].value = result
    logger.debug("%f %s %f = %f", term1, op_str, term2, result)

    # Pop if mnem ends with "p"
    if mnem.endswith("p"):
        cpu_context.registers.fpu.pop()


@opcode
def FABS(cpu_context, ip, mnem, operands):
    """Absolute value of st(0)"""
    term = cpu_context.registers.st0
    result = abs(term)
    cpu_context.registers.st0 = result
    logger.debug("abs(%f) = %f", term, result)


@opcode
def FCHS(cpu_context, ip, mnem, operands):
    """Change the sign of st(0)"""
    term = cpu_context.registers.st0
    result = -term
    cpu_context.registers.st0 = result
    logger.debug("-(%f) = %f", term, result)


@opcode("fcom")
@opcode("fcomp")
@opcode("fcompp")
@opcode("fucom")
@opcode("fucomp")
@opcode("fucompp")
@opcode("fcomi")
@opcode("fcomip")
@opcode("fucomi")
@opcode("fucomip")
@opcode("ficom")
@opcode("ficomp")
@opcode("ftst")
def FCOM(cpu_context, ip, mnem, operands):
    """Compare st0 to a floating point value."""
    if not operands:
        term1 = cpu_context.registers.st0
        term2 = 0.0 if mnem == "ftst" else cpu_context.registers.st1
    elif len(operands) == 1:
        term1 = cpu_context.registers.st0
        term2 = operands[0].value
    elif len(operands) == 2:
        term1 = operands[0].value
        term2 = operands[1].value
    else:
        logger.debug("Unexpected number of operands: %d", len(operands))
        return

    # TODO: If either value is empty (ie. None) we must set C3, C2, and C0 to None
    invalid = (None, cpu_context.registers.fpu.NaN)

    if "comi" in mnem:
        flags = ["zf", "pf", "cf"]
    else:
        flags = ["c3", "c2", "c0"]

    if term1 in invalid or term2 in invalid:
        cpu_context.registers[flags[0]] = 1
        cpu_context.registers[flags[1]] = 1
        cpu_context.registers[flags[2]] = 1
    elif term1 > term2:
        cpu_context.registers[flags[0]] = 0
        cpu_context.registers[flags[1]] = 0
        cpu_context.registers[flags[2]] = 0
    elif term1 < term2:
        cpu_context.registers[flags[0]] = 0
        cpu_context.registers[flags[1]] = 0
        cpu_context.registers[flags[2]] = 1
    elif term1 == term2:
        cpu_context.registers[flags[0]] = 1
        cpu_context.registers[flags[1]] = 0
        cpu_context.registers[flags[2]] = 0

    # Pop off st0.
    if mnem.endswith("p"):
        cpu_context.registers.fpu.pop()
    # Pop off st1 as well.
    if mnem.endswith("pp"):
        cpu_context.registers.fpu.pop()

    logger.debug("Comparing: %f <-> %f", term1, term2)


@opcode("fcmovb")
@opcode("fcmove")
@opcode("fcmovbe")
@opcode("fcmovu")
@opcode("fcmovnb")
@opcode("fcmovne")
@opcode("fcmovnbe")
@opcode("fcmovnu")
def FCMOV(cpu_context, ip, mnem, operands):
    """Conditional move based on CPU flags."""
    condition_str = mnem[5:]
    condition = False

    if "b" in condition_str:
        condition |= cpu_context.registers.cf == 1

    if "e" in condition_str:
        condition |= cpu_context.registers.zf == 1

    if "u" in condition_str:
        condition |= cpu_context.registers.pf == 1

    if condition_str.startswith("n"):
        condition = not condition

    value = operands[1].value
    if condition:
        operands[0].value = value
        logger.debug("Moving: %f -> st0", value)
    else:
        logger.debug("Not moving: %f -> st0. Condition failed.", value)


@opcode("fld")
@opcode("fild")
@opcode("fldz")
@opcode("fld1")
@opcode("fldpi")
@opcode("fldl2e")
@opcode("fldl2t")
@opcode("fldlg2")
@opcode("fldln2")
def FLD(cpu_context, ip, mnem, operands):
    """Load (push) real or integer number into stack."""
    value = orig_value = operands[0].value if operands else None
    if mnem == "fld":
        value = utils.int_to_float(value)
    elif mnem == "fild":
        value = float(value)
    elif mnem.endswith("z"):
        value = 0.0
    elif mnem.endswith("1"):
        value = 1.0
    elif mnem.endswith("pi"):
        value = 3.141592653589793  # math.pi
    elif mnem.endswith("l2e"):
        value = 1.4426950408889634  # math.log(math.e, 2)
    elif mnem.endswith("l2t"):
        value = 3.3219280948873626  # math.log(10, 2)
    elif mnem.endswith("lg2"):
        value = 0.30102999566398114  # math.log(2, 10)
    elif mnem.endswith("ln2"):
        value = 0.6931471805599453  # math.log(2) = ln(2)
    else:
        raise NotImplementedError("Unsupported mnem: {}".format(mnem))
    if orig_value is None:
        logger.debug("Loading: %f -> st0", value)
    else:
        logger.debug("Loading: %d -> %f -> st0", orig_value, value)
    cpu_context.registers.fpu.push(value)


@opcode
def FLDCW(cpu_context, ip, mnem, operands):
    """Load control word from memory."""
    value = operands[0].value
    cpu_context.registers.fpu.control_word = value
    logger.debug("Load control word: %x", value)


@opcode("fst")
@opcode("fstp")
@opcode("fist")
@opcode("fistp")
def FST(cpu_context, ip, mnem, operands):
    """Store (pop) real or integer number from stack into into memory"""
    value = orig_value = cpu_context.registers.st0
    if "i" in mnem:
        # Round integer.
        # TODO: Technically we are suppose to round the number according to the rounding mode of rc.
        value = int(value)
    else:
        value = utils.float_to_int(value)
    operands[0].value = value
    logger.debug("Storing: %f -> %d -> %s", orig_value, value, operands[0].text)
    if mnem.endswith("p"):
        cpu_context.registers.fpu.pop()


@opcode("fstcw")
@opcode("fnstcw")
def FSTCW(cpu_context, ip, mnem, operands):
    """Store control word into memory."""
    value = cpu_context.registers.fpu.control_word
    operands[0].value = value
    logger.debug("Store control word: %x -> %s", value, operands[0].text)


@opcode
def FXAM(cpu_context, ip, mnem, operands):
    """Examine the content of st0."""
    st0 = cpu_context.registers.st0

    cpu_context.registers.c1 = int(st0 < 0)  # sign bit
    if st0 == cpu_context.registers.fpu.NaN:
        cpu_context.registers.c3 = 0
        cpu_context.registers.c2 = 0
        cpu_context.registers.c0 = 1
    elif st0 == cpu_context.registers.fpu.INFINITY:
        cpu_context.registers.c3 = 0
        cpu_context.registers.c2 = 1
        cpu_context.registers.c0 = 1
    elif st0 == 0:
        cpu_context.registers.c3 = 1
        cpu_context.registers.c2 = 0
        cpu_context.registers.c0 = 0
    elif st0 is None:
        cpu_context.registers.c3 = 1
        cpu_context.registers.c2 = 0
        cpu_context.registers.c0 = 1
    # TODO
    # elif st0 is denormalized:
    #     cpu_context.registers.c3 = 1
    #     cpu_context.registers.c2 = 1
    #     cpu_context.registers.c0 = 0
    else:
        cpu_context.registers.c3 = 0
        cpu_context.registers.c2 = 0
        cpu_context.registers.c0 = 0

    logger.debug("Examining: %r", st0)


# TODO: This is suppose to exception if st0 is empty.
@opcode
def FXCH(cpu_context, ip, mnem, operands):
    """Exchange the top data register with another data register"""
    st0 = cpu_context.registers.st0

    if operands:
        opvalue = operands[0].value
        cpu_context.registers.st0, operands[0].value = opvalue, st0
        logger.debug("exchange %f <-> %f", st0, opvalue)
    else:
        st1 = cpu_context.registers.st1
        cpu_context.registers.st0, cpu_context.registers.st1 = st1, st0
        logger.debug("exchange %f <-> %f", st0, st1)


@opcode
def SAHF(cpu_context, ip, mnem, operands):
    """Transfer status word flags into CPU's flag register."""
    cpu_context.registers.zf = cpu_context.registers.c3
    cpu_context.registers.pf = cpu_context.registers.c2
    cpu_context.registers.cf = cpu_context.registers.c0
