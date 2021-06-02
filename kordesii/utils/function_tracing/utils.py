"""
This file contains utility functions utilized throughout the function_tracing package.
"""

import logging
import re
import string
import struct

import ida_allins
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

from .exceptions import FunctionTracingError
from .operands import Operand

logger = logging.getLogger(__name__)


class SetTypeException(Exception):
    pass


def signed(n, bit_width):
    """
    Convert an unsigned integer to a signed integer

    :param uint n: value to convert
    :param int bit_width: byte width of n

    :return int: signed conversion
    """
    if n >> (bit_width - 1):  # Is the hi-bit set?
        return n - (1 << bit_width)

    return n


def sign_bit(value, width):
    """Returns the highest bit with given value and byte width."""
    return (value >> ((8 * width) - 1)) & 0x1


def sign_extend(value, orig_size, dest_size):
    """
    Calculates the sign extension for a provided value and a specified destination size.

    :param value: value to be sign extended

    :param orig_size: width of value in bytes

    :param dest_size: size of the destination in bytes

    :return: value, sign extended
    """
    # Calculate the max value for orig and dest
    orig_max = get_mask(orig_size)
    dest_max = get_mask(dest_size)
    # Calculate bit count to shift by
    orig_shift = 8 * orig_size
    dest_shift = 8 * dest_size
    # Create the bit mask
    masknumber = value & orig_max
    msb = masknumber >> (orig_shift - 1)
    # Perform the sign extension
    if msb:
        signextended = ((dest_max << orig_shift) | masknumber) & dest_max
    else:
        signextended = value & dest_max

    return signextended


def align_page_up(x):
    return (x + 0x1000 - 1) & ~(0x1000 - 1)


def get_byte_width(value):
    """
    Calculate the appropriate byte width of the input value (BYTE, WORD, DWORD, QWORD)

    :param value: value to to determine width of

    :return: bytes required to store data
    """
    if value <= 0xFF:
        return 1

    if value <= 0xFFFF:
        return 2

    if value <= 0xFFFFFFFF:
        return 4

    if value <= 0xFFFFFFFFFFFFFFFF:
        return 8


BIG_ENDIAN = ida_ida.inf_is_be()

# Table used by struct_unpack and struct_pack functions
struct_unpack_table = {
    1: "B",
    2: "H",
    4: "L",
    8: "Q",
    16: "QQ",
}


def _get_format_str(width, signed=False):
    if width not in struct_unpack_table:
        raise FunctionTracingError("Invalid width to unpack: {}".format(width))

    format_char = struct_unpack_table[width]
    if signed:
        format_char = format_char.lower()
    return ">" if BIG_ENDIAN else "<" + format_char


def struct_unpack(buffer, signed=False):
    """
    Unpack a buffer given its length and offset using struct.unpack().
    This function will know how to unpack the given buffer by using the lookup table 'struct_unpack_table'
    If the buffer is of unknown length then None is returned. Otherwise the unpacked value is returned.

    :param buffer: data to be unpacked
    :param signed: whether the data is a signed or unsigned value

    :return: unpacked int or None
    """
    n = len(buffer)
    format_str = _get_format_str(n, signed)

    # Unpack
    if n == 16:
        # Struct can only handle up to 64-bit values...so work in 64-bit chunks
        a, b = struct.unpack(format_str, buffer)
        if BIG_ENDIAN:
            return (a << 64) | b
        else:
            return (b << 64) | a
    else:
        return struct.unpack(format_str, buffer)[0]


def struct_pack(value, width=None):
    """
    Pack the supplied value into a string.

    :param value: value to be packed
    :param signed: whether the data is a signed or unsigned value
    :param width: Width of value to pack data into. (choose from 1, 2, 4, 8, or 16 bytes)

    :return: packed data or None
    """
    # FIXME: get_byte_width() is to just keep backwards compatibility. Remove this.
    width = width or get_byte_width(value)
    # Because our & instructions essentially convert our value to a positive integer anyway, we need not worry about
    # whether the input value is signed or not
    # struct.pack("<q", -723873873)
    # '\xaf\x8f\xda\xd4\xff\xff\xff\xff'
    # struct.pack("<Q", -723873873 & 0xFFFFFFFFFFFFFFFF)
    # '\xaf\x8f\xda\xd4\xff\xff\xff\xff'
    format_str = _get_format_str(width, signed=False)

    # Pack
    if width == 16:
        # Struct can only handle up to 64-bit values... so work in 64-bit chunks
        if BIG_ENDIAN:
            return struct.pack(format_str, value >> 64, value & 0xFFFFFFFFFFFFFFFF)
        else:
            return struct.pack(format_str, value & 0xFFFFFFFFFFFFFFFF, value >> 64)
    else:
        # Need to mask off the size of value to width since pack doesn't truncate...
        return struct.pack(format_str, (value & get_mask(width)))


def float_to_int(val, precision=2):
    """
    Given a float value, convert it to its integer hexadecimal equivalent.

    >>> float_to_int(1.0, 8)
    >>> 4607182418800017408

    :param float val: float to convert to int equivalent
    :param int precision: single or double precision (1 for single, 2 for double)
    :return: int
    :raises: ValueError
    """
    if precision == 1:
        return struct.unpack("H", struct.pack("f", val))[0]
    elif precision == 2:
        return struct.unpack("Q", struct.pack("d", val))[0]
    else:
        raise FunctionTracingError("Precision {} is not valid.".format(precision))


def int_to_float(val, precision=2):
    """
    Given an integer value, convert it to its float hexadecimal equivalent.

    >>> int_to_float(4607182418800017408, 8)
    >>> 1.0

    :param int val: integer value to convert to float equivalent
    :param int precision: single or double precision
    :return: int or None
    :raises: ValueError
    """
    if precision == 1:
        return struct.unpack("f", struct.pack("H", val))[0]
    elif precision == 2:
        return struct.unpack("d", struct.pack("Q", val))[0]
    else:
        raise FunctionTracingError("Precision {} is not valid.".format(precision))


def get_mask(size):
    """
    Get bit mask based on byte size.

    :param size: number of bytes to obtain mask for

    :return: mask of width size
    """
    return 2 ** (8 * size) - 1


def get_bits():
    """
    Gets the architecture of the input file.

    :return int: bit width
    """
    info = idaapi.get_inf_structure()
    result = 16
    if info.is_64bit():
        result = 64
    elif info.is_32bit():
        result = 32

    return result


def _decompile(offset: int) -> tuple:
    """
    Attempt to decompile the function at the provided offset using the Hex-Rays plugin. Returns a tuple containing the
    decompiled text (which will be None if an error occurred) and the populated hexrays_failure_t object.
    :param offset: an offset in the function to decompile
    :return: (decompiled text, failure object)
    """
    func = ida_funcs.get_func(offset)
    hf = ida_hexrays.hexrays_failure_t()
    decompiled = ida_hexrays.decompile_func(func, hf, 0)
    return decompiled, hf


def _set_decompiled_func_type(offset: int, decompiled: "ida_hexrays.cfuncptr_t"):
    """
    Given the cfuncptr_t object, obtain the declaration, sanitize it, and set the function's type.
    :param offset: offset of function to set type for
    :param decompiled: a cfuncptr_t object
    """
    # Save type for next time.
    fmt = decompiled.print_dcl()
    fmt = "".join(c for c in fmt if c in string.printable and c not in ("\t", "!"))
    set_type_result = idc.SetType(offset, "{};".format(fmt))
    if not set_type_result:
        logger.warning("Failed to SetType for function at 0x{:X} with decompiler type {!r}".format(offset, fmt))


DECOMPILE_ERRORS = [
    -12,    # call analysis failed
]


def _get_decompiled_function(offset: int) -> "ida_hexrays.cfuncptr_t":
    """
    Attempt to decompile the function containing offset and return the obtained cfuncptr_t object. Additionaly sets the
    type for all decompiled functions.
    :param offset: offset of interest
    :return: a cfuncptr_t object or None
    """
    # This requires Hexrays decompiler, load it and make sure it's available before continuing.
    if not idaapi.init_hexrays_plugin():
        idc.load_and_run_plugin("hexrays", 0) or idc.load_and_run_plugin("hexx64", 0)
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Unable to load Hexrays decompiler.")

    decompiled = None
    offsets_to_decompile = [offset] # LIFO list of offsets to try to decompile
    offsets_attempted = set()       # Offsets already attempted to decompile, whether successful or not
    offsets_decompiled = set()      # Set of offsets that successfull decompiled
    # Continue trying to decompile until the list of offsets to decompile is empty or we get an error we can't handle
    # TODO: Determine what errors we can actually handle
    while offsets_to_decompile:
        _offset = offsets_to_decompile.pop()
        # This check means we have probably hit a snag preventing us from decompiling all together, and should prevent
        # an endless loop of continuously trying to decompile
        if _offset in offsets_decompiled:   # already decompiled, but still causing a problem?
            raise RuntimeError("Unable to decompile function 0x{:X}".format(offset))

        offsets_attempted.add(_offset)
        decompiled, hf = _decompile(_offset)
        if decompiled and not hf.code:  # successful decompilation, add to set of decompiled, and remove from attempted
            # set the type
            _set_decompiled_func_type(_offset, decompiled)
            offsets_decompiled.add(_offset)
            offsets_attempted.remove(_offset)
        else:   # unsuccessful...
            if not hf.code in DECOMPILE_ERRORS: # cannot possibly recover
                raise RuntimeError("Unable to decompile function at 0x{:X}".format(offset))

            # Can possibly recover by decompiling called functions
            # add the current offset back to the LIFO list to try decompiling a second time
            offsets_to_decompile.append(_offset)
            # get the address where the analysis failed, pull its operand, and add to the stack
            call_ea = idc.get_operand_value(hf.errea, 0)
            # can't continue if this address was already attempted
            if call_ea in offsets_attempted:
                raise RuntimeError("Unable to decompile function at 0x{:X}".format(offset))

            offsets_to_decompile.append(call_ea)

    return decompiled


def _get_function_tif_with_hex_rays(offset):
    """
    Attempt to get the tinfo_t object of a function using the Hex-Rays decompiler plugin.

    :param offset: Offset of function.
    :raises: RuntimeError on failure.
    :returns: tinfo_t object on success.
    """
    tif = ida_typeinf.tinfo_t()
    decompiled = _get_decompiled_function(offset)
    if not decompiled: # not sure what for shenanigans happened to get None back....
        raise RuntimeError("Expected cfuncptr_t object, received None")

    decompiled.get_func_type(tif)
    return tif


def _get_function_tif_with_guess_type(offset):
    """
    Attempt to get the tinfo_t object of a function using the "guess_type" function.

    :param offset: Offset of function.
    :raises: RuntimeError on failure.
    :returns: tinfo_t object on success.
    """
    tif = ida_typeinf.tinfo_t()

    guessed_type = idc.guess_type(offset)
    if guessed_type is None:
        raise RuntimeError("Failed to guess function type for offset 0x{:X}".format(offset))

    func_name = idc.get_func_name(offset)
    if func_name is None:
        raise RuntimeError("Failed to get function name for offset 0x{:X}".format(offset))

    # Documentation states the type must be ';' terminated, also the function name must be inserted
    guessed_type = re.sub(r"\(", " {}(".format(func_name), "{};".format(guessed_type))
    set_type_result = idc.SetType(offset, guessed_type)
    if not set_type_result:
        logger.warning(
            "Failed to SetType for function at 0x{:X} with guessed type {!r}".format(offset, guessed_type)
        )
    # Try one more time to get the tinfo_t object
    if not ida_nalt.get_tinfo(tif, offset):
        raise RuntimeError("Failed to obtain tinfo_t object for offset 0x{:X}".format(offset))

    return tif


# Cache of function types we have computed.
_func_types = set()


def get_function_data(offset, operand: Operand = None):
    """
    Obtain a idaapi.func_type_data_t object for the function with the provided start EA.

    :param int offset: start EA of function
    :param operand: operand containing function address in it's value.
        This can be provided when function is dynamically generated at runtime. (e.g. call eax)

    :return: ida_typeinf.func_type_data_t object, ida_typeinf.tinfo_t object

    :raise RuntimeError: if func_type_data_t object cannot be obtained
    """
    global _func_types

    tif = None

    try:
        func_type = idc.get_type(offset)
    except TypeError:
        raise RuntimeError("Not a valid offset: {!r}".format(offset))

    # First see if it's a type we already set before.
    if func_type and offset in _func_types:
        tif = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tif, offset)

    else:
        # Otherwise, try to use the Hexrays decompiler to determine function signature.
        # (It's better than IDA's guess_type)
        try:
            tif = _get_function_tif_with_hex_rays(offset)

        # If we fail, resort to using guess_type+
        except RuntimeError:
            if func_type:
                # If IDA's disassembler set it already, go with that.
                tif = ida_typeinf.tinfo_t()
                ida_nalt.get_tinfo(tif, offset)
            else:
                try:
                    tif = _get_function_tif_with_guess_type(offset)
                except RuntimeError:
                    # Don't allow to fail if we could pull from operand.
                    pass

    if tif:
        funcdata = ida_typeinf.func_type_data_t()

        # In IDA 7.6, imported functions are now function pointers.
        # To handle this, check if we need to pull out a pointed object first
        if tif.is_funcptr():
            tif = tif.get_pointed_object()

        success = tif.get_func_details(funcdata)
        if success:
            # record that we have processed this function before. (and that we can grab it from the offset)
            _func_types.add(offset)
            return funcdata, tif

    # If we have still failed, we have one more trick under our sleeve.
    # Try to pull the type information from the operand of the call instruction.
    # This could be set if the function has been dynamically created.
    if operand:
        tif = operand._tif
        funcdata = ida_typeinf.func_type_data_t()
        success = tif.get_func_details(funcdata)
        if success:
            return funcdata, tif

    raise RuntimeError("failed to obtain func_type_data_t object for offset 0x{:X}".format(offset))


def get_function_name(func_ea):
    """Retrieves the function name from the given address."""
    # (Using get_name() over get_func_name() so it also works for imported functions)
    func_name = idc.get_name(func_ea)
    # Demangle name if necessary:
    demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
    if demangled_name:
        # Strip off the extra junk: 'operator new(uint)' -> 'new'
        match = re.search("([^ :]*)\(", demangled_name)
        if not match:
            logger.debug("Unable to demangle function name: {}".format(demangled_name))
        else:
            logger.debug("Demangled function name {} -> {}".format(demangled_name, match.group(1)))
            demangled_name = match.group(1)
        func_name = demangled_name
    return func_name


def is_func_ptr(offset: int) -> bool:
    """Returns true if the given offset is a function pointer."""
    # As a first check, simply see if the offset is the start of a function.
    func = ida_funcs.get_func(offset)
    if func and func.start_ea == offset:
        return True

    # Sometimes we will get a really strange issue where the IDA disassember has set a type for an
    # address that should not have been set during our course of emulation.
    # Therefore, before attempting to use get_function_data() to test if it's a function pointer,
    # first see if guess_type() will return None while is_loaded() is true.
    # If it doesn't, we know that it shouldn't be a function pointer.
    # (plus it saves on time)
    # TODO: Determine if we could have false negatives.
    #   - this caused a false negatives, so I added the check if offset is the start of a function.
    try:
        if idc.is_loaded(offset) and not idc.guess_type(offset):
            return False
    except TypeError:
        return False
    try:
        get_function_data(offset)
        return True
    except RuntimeError:
        return False
    except Exception as e:
        # If we get any other type of exception raise a more friendly error message.
        raise FunctionTracingError("Failed to retrieve function data from {!r}: {}".format(offset, e))


def convert_reg(reg_name, width):
    """Convert given register name to the register name for the provided width (eg: conver_reg(eax, 8) -> rax)"""
    reg_idx = ida_idp.str2reg(reg_name)
    if reg_idx > 15:  # R15 is index 15.  8-bit registers have indexes above 15 but are 0 indexed, so sub 16
        reg_idx -= 16

    return ida_idp.get_reg_name(reg_idx, width)


def reg2str(register, width=None):
    """Convert given register index to the register name with the provided width (eg: reg2str(0, 8) -> rax)"""
    if not width:
        width = 8 if idc.__EA64__ else 4
    return ida_idp.get_reg_name(register, width)


## The following functions are ports from the Hex-Rays SDK.  Unfortunately, much of the information found online
## incorrectly interpreted these functions and actually don't work properly.  Not entirely sure why the following
## isn't exposed to Python...


def insn_jcc(insn):
    """Determine if an instruction is a Jcc (jump) instruction"""
    return insn.itype in (
        ida_allins.NN_ja,
        ida_allins.NN_jae,
        ida_allins.NN_jb,
        ida_allins.NN_jbe,
        ida_allins.NN_jc,
        ida_allins.NN_je,
        ida_allins.NN_jg,
        ida_allins.NN_jge,
        ida_allins.NN_jl,
        ida_allins.NN_jle,
        ida_allins.NN_jna,
        ida_allins.NN_jnae,
        ida_allins.NN_jnb,
        ida_allins.NN_jnbe,
        ida_allins.NN_jnc,
        ida_allins.NN_jne,
        ida_allins.NN_jng,
        ida_allins.NN_jnge,
        ida_allins.NN_jnl,
        ida_allins.NN_jnle,
        ida_allins.NN_jno,
        ida_allins.NN_jnp,
        ida_allins.NN_jns,
        ida_allins.NN_jnz,
        ida_allins.NN_jo,
        ida_allins.NN_jp,
        ida_allins.NN_jpe,
        ida_allins.NN_jpo,
        ida_allins.NN_js,
        ida_allins.NN_jz,
    )


def insn_default_opsize_64(insn):
    """Determine, based on the instruction type, if the instruction, by default, is 64-bit"""
    if insn_jcc(insn):
        return True

    return insn.itype in (
        # use ss
        ida_allins.NN_pop,
        ida_allins.NN_popf,
        ida_allins.NN_popfq,
        ida_allins.NN_push,
        ida_allins.NN_pushf,
        ida_allins.NN_pushfq,
        ida_allins.NN_retn,
        ida_allins.NN_retf,
        ida_allins.NN_retnq,
        ida_allins.NN_retfq,
        ida_allins.NN_call,
        ida_allins.NN_callfi,
        ida_allins.NN_callni,
        ida_allins.NN_enter,
        ida_allins.NN_enterq,
        ida_allins.NN_leave,
        ida_allins.NN_leaveq,
        # near branches
        ida_allins.NN_jcxz,
        ida_allins.NN_jecxz,
        ida_allins.NN_jrcxz,
        ida_allins.NN_jmp,
        ida_allins.NN_jmpni,
        ida_allins.NN_jmpshort,
        ida_allins.NN_loop,
        ida_allins.NN_loopq,
        ida_allins.NN_loope,
        ida_allins.NN_loopqe,
        ida_allins.NN_loopne,
        ida_allins.NN_loopqne,
    )


def ad16(insn):
    """Determine if the current addressing is 16-bit"""
    p = insn.auxpref & (0x00000008 | 0x00000010 | 0x00001000)
    return p == 0x00001000 or p == 0x00000008


def op16(insn):
    """Determine if the current operand size is 32-bit"""
    p = insn.auxpref & (0x00000008 | 0x00000010 | 0x00000800)
    return p == 0x00000800 or p == 0x00000008 or p == 0x00000010 and (insn.insnpref & 8) == 0


def op32(insn):
    """Determine if the current operand size is 32-bit"""
    p = insn.auxpref & (0x00000008 | 0x00000010 | 0x00000800)
    return p == 0 or p == (0x00000008 | 0x00000800) or p == (0x00000010 | 0x00000800) and (insn.insnpref & 8) == 0


def op64(insn):
    """Determine if the current operand size is 64-bit"""
    if not idc.__EA64__:
        return False

    return (insn.auxpref & 0x00000010) != 0 and (
        (insn.insnpref & 8) != 0 or (insn.auxpref & 0x00000800) != 0 and insn_default_opsize_64(insn)
    )


def has_sib(op):
    """Return boolean representation of specflag1 which indicates if there is a SIB or not"""
    return bool(op.specflag1)


def sib_base(insn, op):
    """Calculate the base register number for a phrase/displacment"""
    sib = op.specflag2  # specflag2 holds the SIB if there is one
    base = sib & 7
    if idc.__EA64__ and (insn.insnpref & 1):  # Do we need to convert the base to a 64-bit register number?
        base |= 8  # Upconvert to 64-bit register number if not already

    return base


def sib_index(insn, op):
    """Calculate the index register number for a phrase/displacement"""
    sib = op.specflag2  # specflag2 holds the SIB if there is one
    index = (sib >> 3) & 7
    if idc.__EA64__ and (insn.insnpref & 2):  # Do we need to conver the index to a 64-bit register number?
        index |= 8  # Upconvert to 64-bit register number if not already

    return index


def sib_scale(op):
    """Calculate the scale for the index register (default to 1 if the value is 0)"""
    return 1 << ((op.specflag2 >> 6) & 3)


def x86_base_reg(insn, op):
    """Get the base register of the operand with a displacement (handle 16-bit as well for completeness)"""
    if has_sib(op):
        return sib_base(insn, op)  # base register encoded in the SIB

    if not ad16(insn):
        return op.phrase  # "phrase" contains the base register number

    if signed(op.phrase, get_bits()) == -1:
        return idautils.procregs.sp.reg  # return "*SP" register number (4)

    if op.phrase in (0, 1, 7):  # ([BX+SI], [BX+DI], [BX])
        return ida_idp.str2reg("RBX")  # All versions of *BX return 3

    if op.phrase in (2, 3, 6):  # ([BP+SI], [BP+DI], [BP])
        return ida_idp.str2reg("RBP")  # All versions of *BP return 5

    if op.phrase == 4:  # [SI]
        return ida_idp.str2reg("RSI")

    if op.phrase == 5:  # [DI]
        return ida_idp.str2reg("RDI")

    raise ValueError("Unable to parse x86 base register from instruction")


def x86_index_reg(insn, op):
    """Get the index register (if there is one) (handle 16-bit as well for completeness)"""
    if has_sib(op):
        idx = sib_index(insn, op)
        if idx != 4:
            return idx

        return -1  # There is no index register

    if not ad16(insn):
        return -1

    if op.phrase in (0, 2):  # ([BX+SI], [BP+SI])
        return ida_idp.str2reg("RSI")

    if op.phrase in (1, 3):  # ([BX+DI], [BP+DI])
        return ida_idp.str2reg("RDI")

    if op.phrase in (4, 5, 6, 7):  # ([SI], [DI], [BP], [BX])
        return -1

    raise ValueError("Unable to parse x86 index register from instruction")
