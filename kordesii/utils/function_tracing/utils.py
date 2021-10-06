"""
This file contains utility functions utilized throughout the function_tracing package.
"""
from __future__ import annotations

import logging
import re
import string
import struct
from typing import TYPE_CHECKING

import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_nalt
import ida_typeinf
import idaapi
import idc

from .exceptions import FunctionTracingError
from ..utils import is_x86_64, is_ARM  # TODO: Remove usage where possible.

if TYPE_CHECKING:
    from .operands import Operand


logger = logging.getLogger(__name__)


class SetTypeException(Exception):
    pass


def signed(n, bit_width=None):
    """
    Convert an unsigned integer to a signed integer

    :param uint n: value to convert
    :param int bit_width: bit width of n
        Defaults to architecture addressing size.

    :return int: signed conversion
    """
    if bit_width is None:
        bit_width = get_bits()
    if n >> (bit_width - 1):  # Is the hi-bit set?
        return n - (1 << bit_width)

    return n


def unsigned(n, bit_width=None):
    """
    Convert a signed integer to an unsigned integer

    :param sint n: value to convert
    :param in bit_width: bit width of n
        Defaults to architecture addressing size.

    :return int: unsigned conversion
    """
    if bit_width is None:
        bit_width = get_bits()
    return n & ((1 << bit_width) - 1)


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
    return (1 << (8 * size)) - 1


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
    if not ida_hexrays.init_hexrays_plugin():
        if is_x86_64():
            idc.load_and_run_plugin("hexrays", 0) or idc.load_and_run_plugin("hexx64", 0)
        else:
            idc.load_and_run_plugin("hexarm", 0) or idc.load_and_run_plugin("hexarm64", 0)
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Unable to load Hexrays decompiler.")

    decompiled = None
    offsets_to_decompile = [offset] # LIFO list of offsets to try to decompile
    offsets_attempted = set()       # Offsets already attempted to decompile, whether successful or not
    offsets_decompiled = set()      # Set of offsets that successfully decompiled
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


def sanitize_func_name(func_name):
    """Sanitizes the IDA function names to it's core name."""
    # remove the extra "_" IDA likes to add to the function name.
    if func_name.startswith("_"):
        func_name = func_name[1:]

    # Remove the numbered suffix IDA likes to add to duplicate function names.
    func_name = re.sub("_[0-9]+$", "", func_name)

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
