#
# utils.py
#
# This file contains utility functions utilized throughout the function_tracing package.
#
# version: 0.1
# created: 14 Jun 18
#

# python imports
import parser
import re
import struct

# IDA imports
import idautils
import idaapi
import idc


# Make a list of registers used on x86 CPUs for later use
REG_NAMES = ["RAX", "EAX", "AX", "AH", "AL",
             "RBX", "EBX", "BX", "BH", "BL",
             "RCX", "ECX", "CX", "CH", "CL",
             "RDX", "EDX", "DX", "DH", "DL",
             "RBP", "EBP", "BP", "BPL",
             "RSP", "ESP", "SP", "SPL",
             "RSI", "ESI", "SI", "SIL",
             "RDI", "EDI", "DI", "DIL",
             "R8", "R8D", "R8W", "R8B",
             "R9", "R9D", "R9W", "R9B",
             "R10", "R10D", "R10W", "R10B",
             "R11", "R11D", "R11W", "R11B",
             "R12", "R12D", "R12W", "R12B",
             "R13", "R13D", "R13W", "R13B",
             "R14", "R14D", "R14W", "R14B",
             "R15", "R15D", "R15W", "R15B"]

REG_MAP = {0: "RAX", 1: "RCX", 2: "RDX", 3: "RBX", 4: "RSP", 5: "RBP", 6: "RSI", 7: "RDI",
           8: "R8", 9: "R9", 10: "R10", 11: "R11", 12: "R12", 13: "R13", 14: "R14", 15: "R15"}


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
    orig_shift = (8 * orig_size)
    dest_shift = (8 * dest_size)
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


def get_stack_offset(cpu_context, ip, n):
    """
    Get the stack offset for the operand n at address ip.

    :param cpu_context.ProcessorContext cpu_context: processor context

    :param int ip: EA of interest

    :param int n: Operand of interest (0 - first operand, 1 - second operand, ...)

    :return int: signed offset of operand
    """
    opnd = idc.print_operand(ip, n)
    if not any(stack_reg in opnd for stack_reg in ["rsp", "esp", "rbp", "ebp"]):
        raise ValueError("Opnd {} does not appear to reference the stack.".format(opnd))

    # Pulling offset from within esp
    cmd = idaapi.insn_t()
    idaapi.decode_insn(cmd, ip)
    offset = cmd.ops[n].addr
    width = get_bits()
    if "esp" in opnd or "rsp" in opnd:
        return cpu_context.reg_read("RSP") + signed(offset, width)
    elif "rbp" in opnd or "ebp" in opnd:
        return cpu_context.reg_read("RBP") + signed(offset, width)
    # if "esp" in opnd or "rsp" in opnd:
        # return cpu_context.reg_read("RSP") + offset

    # # signed because operand values need to be negative and IDA wasn't nice enough to do this for us.
    # return cpu_context.reg_read("RBP") + signed(offset)


conversion_width = {
    'h': 16,
    'o': 8,
    'b': 2
}

def calc_displacement(cpu_context, ea, opnd):
    """
    Calculate the displacement offset

    :param int ea: address of interest

    :param int opnd: the operand of interest (0 - first operand, 1 - second operand, ...)

    :return int: calculated value or None
    """
    operand = idc.print_operand(ea, opnd)
    # Store our original value for debugging purposes?
    _operand = operand
    # remove everything before "[" (ie: word ptr [ecx+14])
    operand = operand[operand.find('['):]
    # remote [ ] for sanity
    operand = operand.strip("[ ]")
    # replace any hex values with their integer equivalent (ie: 14h -> 20)
    for m in re.finditer("(?P<val>(([0-9A-Fa-f]+h)|([0-7]+o)|([01]+b)))", operand):
        val = m.group("val")
        _val = str(int(val[:-1], conversion_width.get(val[-1:])))
        operand = operand.replace(val, _val)

    # replace any register name found in opnd with its current value
    for reg_name in REG_NAMES:
        operand = operand.replace(reg_name.lower(), str(cpu_context.reg_read(reg_name)))

    # At this point, our equation should be a string of just numbers and operations
    # Use the python parser module to create code to execute with eval
    equation = parser.expr(operand).compile()
    result = eval(equation)
    #function_tracing_logger.debug("calc_displacement :: Displacement {} -> {}".format(idc.print_operand(ea, opnd), result))
    return result


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


# Table used by struct_unpack and struct_pack functions
struct_unpack_table = {
    1: ('b', 'B'),
    2: ('h', 'H'),
    4: ('l', 'L'),
    8: ('q', 'Q'),
    16: ('q', 'Q'),
}


def struct_unpack(buffer, signed=False, offs=0):
    """
    Unpack a buffer given its length and offset using struct.unpack_from().
    This function will know how to unpack the given buffer by using the lookup table 'struct_unpack_table'
    If the buffer is of unknown length then None is returned. Otherwise the unpacked value is returned.

    :param buffer: data to be unpacked

    :param signed: whether the data is a signed or unsigned value

    :param offs: offset to unpack from

    :return: unpacked data or None
    """
    # Supported length?
    n = len(buffer)

    if n not in struct_unpack_table:
        return None

    # Signed boolean to number, unfortunately the struct_unpack_table is reversed...
    signed = 1 if not signed else 0

    # Unpack
    fmt = "{}{}".format((">" if idaapi.cvar.inf.is_be() else "<"), struct_unpack_table[n][signed])
    if n == 16:
        # Struct can only handle up to 64-bit values...so work in 64-bit chunks        
        return (struct.unpack(fmt, buffer[8:])[0] << 64) | (struct.unpack(fmt, buffer[:8])[0])
    else:
        return struct.unpack_from(fmt, buffer, offs)[0]


def struct_pack(value, signed=False, width=None):
    """
    Pack the supplied value into a string.

    :param value: value to be packed

    :param signed: whether the data is a signed or unsigned value
    :param width:

    :return: packed data or None
    """
    # FIXME: get_byte_width() is to just keep backwards compatibility. Remove this.
    width = width or get_byte_width(value)

    if width not in struct_unpack_table:
        return None

    # Signed boolean to number, unfortunately the struct_unpack_table is reversed...
    signed = 1 if not signed else 0

    # Pack
    fmt = "{}{}".format((">" if idaapi.cvar.inf.is_be() else "<"), struct_unpack_table[width][signed])
    if width == 16:
        # Struct can only handle up to 64-bit values...
        return "{}{}".format(struct.pack(fmt, value & 0xFFFFFFFFFFFFFFFF), struct.pack(fmt, value >> 64))
    else:
        # Need to mask off the size of value to width since pack doesn't truncate...
        return struct.pack(fmt, (value & get_mask(width)))


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
        return struct.unpack('H', struct.pack('f', val))[0]
    elif precision == 2:
        return struct.unpack('Q', struct.pack('d', val))[0]
    else:
        raise ValueError("Precision {} is not valid.".format(precision))


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
        return struct.unpack('f', struct.pack('H', val))[0]
    elif precision == 2:
        return struct.unpack('d', struct.pack('Q', val))[0]
    else:
        raise ValueError("Precision {} is not valid.".format(precision))

    
def get_mask(size):
    """
    Get bit mask based on byte size.

    :param size: number of bytes to obtain mask for

    :return: mask of width size
    """
    return 2**(8 * size) - 1


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


def get_function_data(offset):
    """
    Obtain a idaapi.func_type_data_t object for the function with the provided start EA.

    :param int offset: start EA of function

    :return: idaapi.func_type_data_t object

    :raise RuntimeError: if func_type_data_t object cannot be obtained
    """
    tif = idaapi.tinfo_t()

    # First see if a type is already set.
    if idc.get_type(offset):
        idaapi.get_tinfo(tif, offset)

    else:
        # Otherwise, try to use the Hexrays decompiler to determine function signature.
        # (It's better than IDA's guess_type)
        try:
            # This requires Hexrays decompiler, load it and make sure it's available before continuing.
            if not idaapi.init_hexrays_plugin():
                idc.load_and_run_plugin("hexrays", 0) or idc.load_and_run_plugin("hexx64", 0)
            if not idaapi.init_hexrays_plugin():
                raise RuntimeError('Unable to load Hexrays decompiler.')

            # Pull type from decompiled C code.
            decompiled = idaapi.decompile(offset)
            if decompiled is None:
                raise RuntimeError("Cannot decompile function at 0x{:X}".format(offset))
            decompiled.get_func_type(tif)

            # Save type for next time.
            format = decompiled.print_dcl()
            # The 2's remove the unknown bytes always found at the start and end.
            idc.SetType(offset, "{};".format(format[2:-2]))

        # If we fail, resort to using guess_type+
        except RuntimeError:
            # Documentation states the type must be ';' terminated, also the function name must be inserted
            guessed_type = idc.guess_type(offset)
            if guessed_type is None:
                raise RuntimeError("failed to guess function type for offset 0x{:X}".format(offset))

            func_name = idc.get_func_name(offset)
            if func_name is None:
                raise RuntimeError("failed to get function name for offset 0x{:X}".format(offset))

            guessed_type = re.sub("\(",
                                  " {}(".format(func_name),
                                  "{};".format(guessed_type)
                                  )
            idc.SetType(offset, guessed_type)
            # Try one more time to get the tinfo_t object
            if not idaapi.get_tinfo(tif, offset):
                raise RuntimeError("failed to obtain tinfo_t object for offset 0x{:X}".format(offset))

    funcdata = idaapi.func_type_data_t()
    if not tif.get_func_details(funcdata):
        raise RuntimeError("failed to obtain func_type_data_t object for offset 0x{:X}".format(offset))

    return funcdata
