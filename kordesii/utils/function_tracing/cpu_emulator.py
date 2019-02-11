"""
Emulates an X86 cpu by "executing" the instructions provided to it.
"""
# Python imports
import numpy
import logging

import idaapi
import idc
import idautils

from . import utils

# create logger
logger = logging.getLogger(__name__)


# Dictionary containing opcode names -> function
OPCODES = {}


def opcode(opcode_name_or_func):
    """
    Registers an opcode for the CPU emulator.
    """
    if callable(opcode_name_or_func):
        # If function, that means no argument was passed in and we should register using the function name.
        func = opcode_name_or_func
        opcode_name = func.__name__.lower()
        OPCODES[opcode_name] = func
        return func

    # Otherwise, register with user provided name
    opcode_name = opcode_name_or_func
    if opcode_name in OPCODES:
        raise ImportError("Duplicate opcode name: {}".format(opcode_name))

    def _wrapper(func):
        # Register function as opcode.
        OPCODES[opcode_name] = func
        return func  # Must return function afterwards.

    return _wrapper


# TODO: Move this into cpu_context module?
class Operand(object):
    """Stores information for a given operand for a specific CPU context state."""

    # __slots__ = ['value', 'width']

    TYPE_DICT = {
        0: 1,  # dt_byte -> 8 bit
        1: 2,  # dt_word -> 16 bit
        2: 4,  # dt_dword -> 32 bit
        3: 4,  # dt_float -> 4 bytes
        4: 8,  # dt_double -> 8 bytes
        5: 0,  # dt_tbyte -> variable
        6: 0,  # packed real format for mc68040
        7: 8,  # dt_qword -> 64 bit
        8: 16,  # dt_byte16 -> 128 bit
        9: 0,  # dt_code -> ptr to code (not used?)
        10: 0,  # dt_void -> none
        11: 6,  # dt_fword -> 48 bit
        12: 0,  # dt_bitfild -> bit field (mc680x0)
        13: 4,  # dt_string -> pointer to asciiz string
        14: 4,  # dt_unicode -> pointer to unicode string
        # 15: 3, # dt_3byte -> no longer used
        16: 0,  # dt_ldbl -> long double (which may be different from tbyte)
        17: 32,  # dt_byte32 -> 256 bit
        18: 64  # dt_byte64 -> 512 bit
    }

    def __init__(self, cpu_context, ip, idx):
        """
        :param cpu_context: CPU context to pull operand value
        :param ip: instruction pointer
        :param idx: operand number (0 = first operand, 1 = second operand, ...)
        """
        self.ip = ip
        self.idx = idx
        self.type = idc.get_operand_type(ip, idx)
        self.text = idc.print_operand(ip, idx)
        self.width = self._get_width()
        self.value = self._get_value(cpu_context)

    def __repr__(self):
        return '<Operand 0x{:0x}:{} : {} = {!r} : width = {}>'.format(
            self.ip, self.idx, self.text, self.value, self.width)

    def _get_width(self):
        """
        Based on the dtyp value, return the size of the operand in bytes

        :return: size of data type
        """
        cmd = idaapi.insn_t()
        idaapi.decode_insn(cmd, self.ip)
        dtype = cmd.ops[self.idx].dtype
        return self.TYPE_DICT[dtype]

    def _get_value(self, cpu_context):
        """
        Function to retrieve the value of the specified operand.

        :param cpu_context: current context of cpu

        :return int: A dword of the operand value.
        """
        # We need to make we have text and it isn't "".  Otherwise it causes weird issues.
        if not self.text:
            return None

        if self.type == idc.o_reg:
            return cpu_context.reg_read(self.text.upper())

        if self.type in [idc.o_displ, idc.o_phrase]:
            # These need to be handled in the same way even if they don't contain the same types of data...
            try:
                # TODO: Can this function be generalized to work with all registers?
                offset = utils.get_stack_offset(cpu_context, self.ip, self.idx)

            except ValueError:  # A TypeError indicates that the displacement is NOT a stack variable [ebp+8]
                return utils.calc_displacement(cpu_context, self.ip, self.idx)

            else:
                # Need to check for "lea" instructions here, or the value pointed to, not the pointer value is returned
                if idc.print_insn_mnem(self.ip) == "lea":
                    return offset

                frame_data = cpu_context.mem_read(offset, self.width)
                return utils.struct_unpack(frame_data)

        if self.type == idc.o_mem:
            # Need to check for "lea" here also, for the same reason as above
            if idc.print_insn_mnem(self.ip) == "lea":
                return idc.get_operand_value(self.ip, self.idx)

            # FS, GS (at least) registers are identified as memory addresses.  We need to identify them as registers
            # and handle them as such
            if "fs" in self.text:
                return cpu_context.reg_read("fs")
            elif "gs" in self.text:
                return cpu_context.reg_read("gs")

            # Operand could be a function pointer, in which case, we should not be reading from memory.
            operand = idc.get_operand_value(self.ip, self.idx)
            try:
                # If no RuntimeError is generated, that's enough to indicate utils.get_function_data returned a funcdata object
                # Note, bool(utils.get_function_data(operand)) does not work...
                utils.get_function_data(operand)
                is_func_ptr = True
            except RuntimeError:
                is_func_ptr = False

            if is_func_ptr:
                result = operand
            else:
                result = cpu_context.mem_read(operand, self.width)
                result = utils.struct_unpack(result)

            return result

        if self.type in [idc.o_imm, idc.o_near]:
            return idc.get_operand_value(self.ip, self.idx)


# Dictionary containing builtin function names -> function
BUILTINS = {}


def builtin_func(builtin_name_or_func):
    """
    Registers a builtin for the CPU emulator
    """
    if callable(builtin_name_or_func):
        # If function, that means no argument was passed in and we should register using the function name.
        func = builtin_name_or_func
        builtin_name = func.__name__.lower()
        BUILTINS[builtin_name] = func
        return func

    # Otherwise, register with user provided name
    builtin_name = builtin_name_or_func
    if builtin_name in BUILTINS:
        raise ImportError("Duplicate builtin name: {}".format(builtin_name))

    def _wrapper(func):
        # Register function as builtin.
        BUILTINS[builtin_name] = func
        return func  # Must return function afterwards.

    return _wrapper


# TODO: Can this be moved into the Operand class?
def set_operand_value(cpu_context, ip, value, opnd, optype, width=None):
    """
    Function to set the operand to the specified value.

    :param cpu_context: current context of cpu
    :param ip: instruction pointer
    :param value: value to set operand to
    :param opnd: value returned by idc.print_operand()
    :param optype: value returned by idc.get_operand_type()
    :param width: byte width of the operand value being set

    """
    if optype == idc.o_reg:
        # Convert the value from string to integer...
        if isinstance(value, str):
            value = utils.struct_unpack(value)

        cpu_context.reg_write(opnd.upper(), value)

    elif optype in [idc.o_phrase, idc.o_displ]:
        # For data written to the frame or memory, this data MUST be in string form so convert it
        if numpy.issubdtype(type(value), numpy.integer):
            value = utils.struct_pack(value, signed=(value < 0), width=width)

        # These need to be handled in the same way even if they don't contain the same types of data.
        try:
            offset = utils.get_stack_offset(cpu_context, ip, 0)

        except ValueError:   # Not a stack variable, calculate the displacement and set it using .memctrlr
            addr = utils.calc_displacement(cpu_context, ip, 0)
            cpu_context.mem_write(addr, value)

        else:
            cpu_context.mem_write(offset, value)

    elif optype == idc.o_mem:
        # FS, GS are identified as memory addresses, rather use them as registers
        if "fs" in opnd:
            cpu_context.reg_write("FS", value)
        elif "gs" in opnd:
            cpu_context.reg_write("GS", value)
        else:
            if numpy.issubdtype(type(value), numpy.integer):
                value = utils.struct_pack(value, signed=(value < 0), width=width)

            cpu_context.mem_write(idc.get_operand_value(ip, 0), value)

    elif optype == idc.o_imm:
        offset = idc.get_operand_value(ip, 0)
        if idaapi.is_loaded(offset):
            cpu_context.mem_write(offset, value)


def get_operands(cpu_context, ip):
    """
    Gets the Operand objects of all operands in the current instruction and returns them in a list.

    :param cpu_context: current context of cpu
    :param ip: instruction pointer

    :return: list of operand values for instruction
    """
    operands = []
    cmd = idaapi.insn_t()
    inslen = idaapi.decode_insn(cmd, ip)
    for i in xrange(inslen):
        try:
            operands.append(Operand(cpu_context, ip, i))
        except (IndexError, RuntimeError):
            # For some reason, IDA will identify more operands than there actually are causing an issue
            # Just break out of the loop
            # IDA 7 throws RuntimeError instead of IndexError
            break

    return operands


def get_max_operand_size(operand_values):
    """
    Given the list of named tuples containing the operand value and bit width, determine the largest bit width.

    :param operand_values: list of named tuples containing keys "value" and "opwidth"

    :return: largest "opwidth" value in list of named tuples
    """
    return max(operand.width for operand in operand_values)
    

def get_min_operand_size(operand_values):
    """
    Given the list of named tuples containing the operand value and bit width, determine the smallest bit width.

    :param operand_values: list of named tuples containing keys "value" and "opwidth"

    :return: smallest "opwidth" value in list of named tuples
    """
    return min(operand.width for operand in operand_values)


def execute(cpu_context, ip):
    """
    "Execute" the instruction at IP.  The RIP/EIP register will be set to the value supplied in IP so that it is
    correct.

    :param cpu_context: the current cpu context

    :param ip: instruction pointer
    """
    cpu_context.reg_write("RIP", ip)

    mnem = idc.print_insn_mnem(ip)
    # Determine if a rep* instruction and treat it as it's own opcode.
    # TODO: Add support for emulating these rep opcodes.
    if idc.get_wide_byte(ip) in (0xf2, 0xf3):
        _mnem = idc.GetDisasm(ip)  # IDA pro never has operands for rep opcodes.
        if _mnem.startswith('rep'):
            mnem = _mnem

    # TODO: Perhaps the Operand objects should be initialized and accessed from the cpu_context?
    operands = get_operands(cpu_context, ip)

    instruction = OPCODES.get(mnem)
    if instruction:
        instruction(cpu_context, ip, mnem, operands)


def setup():
    """Initial setup that needs to be done before the emulator can be used."""
    # Import opcodes and builtin functions to get them registered.
    # TODO: Import different opcodes and builtins based on architecture.
    from . import opcodes
    from . import builtin_funcs
