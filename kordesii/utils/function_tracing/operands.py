"""
Interface for operand management.
"""

import collections
import logging
from copy import deepcopy

import ida_frame
import ida_nalt
import ida_typeinf
import ida_ua
import idaapi
import idc
import numpy

from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.exceptions import FunctionTracingError

logger = logging.getLogger(__name__)


class Operand(object):
    """Stores information for a given operand for a specific CPU context state."""

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
        18: 64,  # dt_byte64 -> 512 bit
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
        self._cpu_context = cpu_context
        self._width = None
        self.__insn = None

    def __repr__(self):
        string = "<Operand 0x{:0x}:{} : {} = {!r}".format(self.ip, self.idx, self.text, self.value)
        if self.addr is not None:
            string += " : &{} = 0x{:0x}".format(self.text, self.addr)
        string += " : width = {}>".format(self.width)
        return string

    def __deepcopy__(self, memo):
        # When we deep copy, clear out the __insn attribute so we don't
        # run into any serialization issues with Swig objects.
        deepcopy_method = self.__deepcopy__
        self.__deepcopy__ = None
        self.__insn = None
        copy = deepcopy(self, memo)
        self.__deepcopy__ = deepcopy_method
        return copy

    @property
    def _tif(self):
        tif = ida_typeinf.tinfo_t()
        ida_nalt.get_op_tinfo(tif, self.ip, self.idx)
        return tif

    @property
    def _insn(self):
        if self.__insn:
            return self.__insn
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, self.ip)
        if not insn:
            raise FunctionTracingError("Failed to decode instruction at 0x:{:X}".format(self.ip))
        self.__insn = insn
        return self.__insn

    @property
    def _op(self):
        return self._insn.ops[self.idx]

    @property
    def width(self):
        """
        Based on the dtyp value, the size of the operand in bytes

        :return: size of data type
        """
        if self._width is not None:
            return self._width
        self._width = self.TYPE_DICT[self._op.dtype]
        return self._width

    @property
    def is_hidden(self):
        """
        True if the operand is not part of the visible assembly code.
        (These are for implicit registers like EAX)
        """
        return self.text == "" or self.is_void

    @property
    def is_void(self):
        """
        True if the operand is not valid.
        """
        return self.type == idc.o_void

    @property
    def is_register(self):
        """True if the operand is a single register."""
        return self.type == idc.o_reg

    @property
    def has_register(self):
        """True if the operand contains a register."""
        return self.type in (idc.o_reg, idc.o_displ, idc.o_phrase, idc.o_fpreg, idc.o_trreg, idc.o_creg, idc.o_dbreg)

    @property
    def is_immediate(self):
        """True if the operand is an immediate value."""
        return self.type in (idc.o_imm, idc.o_near, idc.o_far)

    @property
    def is_memory_reference(self):
        """True if the operand is a memory reference."""
        return self.type in (idc.o_mem, idc.o_phrase, idc.o_displ)

    @property
    def has_phrase(self):
        """True if the operand contains a phrase."""
        return self.type in (idc.o_phrase, idc.o_displ)

    @property
    def is_func_ptr(self):
        """True if the operand is a pointer to a function."""
        return utils.is_func_ptr(self.addr or self.value)

    @property
    def offset(self):
        """The offset value if the operand is a displacement."""
        if not self.has_phrase:
            return None
        return utils.signed(self._op.addr, utils.get_bits())

    @property
    def scale(self):
        """The scaling factor of the index if operand is a displacement."""
        if not self.has_phrase:
            return None
        return utils.sib_scale(self._op)

    @property
    def base(self):
        """The value of the base register if operand is a displacement."""
        if not self.has_phrase:
            return None
        base_reg = utils.reg2str(utils.x86_base_reg(self._insn, self._op))
        value = self._cpu_context.registers[base_reg]
        return utils.signed(value, utils.get_bits())

    @property
    def index(self):
        """The value of the index register if operand is a displacement."""
        if not self.has_phrase:
            return None
        index_reg = utils.x86_index_reg(self._insn, self._op)
        if index_reg == -1:
            return 0
        index_reg = utils.reg2str(index_reg)
        value = self._cpu_context.registers[index_reg]
        return utils.signed(value, utils.get_bits())

    def _calc_displacement(self):
        """
        Calculate the displacement offset of the operand's text.

        e.g:
            word ptr [rdi+rbx]

        :return int: calculated value
        """
        addr = self.base + self.index * self.scale + self.offset
        logger.debug(
            "calc_displacement :: Displacement {} -> {} + {}*{} + {} = {}".format(
                self.text, self.base, self.index, self.scale, self.offset, addr
            )
        )
        if addr < 0:
            logger.debug("calc_displacement :: Address is negative, resorting to address of 0.")
            addr = 0

        # Before returning, record the stack variable that we have encountered.
        # Ignore if base is 0, because that means we don't have enough information to designate this to a variable.
        if self.base:
            stack_var = ida_frame.get_stkvar(self._insn, self._op, self.offset)
            if stack_var:
                frame_id = idc.get_frame_id(self.ip)
                member, stack_offset = stack_var
                # If the offset in the member object is different than the given stack_offset
                # then we are indexing into a variable.
                # We need to adjust the address to be pointing to the base variable address.
                var_addr = addr - (stack_offset - member.soff)
                self._cpu_context.variables.add(
                    var_addr, frame_id=frame_id, stack_offset=member.soff, reference=self.ip
                )

        return addr

    @property
    def addr(self):
        """
        Retrieves the referenced memory address of the operand.

        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = None
        if self.has_phrase:
            # These need to be handled in the same way even if they don't contain the same types of data...
            addr = self._calc_displacement()
        elif self.type == idc.o_mem:
            addr = idc.get_operand_value(self.ip, self.idx)
            # Record the global variable before we return.
            self._cpu_context.variables.add(addr, reference=self.ip)
        return addr

    @property
    def base_addr(self):
        """
        Retrieves the referenced memory address of the operand minus any indexing that
        has occurred.

        This is useful for pulling out the un-offseted address within a loop.
        e.g. "movzx   edx, [ebp+ecx*2+var_8]"
        where ecx is the loop index starting at a non-zero value.

        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = self.addr
        if addr is None:
            return None
        if self.has_phrase:
            addr -= self.index * self.scale
        return addr

    @property
    def value(self):
        """
        Retrieve the value of the operand as it is currently in the cpu_context.
        NOTE: We can't cache this value because the value may change based on the cpu context.

        :return int: An integer of the operand value.
        """
        if self.is_hidden:
            return None

        if self.is_immediate:
            value = idc.get_operand_value(self.ip, self.idx)
            # Create variable/reference if global.
            if idc.is_loaded(value):
                self._cpu_context.variables.add(value, reference=self.ip)
            return value

        if self.is_register:
            value = self._cpu_context.registers[self.text]
            # Record reference if register is a variable address.
            if value in self._cpu_context.variables:
                self._cpu_context.variables[value].add_reference(self.ip)
            return value

        # TODO: Determine if this is still necessary.
        # FS, GS (at least) registers are identified as memory addresses.  We need to identify them as registers
        # and handle them as such
        if self.type == idc.o_mem:
            if "fs" in self.text:
                return self._cpu_context.registers.fs
            elif "gs" in self.text:
                return self._cpu_context.registers.gs

        # If a memory reference, return read in memory.
        if self.is_memory_reference:
            addr = self.addr

            # Record referenc if address is a variable address.
            if addr in self._cpu_context.variables:
                self._cpu_context.variables[addr].add_reference(self.ip)

            # If a function pointer, we want to return the address.
            # This is because a function may be seen as a memory reference, but we don't
            # want to dereference it in case it in a non-call instruction.
            # (e.g.  "mov  esi, ds:LoadLibraryA")
            # NOTE: Must use internal function to avoid recursive loop.
            if utils.is_func_ptr(addr):
                return addr

            # Return empty
            if not self.width:
                logger.debug("Width is zero for {}, returning empty string.".format(self.text))
                return b""

            # Otherwise, dereference the address.
            value = self._cpu_context.mem_read(addr, self.width)
            return utils.struct_unpack(value)

        raise FunctionTracingError("Invalid operand type: {}".format(self.type), ip=self.ip)

    @value.setter
    def value(self, value):
        """
        Set the operand to the specified value within the cpu_context.
        """
        # If we are writing to an immediate, I believe they want to write to the memory at the immediate.
        # TODO: Should we fail instead?
        if self.is_immediate:
            offset = self.value
            if idaapi.is_loaded(offset):
                self._cpu_context.mem_write(offset, value)
            return

        if self.is_register:
            # Convert the value from string to integer...
            if isinstance(value, str):
                value = utils.struct_unpack(value)

            # On 64-bit, the destination register must be set to 0 first (per documentation)
            # TODO: Check if this happens regardless of the source size
            if idc.__EA64__ and self.width == 4:  # Only do this for 32-bit setting
                reg64 = utils.convert_reg(self.text, 8)
                self._cpu_context.registers[reg64] = 0

            self._cpu_context.registers[self.text] = value
            return

        # TODO: Determine if this is still necessary.
        # FS, GS (at least) registers are identified as memory addresses.  We need to identify them as registers
        # and handle them as such
        if self.type == idc.o_mem:
            if "fs" in self.text:
                self._cpu_context.registers.fs = value
                return
            elif "gs" in self.text:
                self._cpu_context.registers.gs = value
                return

        if self.is_memory_reference:
            # For data written to the frame or memory, this data MUST be a byte string.
            if numpy.issubdtype(type(value), numpy.integer):
                value = utils.struct_pack(value, width=self.width)
            self._cpu_context.mem_write(self.addr, value)
            return

        raise FunctionTracingError("Invalid operand type: {}".format(self.type), ip=self.ip)


# This is a "lite" version of the Operand class that only allows access only to a few attributes, is read only,
# and not backed by a CPU context.
OperandLite = collections.namedtuple("OperandLite", "ip idx text value")
