"""
Interface for operand management.
"""

import collections
import logging
from copy import deepcopy
from typing import Optional

import ida_frame
import ida_nalt
import ida_typeinf
import ida_ua
import idaapi
import idc
import numpy

from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.exceptions import FunctionTracingError
from .x86_64 import ida_intel

logger = logging.getLogger(__name__)


class Operand:
    """Stores information for a given operand for a specific CPU context state."""

    def __init__(self, cpu_context, ip, idx, implied=False, _type=None):
        """
        :param cpu_context: CPU context to pull operand value
        :param ip: instruction pointer
        :param idx: operand number (0 = first operand, 1 = second operand, ...)
        :param _type: Type of operand
            (Sometimes provided to help avoid recomputation.)
        """
        self.ip = ip
        self.idx = idx
        self.implied = implied

        if _type is not None:
            self.type = _type
        else:
            self.type = idc.get_operand_type(ip, idx)

        self._text = None
        self._cpu_context = cpu_context
        self._width = None
        self.__insn = None

    def __repr__(self):
        string = f"<{self.__class__.__name__} 0x{self.ip:0x}:{self.idx} : {self.text} = {self.value!r}"
        if self.addr is not None:
            string += f" : &{self.text} = 0x{self.addr:0x}"
        string += f" : width = {self.width}>"
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
    def _insn(self) -> ida_ua.insn_t:
        if self.__insn:
            return self.__insn
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, self.ip)
        if not insn:
            raise FunctionTracingError("Failed to decode instruction at 0x:{:X}".format(self.ip))
        self.__insn = insn
        return self.__insn

    @property
    def _op(self) -> ida_ua.op_t:
        return self._insn.ops[self.idx]

    def _record_stack_variable(self, addr):
        """
        Record the stack variable encountered at the given address.
        """
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

    @property
    def text(self):
        """
        Obtain the text of the operand, including operands that registers not shown in the UI

        :return: str
        """
        if self._text:
            return self._text

        self._text = idc.print_operand(self.ip, self.idx)
        # An implied (not shown) operand should never be anything other than a register, however it was discovered
        # that IDA will treat the operand as a memory reference if that is how the register was assigned and is the
        # case for checking is_memory_reference
        if self._text == "":
            if self.is_register or self.is_memory_reference:
                self._text = idaapi.get_reg_name(self._op.reg, self.width)
            else:
                raise AssertionError(f"Assumed operand at {hex(self.ip)}:{self.idx} to be register or mem reference")

        return self._text

    @text.setter
    def text(self, value: str):
        """
        Set the text value for the operand.
        """
        self._text = value

    @property
    def width(self):
        """
        Based on the dtyp value, the size of the operand in bytes

        :return: size of data type
        """
        if self._width is None:
            self._width = ida_ua.get_dtype_size(self._op.dtype)
        return self._width

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
    def offset(self) -> Optional[int]:
        """The offset value if the operand is a displacement."""
        return None

    @property
    def base(self) -> Optional[int]:
        """The value of the base register if operand is a displacement."""
        return None

    @property
    def addr(self) -> Optional[int]:
        """
        Retrieves the referenced memory address of the operand.

        This should be overwritten by architecture specific Operand implementations
        if this property is applicable.

        :return int: Memory address or None if operand is not a memory reference.
        """
        return None

    @property
    def value(self):
        """
        Retrieve the value of the operand as it is currently in the cpu_context.
        NOTE: We can't cache this value because the value may change based on the cpu context.

        :return int: An integer of the operand value.
        """
        if self.is_immediate:
            value = self._op.value if self.type == idc.o_imm else self._op.addr
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

        # If a memory reference, return read in memory.
        if self.is_memory_reference:
            addr = self.addr

            # Record reference if address is a variable address.
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
                logger.debug("Width is zero for %s, returning empty string.", self.text)
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
        # Value may be signed.
        if isinstance(value, int) and value < 0:
            value = utils.unsigned(value, bit_width=self.width * 8)

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
            self._cpu_context.registers[self.text] = value
            return

        if self.is_memory_reference:
            # FIXME: Usage of numpy is most likely symptomatic of a bug in an opcode
            #   implementation passing in bad data.
            #   Update this to just is "isinstance" and then fix the buggy opcode.
            # For data written to the frame or memory, this data MUST be a byte string.
            if numpy.issubdtype(type(value), numpy.integer):
                value = utils.struct_pack(value, width=self.width)
            self._cpu_context.mem_write(self.addr, value)
            return

        raise FunctionTracingError(f"Invalid operand type: {self.type}", ip=self.ip)


# This is a "lite" version of the Operand class that only allows access only to a few attributes, is read only,
# and not backed by a CPU context.
OperandLite = collections.namedtuple("OperandLite", "ip idx text value")
