"""
Interface for operand management in x86.
"""

import logging
from typing import Optional

import idc

from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.operands import Operand
from kordesii.utils.function_tracing.x86_64 import ida_intel

logger = logging.getLogger(__name__)


class x86_64Operand(Operand):

    def _calc_displacement(self):
        """
        Calculate the displacement offset of the operand's text.

        e.g:
            word ptr [rdi+rbx]

        :return int: calculated value
        """
        addr = self.base + self.index * self.scale + self.offset
        logger.debug(
            "Calculating operand: %s -> 0x%X + 0x%X*0x%X %s 0x%X = 0x%X" % (
                self.text,
                self.base,
                self.index,
                self.scale,
                "-" if self.offset < 0 else "+",
                abs(self.offset),
                addr
            )
        )
        if addr < 0:
            logger.debug("Address is negative, resorting to address of 0.")
            addr = 0

        return addr

    @property
    def base(self) -> Optional[int]:
        """
        The value of the base register if operand is a displacement.

        e.g.
            [ebp+ecx*2+var_8] -> ebp
        """
        if not self.has_phrase:
            return None
        base_reg = ida_intel.x86_base_reg(self._insn, self._op)
        value = self._cpu_context.registers[utils.reg2str(base_reg)]
        return utils.signed(value)

    @property
    def scale(self) -> Optional[int]:
        """
        The scaling factor of the index if operand is a displacement.

        e.g.
            [ebp+ecx*2+var_8] -> 2
        """
        if not self.has_phrase:
            return None
        return 1 << ida_intel.sib_scale(self._op)

    @property
    def index(self) -> Optional[int]:
        """
        The value of the index register if operand is a displacement.

        e.g.
            [ebp+ecx*2+var_8] -> ecx
        """
        if not self.has_phrase:
            return None
        index_reg = ida_intel.x86_index_reg(self._insn, self._op)
        if index_reg == -1:
            return 0
        index_reg = utils.reg2str(index_reg)
        value = self._cpu_context.registers[index_reg]
        return utils.signed(value)

    @property
    def offset(self) -> Optional[int]:
        """
        The offset value if the operand is a displacement.

        e.g.
            [ebp+ecx*2+var_8] -> var_8
        """
        if not self.has_phrase:
            return None
        return utils.signed(self._op.addr)

    @property
    def addr(self) -> Optional[int]:
        """
        Retrieves the referenced memory address of the operand.

        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = None
        if self.has_phrase:
            # These need to be handled in the same way even if they don't contain the same types of data...
            addr = self._calc_displacement()
            # Before returning, record the stack variable that we have encountered.
            self._record_stack_variable(addr)
        elif self.type == idc.o_mem:
            addr = self._op.addr
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
        # TODO: Determine if this is still necessary.
        # FS, GS (at least) registers are identified as memory addresses.  We need to identify them as registers
        # and handle them as such
        if self.type == idc.o_mem:
            if "fs" in self.text:
                return self._cpu_context.registers.fs
            elif "gs" in self.text:
                return self._cpu_context.registers.gs

        return super().value

    @value.setter
    def value(self, value):
        try:
            logger.debug("0x%X -> %s", value, self.text)
        except TypeError:
            logger.debug("%r -> %s", value, self.text)

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

        # On 64-bit, the destination register must be set to 0 first (per documentation)
        # TODO: Check if this happens regardless of the source size
        if self.is_register and  idc.__EA64__ and self.width == 4:  # Only do this for 32-bit setting
            reg64 = utils.convert_reg(self.text, 8)
            self._cpu_context.registers[reg64] = 0

        super(x86_64Operand, self.__class__).value.__set__(self, value)
