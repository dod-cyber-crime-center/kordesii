"""
Interface for operand management in ARM.
"""

import logging
from typing import Optional, List

import ida_ua

from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.ARM import ida_arm, utils as arm_utils
from kordesii.utils.function_tracing.exceptions import FunctionTracingError
from kordesii.utils.function_tracing.operands import Operand

logger = logging.getLogger(__name__)


class ARMOperand(Operand):

    _shift_map = {
        ida_arm.shift_t.LSL: arm_utils.lsl,
        ida_arm.shift_t.LSR: arm_utils.lsr,
        ida_arm.shift_t.ASR: arm_utils.asr,
        ida_arm.shift_t.ROR: arm_utils.ror,
        # rrx requires also passing in carry. (see usage)
        # TODO: Support other shift operations reported in IDA.
        ida_arm.shift_t.UXTX: arm_utils.lsl
    }

    @property
    def has_register(self):
        return super().has_register or self.type in (
            ida_arm.o_shreg, ida_arm.o_reglist, ida_arm.o_creg, ida_arm.o_creglist, ida_arm.o_fpreglist
        )

    @property
    def base(self) -> Optional[int]:
        """The value of the base register if operand is a displacement."""
        if not self.has_phrase:
            return None
        value = self._cpu_context.registers[utils.reg2str(self._op.reg)]
        return utils.signed(value)

    @base.setter
    def base(self, value: int):
        """Sets the value of the base register if operand is a displacement."""
        if not self.has_phrase:
            return
        self._cpu_context.registers[utils.reg2str(self._op.reg)] = value

    @property
    def offset(self) -> Optional[int]:
        """The offset value if the operand is a displacement/phrase."""
        # [R1, R2]
        if self.type == ida_ua.o_phrase:
            second_reg = ida_arm.secreg(self._op)  # pulling the R2
            offset = self._cpu_context.registers[utils.reg2str(second_reg)]
            # We could also have a shift applied in the offset.
            #   [R1, R2, LSL #3]
            offset = self._calc_shift(offset)
            return utils.signed(offset)

        # [R1, #1]
        elif self.type == ida_ua.o_displ:
            return utils.signed(self._op.addr)

        return None

    @property
    def shift_count(self) -> int:
        """The amount to shift (if a shifted register)"""
        if self.type == ida_ua.o_phrase:
            # For a phrase, shift is in op.value
            return self._op.value

        if self.type == ida_arm.o_shreg:
            # Shift can be an immediate or another register.
            # I believe we determine which one it is based on whether op.value is zero.
            count = self._op.value
            if not count:
                count = self._cpu_context.registers[utils.reg2str(ida_arm.secreg(self._op))]
            return count

        return 0  # not shifted

    def _calc_shift(self, value) -> int:
        """
        Calculates the shift applied within the operand.
        This could be applied directly or within the offset of a displacement.
            e.g.
                R2, LSL #3 -> R2 << 3
                R2, LSL R3 -> R2 << R3
                [R1, R2, LSL #3]  -> R2 << 3

        NOTE: Any modifications to the carry flag will be applied only if
             the condition flag is set and the context's ip is the same as the
             address of the operand's instruction.

        :param value: The base value the shift is to be applied to.
        :return: Results of the shift (or original value back if no shift is applicable.)
        """
        count = self.shift_count
        if count > 0:
            shift_op = self._op.specflag2
            if shift_op == ida_arm.shift_t.RRX:  # RRX also requires original carry flag
                carry, value = arm_utils.rrx(self._cpu_context.registers.c, value, count)
            else:
                carry, value = self._shift_map[shift_op](value, count)

            # Update carry flag if condition flag is set for instruction (S postfix)
            # (But only update if context's instruction pointer is still looking at this instruction.)
            if self._insn.auxpref & ida_arm.aux_cond and self._cpu_context.ip == self.ip:
                self._cpu_context.registers.c = carry

        return value

    @property
    def addr(self) -> Optional[int]:
        """
        The referenced memory address of the operand.
        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = None
        if self.has_phrase:
            addr = self.base

            # Ignore including the offset if post indexed.
            #   ie. include offset for [R2, #4] but ignore for [R2], #4
            if not self._insn.auxpref & ida_arm.aux_postidx:
                offset = self.offset
                logger.debug("0x%X + 0x%X = 0x%X", addr, offset, addr + offset)
                addr += self.offset

            if addr < 0:
                logger.debug("Address is negative, resorting to address of 0.")
                addr = 0

            self._record_stack_variable(addr)

        elif self.type == ida_ua.o_mem:
            addr = self._op.addr
            # Record the global variable before we return.
            self._cpu_context.variables.add(addr, reference=self.ip)

        if addr is not None:
            logger.debug("&%s -> 0x%X", self.text, addr)

        return addr

    @property
    def is_signed(self) -> bool:
        """
        Whether the memory addressing is signed.
        """
        return bool(self._insn.auxpref & (ida_arm.aux_sb | ida_arm.aux_sh | ida_arm.aux_sw))

    @property
    def is_register_list(self) -> bool:
        """
        Whether operand is a register list.
        """
        return self.type == ida_arm.o_reglist

    @property
    def register_list(self) -> Optional[List[str]]:
        """
        List of register names if operand is a register list.
        """
        if not self.is_register_list:
            return None
        # Register numbers are stored in a bitmap in specval.
        reg_bitmap = self._op.specval
        return [utils.reg2str(i) for i in range(16) if reg_bitmap & (1 << i)]

    @property
    def value(self):
        # Barrel shifter
        if self.type == ida_arm.o_shreg:
            value = self._cpu_context.registers[utils.reg2str(self._op.reg)]
            value = self._calc_shift(value)
            return value

        # Register list
        if self.type == ida_arm.o_reglist:
            return [self._cpu_context.registers[reg] for reg in self.register_list]

        value = super().value

        # If a memory reference, the final value may be signed.
        if self.is_memory_reference and self.is_signed:
            value = utils.signed(value)

        return value

    @value.setter
    def value(self, value):
        try:
            logger.debug("0x%X -> %s", value, self.text)
        except TypeError:
            logger.debug("%r -> %s", value, self.text)

        # Barrel shifter
        if self.type == ida_arm.o_shreg:
            raise FunctionTracingError(f"Unable to set value to operand with a shift", ip=self.ip)

        # Register list
        if self.type == ida_arm.o_reglist:
            reg_list = self.register_list
            # To set the value for an operand that is a register list, user must provide
            # a list of value of equal size.
            # User can use None to indicate not to update that register.
            if not isinstance(value, list) or len(value) != len(reg_list):
                raise ValueError(f"Operand value for {self.text} must be a list of {len(reg_list)} values.")
            for reg_name, reg_value in zip(reg_list, value):
                if reg_value is not None:
                    self._cpu_context.registers[reg_name] = reg_value
            return

        super(ARMOperand, self.__class__).value.__set__(self, value)
