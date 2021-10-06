"""
Interface for instruction management.
"""
import logging
from typing import Optional

from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.ARM.operands import ARMOperand
from kordesii.utils.function_tracing.exceptions import FunctionTracingError
from kordesii.utils.function_tracing.instruction import Instruction
from . import ida_arm

logger = logging.getLogger(__name__)


class ARMInstruction(Instruction):

    _operand_class = ARMOperand

    # Maps condition code to function to check if we can execute.
    _cond_map = {
        ida_arm.cond_t.cEQ: lambda ctx: bool(ctx.registers.z),
        ida_arm.cond_t.cNE: lambda ctx: bool(not ctx.registers.z),
        ida_arm.cond_t.cCS: lambda ctx: bool(ctx.registers.c),
        ida_arm.cond_t.cCC: lambda ctx: bool(not ctx.registers.c),
        ida_arm.cond_t.cMI: lambda ctx: bool(ctx.registers.n),
        ida_arm.cond_t.cPL: lambda ctx: bool(not ctx.registers.n),
        ida_arm.cond_t.cVS: lambda ctx: bool(ctx.registers.v),
        ida_arm.cond_t.cVC: lambda ctx: bool(not ctx.registers.v),
        ida_arm.cond_t.cHI: lambda ctx: bool(ctx.registers.c and not ctx.registers.z),
        ida_arm.cond_t.cLS: lambda ctx: bool(not ctx.registers.c or ctx.registers.z),
        ida_arm.cond_t.cGE: lambda ctx: bool(
            (ctx.registers.n and ctx.registers.v)
            or (not ctx.registers.n and not ctx.registers.v)
        ),
        ida_arm.cond_t.cLT: lambda ctx: bool(
            (ctx.registers.n and not ctx.registers.v)
            or (not ctx.registers.n and ctx.registers.v)
        ),
        ida_arm.cond_t.cGT: lambda ctx: bool(
            not ctx.registers.z
            and (
                (ctx.registers.n and ctx.registers.v)
                or (not ctx.registers.n and not ctx.registers.v)
            )
        ),
        ida_arm.cond_t.cLE: lambda ctx: bool(
            ctx.registers.z
            or (ctx.registers.n and not ctx.registers.v)
            or (not ctx.registers.n and ctx.registers.v)
        ),
        ida_arm.cond_t.cAL: lambda ctx: True,
        ida_arm.cond_t.cNV: lambda ctx: False,
    }

    @property
    def flag_update(self) -> bool:
        """
        Whether the condition flags are updated on the result of the operation.
        (S postfix)
        """
        return bool(self._insn.auxpref & ida_arm.aux_cond)

    def _check_condition(self) -> bool:
        """
        Checks condition flags to determine if instruction should be executed.
        """
        condition = ida_arm.get_cond(self._insn)
        try:
            return self._cond_map[condition](self._cpu_context)
        except IndexError:
            raise FunctionTracingError(f"Invalid condition code: {condition}")

    def _execute(self):
        # First check if conditions allow us to execute the instruction.
        if not self._check_condition():
            logger.debug("Skipping instruction at 0x%X. Condition code fails.", self.ip)
            return

        # Execute instruction.
        super()._execute()

        # If post-index or pre-index with update addressing mode,
        # update operand's base register based on offset.
        if self._insn.auxpref & (ida_arm.aux_wback | ida_arm.aux_wbackldm | ida_arm.aux_postidx):
            if self._insn.auxpref & ida_arm.aux_wbackldm:
                # write back for first operand (LDM/STM instruction)
                operand = self.operands[0]
            else:
                # write back for last operand (! postfix or post-indexed operand)
                operand = self.operands[-1]
            logger.debug("Post-index operation for: %s", operand.text)
            operand.base += operand.offset

