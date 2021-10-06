"""
Interface for instruction management.
"""
import logging

import idc

from kordesii.utils.function_tracing.instruction import Instruction
from kordesii.utils.function_tracing.x86_64.operands import x86_64Operand

logger = logging.getLogger(__name__)


class x86_64Instruction(Instruction):

    _operand_class = x86_64Operand

    def _execute(self):
        # Before executing, determine if a rep* instruction and add termination condition.
        term_condition = None
        if idc.get_wide_byte(self.ip) in (0xF2, 0xF3):
            text = self.text  # IDA pro never has operands for rep opcodes, we need to look at the text.
            if text.startswith("rep "):
                term_condition = lambda ctx: ctx.registers.ecx == 0
                term_condition.unconditional = True
            elif text.startswith(("repe ", "repz ")):
                term_condition = lambda ctx: ctx.registers.ecx == 0 or ctx.registers.zf == 0
                term_condition.unconditional = False
            elif text.startswith(("repne ", "repnz ")):
                term_condition = lambda ctx: ctx.registers.ecx == 0 or ctx.registers.zf == 1
                term_condition.unconditional = False

        # Execute like normal if not a rep instruciton.
        if not term_condition:
            super()._execute()
            return

        # Skip if user disabled all rep instruction.
        if self._cpu_context.emulator.disabled_rep:
            logger.debug("Ignoring rep instruction at 0x%X: DISABLED.", self.ip)
            return

        # As a safety measure, don't allow rep instructions to surpass
        # our max memory read limit.
        # Only do this check if the terminating condition is unconditional, otherwise
        # this number usually big because it expects zf to be toggled.
        if (
                term_condition.unconditional
                and self._cpu_context.registers.ecx > self._cpu_context.memory.MAX_MEM_READ
        ):
            logger.warning(
                "Emulation attempted to read %s instruction %d times. "
                "Ignoring instruction.", self.mnem, self._cpu_context.registers.ecx
            )
            return

        # Execute instruction ecx number of times or when terminal condition applies.
        logger.debug("Emulating %s instruction %d times.", self.mnem, self._cpu_context.registers.ecx)
        count = 0
        while not term_condition(self._cpu_context):
            super()._execute()
            self._cpu_context.registers.ecx -= 1
            # Stop if we are iterating too much.
            count += 1
            if count > self._cpu_context.memory.MAX_MEM_READ:
                logger.warning("Looped too many times, exiting prematurely.")
                break
