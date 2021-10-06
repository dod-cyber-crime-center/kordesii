"""
Components for emulating an ARM architecture.
"""
from .instruction import ARMInstruction
from ..cpu_context import ProcessorContext
from .registers import ARM_Registers
from .opcodes import OPCODES
from ..utils import get_bits


STACK_BASE = 0x1180000  # Base address for stack

SP_OFFSET = 0x800
FP_OFFSET = 0x400


class ARMProcessorContext(ProcessorContext):
    """Processor context for ARM architecture"""

    OPCODES = OPCODES.copy()
    _instruction_class = ARMInstruction

    def __init__(self, emulator):
        super().__init__(
            emulator,
            ARM_Registers(),
            instruction_pointer="pc",
            stack_pointer="sp",
            return_register="x0",  # TODO: Specify r0 or x0 based on bitness?
        )
        # Set up the stack before we go.
        self.registers.sp = STACK_BASE - SP_OFFSET
        if get_bits() == 64:
            self.registers.x29 = STACK_BASE - FP_OFFSET
        else:
            self.registers.r11 = STACK_BASE - FP_OFFSET
