"""
Components for emulating an x86/x64 architecture.
"""

from ..cpu_context import ProcessorContext
from ..registry import registrar
from .registers import ARM_Registers
from .opcodes import OPCODES


STACK_BASE = 0x1180000  # Base address for stack

RSP_OFFSET = 0x800
RBP_OFFSET = 0x400


class ARMProcessorContext(ProcessorContext):
    """Processor context for ARM architecture"""

    ARCH_NAME = "ARM"
    OPCODES = OPCODES

    def __init__(self):
        super(ARMProcessorContext, self).__init__(
            ARM_Registers(), instruction_pointer="pc", stack_pointer="sp", stack_registers=["sp", "wsp"],
        )
        # TODO: Set up stack correctly for ARM
        # # Set up the stack before we go.
        # self.registers.rsp = STACK_BASE - RSP_OFFSET
        # self.registers.rbp = STACK_BASE - RBP_OFFSET
