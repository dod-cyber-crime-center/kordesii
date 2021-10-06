"""
Components for emulating an x86/x64 architecture.
"""
from .instruction import x86_64Instruction
from ..cpu_context import ProcessorContext
from .registers import x86_64_Registers
from .opcodes import OPCODES
from . import fpu_opcodes  # trigger registration


STACK_BASE = 0x1180000  # Base address for stack

RSP_OFFSET = 0x800
RBP_OFFSET = 0x400


class x86_64ProcessorContext(ProcessorContext):
    """Processor context for x86/x64 architecture"""

    OPCODES = OPCODES.copy()
    _instruction_class = x86_64Instruction

    def __init__(self, emulator):
        super(x86_64ProcessorContext, self).__init__(
            emulator,
            registers=x86_64_Registers(),
            instruction_pointer="rip",
            stack_pointer="rsp",
            return_register="rax",
        )
        # Set up the stack before we go.
        self.registers.rsp = STACK_BASE - RSP_OFFSET
        self.registers.rbp = STACK_BASE - RBP_OFFSET
