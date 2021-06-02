"""
Provides user-facing API for function_tracing.
"""

# Import functions and classes we want to expose as the API.
from .emulator import Emulator
from .cpu_context import ProcessorContext
# TODO: Remove import for function_tracer in future release.
from .function_tracer import FunctionTracer, TracerCache, get_tracer, hook_tracers, clear_hooks
from .flowchart import FlowChart, Flowchart, BasicBlock
from .objects import File, RegKey, Service
from .actions import *
from .exceptions import *

# Expose constants that may be useful
from .constants import *

# TODO: Can these be generalized for all architectures?
from .x86_64 import STACK_BASE, RSP_OFFSET, RBP_OFFSET
from .x86_64 import x86_64ProcessorContext
from .ARM import ARMProcessorContext

# Import architecture packages to ensure they are registered.
from . import x86_64, ARM
