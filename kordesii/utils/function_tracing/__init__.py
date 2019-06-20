"""
Provides user-facing API for function_tracing.
"""

# Import functions and classes we want to expose as the API.
from .function_tracer import FunctionTracer, TracerCache, get_tracer, hook_tracers, clear_hooks
from .flowchart import FlowChart, CustomBasicBlock
from .exceptions import *

# Expose constants that may be useful
from .constants import *
# TODO: Can these be generalized for all architectures?
from .x86_64 import STACK_BASE, RSP_OFFSET, RBP_OFFSET

# Import architecture packages to ensure they are registered.
from . import x86_64, ARM
