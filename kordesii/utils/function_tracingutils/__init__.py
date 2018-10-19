"""
Provides user-facing API for function_tracingutils.
"""

# Import functions and classes we want to expose as the API.
from .function_tracer import FunctionTracer
from .flowchart import FlowChart, CustomBasicBlock

# Expose constants that may be useful
from .constants import *
from .cpu_context import ProcessorContext as _ProcessorContext
STACK_BASE = _ProcessorContext.STACK_BASE
STACK_LIMIT = _ProcessorContext.STACK_LIMIT
RSP_OFFSET = _ProcessorContext.RSP_OFFSET
RBP_OFFSET = _ProcessorContext.RBP_OFFSET
