"""
Function tracing utility which will trace a function to a given EA and provide the value stored in a given operand.idaapi.__struct_unpack_table

This will essentially emulate, on a very primitive level, a x86(_64) cpu during execution and will maintain the stack,
registers, etc.
"""

import logging
import warnings
from builtins import object

from .emulator import Emulator


warnings.warn(
    "The function_tracer module is deprecated. Please create and use an instance of Emulator instead.", DeprecationWarning)

logger = logging.getLogger(__name__)


# Create a global Emulator to keep backwards compatibility with the legacy FunctionTracer and TracerCache.
_emulator = Emulator()


def FunctionTracer(func_ea):
    warnings.warn("FunctionTracer class is deprecated. Please create an instance of Emulator instead.", DeprecationWarning)
    return _emulator


class TracerCache(object):
    def __init__(self):
        warnings.warn("TracerCache is deprecated, please use an instance of Emulator instead.", DeprecationWarning)

    def get(self, ea, default="NOTSET"):
        return _emulator

    def hook(self, name_or_start_ea, func):
        _emulator.hook_call(name_or_start_ea, func)

    def clear_hooks(self):
        _emulator.reset_hooks()


def get_tracer(ea, default="NOTSET"):
    warnings.warn("get_tracer() is deprecated. Please create an instance of Emulator instead.", DeprecationWarning)
    return _emulator


def hook_tracers(name_or_start_ea, func):
    warnings.warn(
        "hook_tracers() is deprecated. Please call hook_call() on an instance of Emulator instead.", DeprecationWarning)
    _emulator.hook_call(name_or_start_ea, func)


def clear_hooks():
    warnings.warn(
        "clear_hooks() is deprecated. Please call clear_hooks() on an instance of Emulator instead.", DeprecationWarning)
    _emulator.reset_hooks()
