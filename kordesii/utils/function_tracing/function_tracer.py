"""
Function tracing utility which will trace a function to a given EA and provide the value stored in a given operand.idaapi.__struct_unpack_table

This will essentially emulate, on a very primitive level, a x86(_64) cpu during execution and will maintain the stack,
registers, etc.
"""

import logging
from builtins import object
from typing import Tuple, List, Generator

import idaapi

from . import builtin_funcs
from .cpu_context import ProcessorContext
from .flowchart import FlowChart

logger = logging.getLogger(__name__)


class FunctionTracer(object):
    """
    This class should be instantiated by the user in order to trace a function.  Ideally, the object will be stored
    for future use should the caller expect the function traced to be analyzed multiple times.

    To use, the caller will supply the function address (or any address within the function), the address where the
    value of interest is set, the operand containing the value of interest, and optionally a list of arguments passed
    to the function.  The list of arguments will be used to set argument values for a more complete assessment of the
    function.

    The FunctionTracer object will utilize the IDAPython FlowChart object, with custom BasicBlocks.  The FlowChart
    object is utilized to efficiently grab all the instructions which are known to be executed sequentially, as well
    as ensure that the function is traced using appropriate code paths to the interesting ea.  A "snapshot" of the
    CPU register state and stack will be copied and stored for each custom BasicBlock.  The idea behind storing this
    "snapshot" is that if the function needs to be traced multiple times, the "snapshot" data can be utilized to
    initialize the state of execution when a previously unanalyzed block is being inspected rather than having to
    completely reanalyze the entire function again.
    """

    def __init__(self, func_ea):
        """
        :param func_ea: any address in the function of interest
        """
        # FIXME: Importing here to prevent cyclic imports.
        from kordesii.utils import decoderutils

        self.func_obj = decoderutils.SuperFunc_t(func_ea)
        self.func_ea = self.func_obj.start_ea
        # Create the graph object of the function
        self.flowchart = FlowChart(self.func_ea)
        self._hooks = {}

    def __repr__(self):
        return "<FunctionTracer for function at 0x{:X}>".format(self.func_ea)

    def iter_context_at(self, ea, depth=0, exhaustive=True) -> Generator[ProcessorContext, None, None]:
        """
        Iterate over cpu context for instructions up to, but not including, a given ea.

        >>> ea = 0x1001b9ad
        >>> ft = FunctionTracer(ea)
        >>> for cpu_context in ft.iter_context_at(ea):
        >>>     print cpu_context

        :param int ea: ea of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)
        :param bool exhaustive: If true, all paths for each depth is processed
            if false, only the first path for each depth is processed.
            (defaults to exhaustive)

        :yield: cpu_context or None (if ea is the function's first address)
        """
        if depth < 0:
            raise ValueError("Depth must be a positive integer.")

        if ea not in self.func_obj:
            raise ValueError("Address 0x{:08X} not within function at 0x{:08X}".format(ea, self.func_obj.start_ea))

        # Obtaining the context consists of tracing up to, but not including ea, unless ea is the first instruction.

        for path_block in self.flowchart.get_paths(ea):
            with builtin_funcs.hooks(self._hooks):
                if not depth:
                    yield path_block.cpu_context(ea)
                    continue

                # Pull contexts from caller functions first.
                yielded = False
                for call_ea in self.func_obj.xrefs_to:
                    if call_ea in self.func_obj:
                        logger.debug("Ignoring recursive function call at 0x{:08X}".format(call_ea))
                        continue
                    tracer = get_tracer(call_ea, None)
                    if tracer:
                        for context in tracer.iter_context_at(call_ea, depth=depth - 1, exhaustive=exhaustive):
                            # increase the sp to account for the return address that gets pushed
                            # onto the stack so that we are aligned correctly.
                            context.sp -= context.byteness

                            # yield a context containing the caller executed first.
                            yield path_block.cpu_context(ea, init_context=context)
                            yielded = True
                # If we didn't yield, then we hit a function that has no callers or valid contexts.
                if not yielded:
                    yield path_block.cpu_context(ea)

            # break and don't process other paths if not exhaustive.
            if not exhaustive:
                break

    def context_at(self, ea, depth=0):
        """
        Obtain a cpu context for instructions up to, but not including, a given ea.

        :param int ea: ea of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)

        :return: cpu_context or None
        :rtype: ProcessorContext
        """
        for ctx in self.iter_context_at(ea, depth=depth):
            return ctx

    def iter_operand_value(self, ea, index, depth=0, exhaustive=True):
        """
        Trace the function to the specified ea and yield all possible values for the operand.
        This is a helper wrapper for extracting the context and then retrieving either
        the memory address or raw value from the operand.

        NOTE: We are using "get_operand_value" to help show this is the equivalent to
        idc.get_operand_value() but pulls from emulated data.


        >>> ft = FunctionTracer(0x1001b9a0)
        >>> for ctx, val in ft.iter_operand_value(0x1001b9ad, 0):
        >>>     print "Val for opnd0 at 0x1001b9ad = 0x{:x}".format(val)

        :param int ea: address to trace to
        :param int index: the operand of interest (0 - first operand, 1 - second operand, ...)
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)
        :param bool exhaustive: If true, all paths for each depth is processed
            if false, only the first path for each depth is processed.
            (defaults to exhaustive)

        :yield tuple: (context at ea, operand value)
        """
        values = set()

        # Iterate all the nodes to obtain the CPU context
        for cpu_context in self.iter_context_at(ea, depth=depth, exhaustive=exhaustive):
            operand = cpu_context.operands[index]
            # Pass memory address if there is one, otherwise pass the value.
            value = operand.addr or operand.value
            # value = cpu_context.get_operand_value(index, data_size, data_type=data_type, ip=ea)
            # Prevent returning multiple values which are the same....
            if value in values:
                logger.debug("trace :: value 0x{:X} already returned.".format(value))
                continue

            values.add(value)
            yield cpu_context, value

    def get_operand_value(self, ea, index, depth=0):
        """
        Trace the function to the specified ea and return the value for the specified operand.
        This is a helper wrapper for extracting the context and then retrieving either
        the memory address or raw value from the operand.

        NOTE: We are using "get_operand_value" to help show this is the equivalent to
        idc.get_operand_value() but pulls from emulated data.

        >>> ft = FunctionTracer(0x1001b9a0)
        >>> val = ft.get_operand_value(0x1001b9ad, 0)
        >>> print "Val for opnd0 at 0x1001b9ad = 0x{:x}".format(val)

        :param int ea: address to trace to
        :param int opnd: the operand of interest (0 - first operand, 1 - second operand, ...)
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)

        :returns tuple: (context at ea, operand value)
        """
        for cpu_context, value in self.iter_operand_value(ea, index, depth=depth):
            return cpu_context, value

    def iter_function_args(self, ea, depth=0, exhaustive=True, num_args=None):
        """
        Given the EA of a function call, attempt to determine the number of arguments passed to the function and
        return those values to the caller.  Additionally, give back the context as well since it may be useful.

        >>> ft = FunctionTracer(0x1001b9a0)
        >>> call_addr = 0x1001b9d0
        >>> for context, args in ft.iter_function_args(call_addr):
        >>>     print "Args for call at 0x{:X}: {}".format(call_addr, ", ".join(args))

        :param int ea: address containing the function call of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)
        :param bool exhaustive: If true, all paths for each depth is processed
            if false, only the first path for each depth is processed.
            (defaults to exhaustive)
        :param int num_args: Force a specific number of arguments.
            If not provided, number of arguments is determined by the disassembler.
            Extra arguments not defined by the disassembler are assumed to be 'int' type.

        :yield tuple: (context at ea, list of function parameters passed to called function in order)
        """
        # Iterate all the paths leading up to ea
        for cpu_context in self.iter_context_at(ea, depth=depth, exhaustive=exhaustive):
            func_ea = cpu_context.operands[0].value
            yield cpu_context, cpu_context.get_function_args(func_ea, num_args=num_args)

    def get_function_args(self, ea, depth=0, num_args=None):
        """
        Simply calls iter_function_args with the provided ea and returns the first set of arguments.

        >>> ft = FunctionTracer(0x1001b9a0)
        >>> call_addr = 0x1001b9d0
        >>> context, args = ft.get_function_args(call_addr):
        >>> print "Args for call at 0x{:X}: {}".format(call_addr, ", ".join(args))

        :param int ea: address containing the function call of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)
        :param int num_args: Force a specific number of arguments.
            If not provided, number of arguments is determined by the disassembler.
            Extra arguments not defined by the disassembler are assumed to be 'int' type.

        :return tuple: (context at ea, list of function parameters passed to called function in order)
        :rtype: Tuple[ProcessorContext, List]
        """
        for cpu_context, args in self.iter_function_args(ea, depth=depth, num_args=num_args):
            return cpu_context, args

    def hook(self, name_or_start_ea, func):
        """
        Hooks the given name with a custom user defined function.
        Useful for emulating the effects of a function or reporting data.

        :param name_or_start_ea: Name or starting address of the function to hook (e.g. 'base64')
        :param func: Function to run while emulating a call to that function.
            Function must accept 3 arguments: cpu_context, func_name, and func_args and
            may return a value to be set to the rax register (or equivalent)
        :return:
        """
        if isinstance(name_or_start_ea, str):
            name_or_start_ea = name_or_start_ea.lower()

        self._hooks[name_or_start_ea] = func

    def clear_hooks(self):
        """
        Clears all previously set hooks.
        """
        self._hooks = {}


class TracerCache(object):
    """
    Class containing a cache of all tracer objects that are used within a decoder to avoid having to do all the
    reinitialization work on subsequent uses.
    """

    def __init__(self):
        self._tracers = {}
        self._hooks = {}

    def get(self, ea, default="NOTSET"):
        # type: (int, object) -> FunctionTracer
        """
        Get either an existing tracer for a provided EA, or create a new one.

        :param int ea: address within a function for which to retrieve a tracer
        :param default: What to return, if anything, when a function cannot be created for EA
        :return: FunctionTracer object or default
        :raises: KeyError
        """
        func = idaapi.get_func(ea)
        if not func:
            if default != "NOTSET":
                return default
            else:
                raise KeyError("Unable to create tracer")

        try:
            return self._tracers[func.start_ea]
        except KeyError:
            tracer = FunctionTracer(ea)
            for name_or_start_ea, func_hook in list(self._hooks.items()):
                tracer.hook(name_or_start_ea, func_hook)
            self._tracers[func.start_ea] = tracer
            return tracer

    def hook(self, name_or_start_ea, func):
        """
        Hooks the given name with a custom user defined function.
        Useful for emulating the effects of a function or reporting data.
        All tracers produced will contain this hook when used here.

        :param name_or_start_ea: Name or starting address of the function to hook (e.g. 'base64')
        :param func: Function to run while emulating a call to that function.
            Function must accept 3 arguments: cpu_context, func_name, and func_args and
            may return a value to be set to the rax register (or equivalent)
        :return:
        """
        if isinstance(name_or_start_ea, str):
            name_or_start_ea = name_or_start_ea.lower()

        # Hook already created tracers.
        for tracer in list(self._tracers.values()):
            tracer.hook(name_or_start_ea, func)

        # Save hook for future tracers.
        self._hooks[name_or_start_ea] = func

    def clear_hooks(self):
        """Clears all previously set hooks."""
        self._hooks = {}
        for tracer in list(self._tracers.values()):
            tracer.clear_hooks()


# Create a global TracerCache that can be used throughout.
_tracer_cache = TracerCache()
get_tracer = _tracer_cache.get
hook_tracers = _tracer_cache.hook
clear_hooks = _tracer_cache.clear_hooks
