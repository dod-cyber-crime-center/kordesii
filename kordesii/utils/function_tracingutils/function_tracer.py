"""
Function tracing utility which will trace a function to a given EA and provide the value stored in a given operand.idaapi.__struct_unpack_table

This will essentially emulate, on a very primitive level, a x86(_64) cpu during execution and will maintain the stack,
registers, etc.
"""

# Python imports
from operator import attrgetter
from copy import copy, deepcopy
import parser
import logging
import collections
import struct

# IDAPython imports
import idaapi
import idautils
import idc

# kordesii imports
import kordesii.kordesiiidahelper as kordesiiidahelper

# Import FlowChart functionality and CPU implementation
from .constants import *
from .flowchart import FlowChart, CustomBasicBlock
from .utils import struct_unpack, struct_pack, get_bits, get_stack_offset, calc_displacement, get_function_data, get_mask, REG_MAP


# HACKY work around for allowing for enabling/disabling of debug statements
import os
function_tracing_logger = logging.getLogger("function_tracingutils")
DEBUG = os.environ.get("ENABLE_DEBUG", "False")
if DEBUG == "True":
    function_tracing_logger.debug = kordesiiidahelper.append_debug


class FunctionTracer(object):
    """
    This class should be instantiated by the user in order to trace a function.  Ideally, the object will be stored
    for future use should the caller expect the function traced to be analyzed multiple times.  
    
    To use, the caller will supply the function address (or any address within the function), the address where the 
    value of interest is set, the operand containing the value of interest, and optionally a list of arguments passed 
    to the function.  The list of arguments will be used to set argument values for a more complete assesment of the 
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
        self.func_obj = idaapi.get_func(func_ea)
        self.func_ea = self.func_obj.startEA
        # Create the graph object of the function
        self.flowchart = FlowChart(self.func_ea, node_type=CustomBasicBlock)
        # The following dictionary contains an entry for every idaapi.BasicBlock.startEA contained in the function.
        # Each dictionary entry contains a list of BlockStateNode objects for every path in which the BasicBlock
        # appears.  When a block is requested, this list will be used to walk the associated path backwards looking
        # for states which have not been obtained and will begin executing the instructions on the path from that
        # node forward.
        self._path_cache = collections.defaultdict(list)
        self._gen_cache = {}

        # TODO: How can we actually provide function parameters with the way this framework has been implemented?
        #       There would need to be a way to send the args to the FlowChart, which would then somehow inform
        #       the first context created of what data needs to be initialized differing from the default.

    def __repr__(self):
        return "<FunctionTracer for function at 0x{:X}>".format(self.func_ea)

    def context_at_iter(self, ea):
        """
        Iterate over cpu context for instructions up to, but not including, a given ea.

        >>> ea = 0x1001b9ad
        >>> ft = FunctionTracer(ea)
        >>> for cpu_context in ft.context_at_iter(ea):
        >>>     print cpu_context

        :param int ea: ea of interest

        :yield: cpu_context or None (if ea is the function's first address)
        """
        # Obtaining the context consists of tracing up to, but not including ea, unless ea is the first instruction.  
        if ea == idc.GetFunctionAttr(ea, idc.FUNCATTR_START):
            # Return None since a context can't be built if there is no code to "execute"
            return

        # Get all the CodeRefs to ea and trace to each of those.
        code_refs = idautils.CodeRefsTo(ea, True)
        for code_ref in code_refs:
            for pb in self.flowchart.get_paths(code_ref):
                yield pb.cpu_context(code_ref)

    def context_at(self, ea):
        """
        Obtain a cpu context for instructions up to, but not including, a given ea.

        >>> ea = 0x1001b9ad
        >>> ft = FunctionTracer(ea)
        >>> cpu_context = ft.context_at(ea):
        >>> print cpu_context

        :param int ea: ea of interest

        :return: cpu_context or None
        """
        for ctx in self.context_at_iter(ea):
            return ctx

    def trace_iter(self, ea, opnd, data_type, data_size, include_inst=False):
        """
        Trace the function to the specified ea and yield all possible values for the operand.

        >>> ft = FunctionTracer(0x1001b9a0)
        >>> for val in ft.trace_iter(0x1001b9ad, 0):
        >>>     print "Val for opnd0 at 0x1001b9ad = 0x{:x}".format(val)

        :param int ea: address to trace to
        :param int opnd: the operand of interest (0 - first operand, 1 - second operand, ...)
        :param str data_type: type of data to be extracted, can be one of: STRING, WIDE_STRING, BYTE_STRING, BYTE, WORD,
                          DWORD, QWORD
        :param int data_size: size of data, in bytes, to be extracted.  For STRING and WIDE_STRING, the size need not
                    be supplied IFF the string is NULL terminated and the data requested is the entire string up to the
                    null terminator.  For BYTE_STRING, a size IS required in all instances.  For BYTE, WORD, DWORD, 
                    and QWORD, the size value is ignored in all cases.

        :yield: each possible value for operand per path
        """
        values = set()
        
        # Iterate all the nodes to obtain the CPU context
        _ea = idc.NextHead(ea) if include_inst else ea
        for cpu_context in self.context_at_iter(_ea):
            value = cpu_context.get_operand_value(opnd, data_size, ip=ea, data_type=data_type)
            # Prevent returning multiple values which are the same....
            if value in values:
                function_tracing_logger.debug("trace :: value 0x{:X} already returned.".format(value))
                continue

            values.add(value)
            yield value

    def trace(self, ea, opnd, data_type=BYTE_STRING, data_size=8, include_inst=False):
        """
        Trace the function to the specified ea and return the value for the specified operand.

        >>> ft = FunctionTracer(0x1001b9a0)
        >>> val = ft.trace(0x1001b9ad, 0)
        >>> print "Val for opnd0 at 0x1001b9ad = 0x{:x}".format(val)

        :param int ea: address to trace to

        :param int opnd: the operand of interest (0 - first operand, 1 - second operand, ...)

        :param int data_size: size of data, in bytes, to be extracted.  For STRING and WIDE_STRING, the size need not
                    be supplied IFF the string is NULL terminated and the data requested is the entire string up to the
                    null terminator.  For BYTE_STRING, a size IS required in all instances.  For BYTE, WORD, DWORD, 
                    and QWORD, the size value is ignored in all cases.

        :return: value for operand on first traversed path
        """
        val = self.trace_iter(ea, opnd, data_type, data_size, include_inst).next()
        return val

    def iter_function_args(self, ea):
        """
        Given the EA of a function call, attempt to determine the number of arguments passed to the function and
        return those values to the caller.  Additionally, give back the context as well since it may be useful.

        >>> ft = FunctionTracer(0x1001b9a0)
        >>> call_addr = 0x1001b9d0
        >>> for context, args in ft.iter_function_args(call_addr):
        >>>     print "Args for call at 0x{:X}: {}".format(call_addr, ", ".join(args))

        :param int ea: address containg the function call of interest

        :yield tuple: (context at ea, list of function parameters passed to called function in order)
        """
        # Iterate all the paths leading up to ea
        for cpu_context in self.context_at_iter(ea):
            if idc.GetOpType(ea, 0) == idc.o_reg:
                func_ea = cpu_context.get_operand_value(0, ip=ea, data_type=DWORD)
            else:
                func_ea = idc.GetOperandValue(ea, 0)
            yield cpu_context, cpu_context.get_function_args(func_ea)

    def get_function_args(self, ea):
        """
        Simply calls iter_function_args with the provided ea and returns the first set of arguments.

        >>> ft = FunctionTracer(0x1001b9a0)
        >>> call_addr = 0x1001b9d0
        >>> context, args = ft.get_function_args(call_addr):
        >>> print "Args for call at 0x{:X}: {}".format(call_addr, ", ".join(args))

        :param int ea: address containg the function call of interest

        :return tuple: (context at ea, list of function parameters passed to called function in order)
        """
        for cpu_context, args in self.iter_function_args(ea):
            return cpu_context, args
