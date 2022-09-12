"""
This module extends the flowchart module in kordesii.utils in order to add ProcessorContext
tracking and emulation.
"""
from __future__ import annotations
import logging
import warnings
from copy import deepcopy
from typing import TYPE_CHECKING, Optional

import idautils

from kordesii.utils import flowchart

if TYPE_CHECKING:
    from .cpu_context import ProcessorContext


logger = logging.getLogger(__name__)


# TODO: Refactor this so we no longer need to have a separate version of PathNode.
class PathNode(flowchart.PathNode):
    """
    Extends original PathNode to add ability to get cpu_context.
    """

    _cache = {}

    def __init__(self, bb: BasicBlock, prev: Optional[PathNode]):
        """
        Initialize a path node.

        :param bb: The underlying basic block for this node.
        :param prev: The parent node that points to this node.
        """
        super().__init__(bb, prev)
        # TODO: Add caching for multiple init_contexts?
        self._context = None
        self._context_ea = None  # ea that the context has been filled to (but not including)
        self._init_context = None  # the context used at the starting path
        self._call_depth = 0       # the number of calls deep we are allowed to emulate

    def cpu_context(self, ea=None, *, call_depth: int = 0, init_context: ProcessorContext) -> ProcessorContext:
        """
        Returns the cpu context filled to (but not including) the specified ea.

        :param int ea: address of interest (defaults to the last ea of the block)
        :param call_depth: Number of function calls we are allowed to emulate into.
            When we hit our limit (depth is 0), emulation will no longer jump into function calls.
            (Defaults to not emulating into any function calls.)
            NOTE: This does not affect call hooks.
        :param init_context: Initial context to use for the start of the path. (required)

        :return cpu_context.ProcessorContext: cpu context
        """
        if ea is not None and ea not in self.bb:
            raise KeyError(
                "Provided address 0x{:X} not in this block "
                "(0x{:X} :: 0x{:X})".format(ea, self.bb.start_ea, self.bb.end_ea)
            )

        # Determine address to stop computing.
        if ea is None:
            end = self.bb.end_ea  # end_ea of a BasicBlock is the first address after the last instruction.
        else:
            end = ea

        # Determine if we need to force the creation of a new context if we have a different init_context
        # or call_depth.
        new_init_context = self._init_context != init_context or self._call_depth != call_depth
        self._init_context = init_context
        self._call_depth = call_depth

        assert end is not None
        # Fill context up to requested endpoint.
        if self._context_ea != end or new_init_context:
            # Create context if:
            #   - not created
            #   - current context goes past requested ea
            #   - given init_context/call_depth is different from the previously given init_context/call_depth.
            if not self._context or self._context_ea > end or new_init_context:
                # Need to check if there is a prev, if not, then we need to create a default context here...
                if self.prev:
                    self._context = self.prev.cpu_context(call_depth=call_depth, init_context=init_context)
                    # Modify the context for the current branch if required
                    self._context.prep_for_branch(self.bb.start_ea)
                else:
                    self._context = deepcopy(init_context)

                self._context_ea = self.bb.start_ea

            if self._context_ea != end:
                # Fill context up to requested ea.
                logger.debug("Emulating instructions 0x%08X -> 0x%08X", self._context_ea, end)
                for ip in idautils.Heads(self._context_ea, end):
                    self._context.execute(ip, call_depth=call_depth)

            self._context_ea = end

        # Set the next instruction pointer to be the end instruction that we did NOT execute.
        self._context.ip = end

        return deepcopy(self._context)


class BasicBlock(flowchart.BasicBlock):
    """
    Inherited version of BasicBlock that uses our modified PathNode for paths.
    """
    _PATHNODE_CLASS = PathNode


class Flowchart(flowchart.Flowchart):
    """
    Inherited version of Flowchart that uses our modified BasicBlock.
    """
    _cache = {}
    _BASICBLOCK_CLASS = BasicBlock


class FlowChart(Flowchart):
    def __init__(self, *args, **kwargs):
        warnings.warn("FlowChart has been renamed to Flowchart", DeprecationWarning)
        super(FlowChart, self).__init__(*args, **kwargs)

