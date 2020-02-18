"""
This module uses the idaapi.FlowChart object and extends it as well as idaapi.BasicBlock in order to add
functionality including Breadth-First and Depth-First chart traversal, locating a specific block within the
chart based on an EA, generating a list of all possible paths to a specified EA, etc.
"""

import functools
import logging
import warnings
from operator import attrgetter
from copy import copy, deepcopy
import collections

import idaapi
import idautils
import idc

from .cpu_context import ProcessorContext


logger = logging.getLogger(__name__)


class PathNode(object):
    """
    Represents a linked-list of objects constituting a path from a specific node to the function entry point node.  This
    object can also track cpu context up to a certain EA.
    """

    _cache = {}

    def __init__(self, bb, prev):
        self.bb = bb
        self.prev = prev
        # TODO: Add caching for multiple init_contexts?
        self._context = None
        self._context_ea = None  # ea that the context has been filled to (but not including)
        self._init_context = None  # the context used at the starting path

    @classmethod
    def from_cache(cls, bb, prev):
        """Constructor that caches and reuses existing instances."""
        try:
            return cls._cache[(bb, prev)]
        except KeyError:
            path_node = cls(bb, prev)
            cls._cache[(bb, prev)] = path_node
            return path_node

    def __contains__(self, ea):
        return ea in self.bb

    def __repr__(self):
        return "PathNode({!r})".format(self.bb)

    def path(self):
        """Returns a list of PathNode objects represented by the linked list."""
        if self.prev:
            return self.prev.path() + [self]
        else:
            return [self]

    def cpu_context(self, ea=None, init_context=None):
        """
        Returns the cpu context filled to (but not including) the specified ea.

        :param int ea: address of interest (defaults to the last ea of the block)
        :param init_context: Initial context to use for the start of the path.
            (defaults to an new empty context)

        :return cpu_context.ProcessorContext: cpu context
        """
        if ea is not None and not (self.bb.start_ea <= ea < self.bb.end_ea):
            raise KeyError(
                "Provided address 0x{:X} not in this block "
                "(0x{:X} :: 0x{:X})".format(ea, self.bb.start_ea, self.bb.end_ea)
            )

        # Determine address to stop computing.
        if ea is None:
            end = self.bb.end_ea  # end_ea of a BasicBlock is the first address after the last instruction.
        else:
            end = ea

        # Determine if we need to force the creation of a new context if we have a different init_context.
        new_init_context = self._init_context != init_context
        self._init_context = init_context

        assert end is not None
        # Fill context up to requested endpoint.
        if self._context_ea != end or new_init_context:
            # Create context if:
            #   - not created
            #   - current context goes past requested ea
            #   - given init_context is different from the previously given init_context.
            if not self._context or self._context_ea > end or new_init_context:
                # Need to check if there is a prev, if not, then we need to create a default context here...
                if self.prev:
                    self._context = self.prev.cpu_context(init_context=init_context)
                    # Modify the context for the current branch if required
                    self._context.prep_for_branch(self.bb.start_ea)
                elif init_context:
                    self._context = deepcopy(init_context)
                else:
                    self._context = ProcessorContext.from_arch()

                self._context_ea = self.bb.start_ea

            if self._context_ea != end:
                # Fill context up to requested ea.
                logger.debug("Emulating instructions 0x{:08X} -> 0x{:08X}".format(self._context_ea, end))
                for ip in idautils.Heads(self._context_ea, end):
                    self._context.execute(ip)

            self._context_ea = end

        # Set the next instruction pointer to be the end instruction that we did NOT execute.
        self._context.ip = end

        return deepcopy(self._context)


def _get_flowchart(ea):
    """
    Helper function to obtain an idaapi.FlowChart object for a given ea.

    :param int ea: ea of interest

    :return idaapi.FlowChart: idaapi.FlowChart object
    """
    func = idaapi.get_func(ea)
    flowchart_ = idaapi.FlowChart(func)
    return flowchart_


def _get_codeblock(ea):
    """
    Helper function to obtain a idaapi.BasicBlock object containing a given ea.

    :param int ea: ea of interest

    :return idaapi.BasicBlock: idaapi.BasicBlock object
    """
    flowchart_ = _get_flowchart(ea)
    for code_block in flowchart_:
        if code_block.start_ea <= ea < code_block.end_ea:
            return code_block


@functools.total_ordering
class CustomBasicBlock(idaapi.BasicBlock):
    """
    An idaapi.BasicBlock object which has been extended with additional functionality beyond the base class.

    Additional functionality:
        - Ability to use BasicBlocks as hashable objects (ie: as dictionary keys)
        - Check if two BasicBlocks are equal (based on their start_ea)
        - Check if an EA is contained in a BasicBlock (ie: if ea in <CustomBasicBlock>:)
        - Check length of block
        - Iterator addresses in block.
        - Iterator of paths leading to this block.
    """

    def __init__(self, id_or_ea, bb=None, fc=None):
        if bb is None and fc is None:
            temp_codeblock = _get_codeblock(id_or_ea)
            self.__dict__.update(temp_codeblock.__dict__)
        else:
            super(CustomBasicBlock, self).__init__(id=id_or_ea, bb=bb, fc=fc)

    def __hash__(self):
        return self.start_ea

    def __repr__(self):
        return "<CustomBasicBlock(start_ea=0x{:08X}, end_ea=0x{:08X})>".format(self.start_ea, self.end_ea)

    def __eq__(self, other):
        return self.start_ea == other.start_ea

    def __lt__(self, other):
        return self.start_ea < other.start_ea

    def __contains__(self, ea):
        return self.start_ea <= ea < self.end_ea

    def __len__(self):
        """Length of block is the number of instructions contained within."""
        return len(list(self.heads()))

    def heads(self, start=None, reverse=False):
        """
        Iterates all the heads within the given block.

        :param start: Start address (defaults to start_ea or end_ea)
        :param reverse: Direction to iterate

        :yields: Instruction addresses.

        :raises ValueError: If given start address it not in block.
        """
        if start and start not in self:
            raise ValueError("Start address 0x{:08X} is not in block: {!r}".format(start, self))

        if reverse:
            for head in reversed(list(idautils.Heads(self.start_ea, start or self.end_ea))):
                yield head
        else:
            for head in idautils.Heads(start or self.start_ea, self.end_ea):
                yield head

    def paths(self, _visited=None):
        """
        Iterates the paths that lead to this block.

        :param _visited: Internally used.
        :yields: PathNode objects that represent the last entry of the path linked list.
        """
        if _visited is None:
            _visited = set()

        # Otherwise generate path nodes and cache results for next time.
        _visited.add(self.start_ea)

        parents = list(self.preds())
        if not parents:
            yield PathNode.from_cache(self, prev=None)
        else:
            for parent in parents:
                if parent.start_ea in _visited:
                    continue

                # Create path nodes for each path of parent.
                for parent_path in parent.paths(_visited=_visited):
                    yield PathNode.from_cache(self, prev=parent_path)

        _visited.remove(self.start_ea)


class FlowChart(idaapi.FlowChart):
    """
    Object containing the function graph generated by IDA.  Implements the traversal of the function.
    """

    def __init__(self, f, bounds=None, flags=idaapi.FC_PREDS):
        self.f = idaapi.get_func(f)
        super(FlowChart, self).__init__(f=self.f, bounds=bounds, flags=flags)

    def _traverse(self, start_ea=None, dfs=False):
        """
        Blind traversal of the graph.
        For each block, obtain the children (or blocks which are reachable
        from the current block), sort the children by their start_ea in ascending order, and "push" the list on to the
        front of the non_visisted blocks list.

        :param int start_ea: EA within a block from which to start traversing
        :param bool dfs: If true, traversal will be depth-first. If false, traversal will be breadth-first.

        :yield CustomBasicBlock: function block object
        """
        # Set our flag to True if start_ea is none so we yield all blocks, else wait till we find the requested block
        block_found = start_ea is None
        non_visited = [self[0]]
        visited = set()
        while non_visited:
            cur_block = non_visited.pop(0)
            if hash(cur_block) in visited:
                continue

            visited.add(hash(cur_block))
            succs = sorted(cur_block.succs())
            if dfs:
                # [0:0] allows us to extend to the front
                non_visited[0:0] = succs
            else:
                non_visited.extend(succs)

            if not block_found:
                block_found = start_ea in cur_block

            if block_found:
                yield cur_block

    def _traverse_reverse(self, start_ea=None, dfs=False):
        """
        Perform a reverse traversal of the graph in depth-first/breadth-first manner where given a start node, traverse 1 complete
        path to the root node before following additional paths.

        :param int start_ea: EA within a block from which to start traversing
        :param bool dfs: If true, traversal will be depth-first. If false, traversal will be breadth-first.

        :yield: function block object
        """
        if start_ea:
            non_visited = [self.find_block(start_ea)]
        else:
            non_visited = list(sorted(self, key=attrgetter("start_ea")))[-1:]

        visited = set()
        while non_visited:
            cur_block = non_visited.pop(0)
            if hash(cur_block) in visited:
                continue

            visited.add(hash(cur_block))

            preds = sorted(cur_block.preds(), reverse=True)
            # For now, only consider predicates that are before the current block.
            # This helps to prevent cyclic loops.
            preds = [pred for pred in preds if pred < cur_block]
            if dfs:
                non_visited[0:0] = preds
            else:
                non_visited.extend(preds)

            yield cur_block

    def blocks(self, start=None, reverse=False, dfs=False):
        """
        Iterates over CustomBasicBlocks.

        :param int start: optional address to start iterating from.
        :param bool reverse: iterate in reverse
        :param bool dfs: If true, traversal will be depth-first. If false, traversal will be breadth-first.
        """
        if reverse:
            for cur_block in self._traverse_reverse(start, dfs=dfs):
                yield cur_block

        else:
            for cur_block in self._traverse(start, dfs=dfs):
                yield cur_block

    def heads(self, start=None, reverse=False, dfs=False):
        """
        Iterate over instructions in function blocks.

        :param int start: optional address to start iterating from.
        :param bool reverse: iterate in reverse
        :param bool dfs: If true, traversal of blocks will be depth-first.
            If false, traversal will be breadth-first.
        """
        _first_block = True
        for cur_block in self.blocks(start, reverse=reverse, dfs=dfs):
            if start and _first_block:
                heads = cur_block.heads(start, reverse=reverse)
            else:
                heads = cur_block.heads(reverse=reverse)

            _first_block = False

            for head in heads:
                yield head

    def dfs_iter_blocks(self, start_ea=None, reverse=False):
        """
        Iterate over idaapi.BasicBlocks in depth-first manner.

        :param int start_ea: optional address to start iterating from.

        :param bool reverse: iterate in reverse
        """
        warnings.warn("dfs_iter_blocks() is deprecated. Please use blocks(dfs=True) instead.", DeprecationWarning)
        for block in self.blocks(start=start_ea, reverse=reverse, dfs=True):
            yield block

    def dfs_iter_heads(self, start_ea=None, reverse=False):
        """
        Iterate over instructions in idaapi.BasicBlocks in depth-first manner.

        :param int start_ea: option address to start iterating from.

        :param bool reverse: iterate in reverse
        """
        warnings.warn("dfs_iter_heads() is deprecated. Please use heads(dfs=True) instead.", DeprecationWarning)
        for head in self.heads(start=start_ea, reverse=reverse, dfs=True):
            yield head

    def bfs_iter_blocks(self, start_ea=None, reverse=False):
        """
        Iterate over CustomBasicBlocks in breadth-first manner.

        :param int start_ea: optional address to start iterating from

        :param bool reverse: iterate in reverse
        """
        warnings.warn("bfs_iter_blocks() is deprecated. Please use blocks() instead.", DeprecationWarning)
        for block in self.blocks(start=start_ea, reverse=reverse):
            yield block

    def bfs_iter_heads(self, start_ea=None, reverse=False):
        """
        Iterate over instructions in idaapi.BasicBlocks in breadth-first manner.

        :param int start_ea: optional address to start iterating from.

        :param bool reverse: iterate in reverse
        """
        warnings.warn("bfs_iter_heads() is deprecated. Please use heads() instead.", DeprecationWarning)
        for head in self.heads(start=start_ea, reverse=reverse):
            yield head

    def find_block(self, ea):
        """
        Locate a BasicBlock which contains the specified ea

        :param int ea: ea of interest

        :return: CustomBasicBlock object or None if not found.
        :rtype: CustomBasicBlock
        """
        for block in self:
            if ea in block:
                return block

    def _paths_to_ea(self, ea, cur_block, visited=None, cur_path=None):
        """
        Recursive DFS traversal of graph which yields a path to EA.

        :param int ea: ea of interesting
        :param CustomBasicBlock cur_block: current block in graph
        :param set visited: set of blocks already visited
        :param list cur_path: a list of blocks on the current path

        :yield list: current path
        """
        cur_path = cur_path or []

        # Initialize our visited set of blocks
        if visited is None:
            visited = set()

        # Mark the current block as visited and add it to the current path
        visited.add(cur_block.start_ea)
        cur_path.append(cur_block)
        # We've found our block, so yield the current path
        if ea in cur_block:
            yield copy(cur_path)

        # Continue traversing
        for block in cur_block.succs():
            if block.start_ea in visited:
                continue

            for path in self._paths_to_ea(ea, block, visited, cur_path):
                yield path

        # Remove the current block from the path and visited so it is included in subsequent paths
        cur_path.pop()
        visited.remove(cur_block.start_ea)

    def paths_to_ea(self, ea):
        """
        Yield a list which contains all the blocks on a path from the function entry point to the block
        containing the specified ea.  Raises ValueError if specified EA is not within the current function.

        :param int ea: ea of interest

        :yield list: list of BasicBlocks residing on a given path to EA
        """
        # make sure the specified ea is within the function
        if not (self.f.start_ea <= ea < self.f.end_ea):
            raise ValueError

        for path in self._paths_to_ea(ea, self[0]):
            yield path

    def get_paths(self, ea):
        """
        Given an EA, iterate over the paths to the EA.

        For usage example, see function_tracer.trace in function_tracer.py

        WARNING:
        DO NOT WRAP THIS GENERATOR IN list()!!!  This generator will iterate all possible paths to the node containing
        the specified EA.  On functions containing large numbers of jumps, the number of paths grows exponentially and
        you WILL hit memory exhaustion limits, extremely slow run times, etc.  Use extremely conservative constraints
        when iterating.  Nodes containing up to at least 32,768 paths are computed in a reasonably sane amount of time,
        though it probably doesn't make much sense to check this many paths for the data you are looking for.

        :param int ea: EA of interest

        :yield: a path to the object
        """
        # Obtain the block containing the EA of interest
        block = self.find_block(ea)

        # If block not found, then there are no paths to it.
        if not block:
            logger.debug("Unable to find block with ea: 0x{:08X}".format(ea))
            return

        for path_node in block.paths():
            yield path_node

    def _getitem(self, index):
        """
        Override the idaapi.FlowChart._getitem function to return our CustomBasicBlock
        type instead.
        """
        return CustomBasicBlock(index, self._q[index], self)
