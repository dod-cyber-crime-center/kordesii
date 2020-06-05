"""
This module uses the idaapi.FlowChart object and extends it as well as idaapi.BasicBlock in order to add
functionality including Breadth-First and Depth-First chart traversal, locating a specific block within the
chart based on an EA, generating a list of all possible paths to a specified EA, etc.
"""

import functools
import logging
from operator import attrgetter
from typing import Optional, Set, Iterator

import ida_idaapi
import ida_gdl
import ida_funcs
import idautils

logger = logging.getLogger(__name__)


class PathNode(object):
    """
    Represents a linked-list of objects constituting a path from a specific node to the function entry point node.
    This object can also track cpu context up to a certain EA.
    """

    _cache = {}

    def __init__(self, bb: "BasicBlock", prev: Optional["PathNode"]):
        """
        Initialize a path node.

        :param bb: The underlying basic block for this node.
        :param prev: The parent node that points to this node.
        """
        self.bb = bb
        self.prev = prev

    @classmethod
    def from_cache(cls, bb: "BasicBlock", prev: Optional["PathNode"]):
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


@functools.total_ordering
class BasicBlock(object):
    """
    A reimplementation of  ida_gdl.BasicBlock object which has been extended with additional
    functionality.

    NOTE: This is a reimplementation of ida_gdl.BasicBlock. We are not inheriting from
    this class because it causes limitations for the IDA proxy feature.

    Additional functionality:
        - Ability to use BasicBlocks as hashable objects (ie: as dictionary keys)
        - Check if two BasicBlocks are equal (based on their start_ea)
        - Check if an EA is contained in a BasicBlock (ie: if ea in <BasicBlock>:)
        - Check length of block
        - Iterator addresses in block.
        - Iterator of paths leading to this block.
    """

    # This allows us to change the PathNode class in kordesii.utils.function_tracing.flowchart
    _PATHNODE_CLASS = PathNode

    def __init__(self, id, bb, fc):
        self._fc = fc
        self.id = id
        self.start_ea = bb.start_ea
        self.end_ea = bb.end_ea
        self.type = self._fc._q.calc_block_type(self.id)

    @classmethod
    def from_address(cls, ea):
        """Factory method for creating BasicBlock from an address."""
        fc = Flowchart.from_cache(ea)
        block = fc.find_block(ea)
        assert block, "Failed to get a BasicBlock"
        return block

    # region ida_gdl.BasicBlock functions

    def preds(self):
        """
        Iterates the predecessors list
        """
        q = self._fc._q
        for i in range(0, self._fc._q.npred(self.id)):
            yield self._fc[q.pred(self.id, i)]

    def succs(self):
        """
        Iterates the successors list
        """
        q = self._fc._q
        for i in range(0, q.nsucc(self.id)):
            yield self._fc[q.succ(self.id, i)]

    # endregion

    def __hash__(self):
        return self.start_ea

    def __repr__(self):
        return "<BasicBlock(start_ea=0x{:08X}, end_ea=0x{:08X})>".format(self.start_ea, self.end_ea)

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
            yield from reversed(list(idautils.Heads(self.start_ea, start or self.end_ea)))
        else:
            yield from idautils.Heads(start or self.start_ea, self.end_ea)

    def paths(self, _visited=None) -> Iterator[_PATHNODE_CLASS]:
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
            yield self._PATHNODE_CLASS.from_cache(self, prev=None)
        else:
            for parent in parents:
                if parent.start_ea in _visited:
                    continue

                # Create path nodes for each path of parent.
                for parent_path in parent.paths(_visited=_visited):
                    yield self._PATHNODE_CLASS.from_cache(self, prev=parent_path)

        _visited.remove(self.start_ea)

    def ancestors(self, _visited=None) -> Set["BasicBlock"]:
        """
        Returns a set of ancestor blocks for the given block.

        :param _visited: Internally used.

        :returns: Set of ancestor blocks.
        """
        if _visited is None:
            _visited = set()

        _visited.add(self)

        parents = set(parent for parent in self.preds() if parent not in _visited)
        ancestors = parents.union(*(parent.ancestors(_visited=_visited) for parent in parents))

        _visited.remove(self)

        return ancestors


class Flowchart(object):
    """
    Object containing the function graph generated by IDA.
    Implements the traversal of the function.

    NOTE: This is a reimplementation of ida_gdl.Flowchart. We are not inheriting from
    this class because it causes limitations for the IDA proxy feature.
    """

    _cache = {}

    # This allows us to change the BasicBlock class in kordesii.utils.function_tracing.flowchart
    _BASICBLOCK_CLASS = BasicBlock

    def __init__(self, func_ea):
        """
        Initializes Flowchart

        :param func_ea: An address in the function.
        """
        self.func_obj = ida_funcs.get_func(func_ea)
        self._q = ida_gdl.qflow_chart_t(
            "", self.func_obj, ida_idaapi.BADADDR, ida_idaapi.BADADDR, ida_gdl.FC_PREDS
        )

    @classmethod
    def from_cache(cls, func_ea):
        """Constructor that caches and reuses existing instances."""
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise ValueError(f"{func_ea} is not within a function.")

        try:
            return cls._cache[func.start_ea]
        except KeyError:
            flowchart = cls(func.start_ea)
            cls._cache[func.start_ea] = flowchart
            return flowchart

    # region ida_gdl.Flowchart functions

    @property
    def size(self):
        return self._q.size()

    def refresh(self):
        self._q.refresh()

    def _getitem(self, index):
        return self._BASICBLOCK_CLASS(index, self._q[index], self)

    def __iter__(self):
        return (self._getitem(index) for index in range(0, self.size))

    def __getitem__(self, index):
        if index >= self.size:
            raise KeyError
        else:
            return self._getitem(index)

    # endregion

    def _traverse(self, start_ea=None, dfs=False):
        """
        Blind traversal of the graph.
        For each block, obtain the children (or blocks which are reachable
        from the current block), sort the children by their start_ea in ascending order, and "push" the list on to the
        front of the non_visisted blocks list.

        :param int start_ea: EA within a block from which to start traversing
        :param bool dfs: If true, traversal will be depth-first. If false, traversal will be breadth-first.

        :yield BasicBlock: function block object
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
                yield from cur_block.heads(start, reverse=reverse)
            else:
                yield from cur_block.heads(reverse=reverse)

            _first_block = False

    def find_block(self, ea):
        """
        Locate a BasicBlock which contains the specified ea

        :param int ea: ea of interest

        :return: CustomBasicBlock object or None if not found.
        :rtype: BasicBlock
        """
        for block in self:
            if ea in block:
                return block

    def get_paths(self, ea) -> Iterator[PathNode]:
        """
        Given an EA, iterate over the paths to the EA.

        For usage example, see Emulator.iter_context_at()

        ..warning:: DO NOT WRAP THIS GENERATOR IN list()!!!  This generator will iterate all possible paths to the node containing
        the specified EA.  On functions containing large numbers of jumps, the number of paths grows exponentially and
        you WILL hit memory exhaustion limits, extremely slow run times, etc. Use extremely conservative constraints
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

        yield from block.paths()
