"""
Utilties for working with functions.
"""

import collections
import logging
import warnings
from typing import Iterable, Tuple

import ida_bytes
import ida_name
import idaapi
import idautils
import idc

from kordesii.utils.flowchart import Flowchart
from kordesii.utils.function_creator import create_function_precise

logger = logging.getLogger(__name__)


class Function(object):
    """
    Object that wraps the func_t object created by IDA.
    This object greatly expands the functionality for interfacing with a function.
    """

    def __init__(self, ea, identifier=None, create_if_not_exists=True):
        """

        :param ea: An address within the function.
        :param identifier: **DEPRECATED** Some custom unique identifier for this function.
            Historically this was the id of the YARA rule that hit this function.
        :param create_if_not_exists: If True, the function_creator will be used to attempt
            to create function if not defined by IDA.

        :raises AttributeError: If no function exists at the given address.
        """
        self.origin_ea = ea
        self._identifier = identifier
        self.function_obj = idaapi.get_func(ea)
        if not self.function_obj:
            if create_if_not_exists:
                if create_function_precise(ea, False):
                    self.function_obj = idaapi.get_func(ea)
                    logger.debug(
                        "Created function at 0x%X" % self.function_obj.start_ea
                    )
                else:
                    raise AttributeError("No function at 0x%X" % ea)
            else:
                raise AttributeError("No function at 0x%X" % ea)
        if self.function_obj:
            self.start_ea = self.function_obj.start_ea
            self.end_ea = self.function_obj.end_ea
        self.name = idaapi.get_func_name(self.function_obj.start_ea)
        self.xrefs_to = [
            ref.frm
            for ref in idautils.XrefsTo(self.function_obj.start_ea)
            if idaapi.get_func_name(ref.frm) != self.name
        ]
        self.xref_count = len(self.xrefs_to)
        self._flowchart = None
        self._api_calls = None

    @property
    def identifier(self):
        warnings.warn("The identifier property in Function is deprecated.", DeprecationWarning)
        return self._identifier

    @identifier.setter
    def identifier(self, value):
        warnings.warn("The identifier property in Function is deprecated.", DeprecationWarning)
        self._identifier = value

    @classmethod
    def from_name(cls, func_name: str, ignore_underscore: bool = False) -> "Function":
        """
        Factory method for obtaining Function by name.

        :param str func_name: Name of function to obtain
        :param bool ignore_underscore: Whether to ignore underscores in function name.
            (Will return the first found function if enabled.)

        :return: Function object
        :raises ValueError: If function name was not found.
        """
        for ea in idautils.Functions():
            _func_name = idc.get_func_name(ea)
            if ignore_underscore:
                _func_name = _func_name.strip("_")
            if func_name == _func_name:
                return cls(ea)
        raise ValueError("Unable to find function with name: {}".format(func_name))

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __hash__(self):
        return self.__repr__().__hash__()

    def __str__(self):
        return "%s 0x%X - 0x%X" % (
            self.name,
            self.function_obj.start_ea,
            self.function_obj.end_ea,
        )

    def __repr__(self):
        return "<Function : {}() : {:#08x} - {:#08x}>".format(
            self.name, self.start_ea, self.end_ea
        )

    def __contains__(self, ea: int):
        """Tests if ea is within function."""
        # NOTE: We can't just test if it's between start_ea and end_ea because the function might have
        # fragmented function chunks.
        try:
            func = idaapi.get_func(ea)
            if not func:
                return False
        except AttributeError:
            return False
        return func.start_ea == self.start_ea

    def heads(self, start: int = None, reverse: bool = False, dfs: bool = False) -> Iterable[int]:
        """
        Iterates all the heads for the given function.

        :param start: Start address (defaults to start_ea or end_ea)
        :param reverse:  Direction to iterate
        :param bool dfs: If true, traversal of blocks will be depth-first.
            If false, traversal will be breadth-first.

        :yields: Address of head
        """
        if not self._flowchart:
            self._flowchart = Flowchart(self.start_ea)
        if not start:
            start = self.end_ea if reverse else self.start_ea

        yield from self._flowchart.heads(start, reverse=reverse, dfs=dfs)

    def rename(self, new_name: str):
        """
        Attempts to apply new_name to the object at <ea>. If more than one object starts at <ea>, the
        largest object will be renamed. If that name already exists, let IDA resolve the collision
        and then return that name. If new_name is "", reset the name to IDA's default.

        :param str new_name: The desired new name for the function.

        :return str: The name that ended up getting set (unless no name was set, then return None).
        """
        if new_name == "":
            if idaapi.set_name(self.start_ea, new_name):
                return idaapi.get_name(self.function_obj.start_ea)
            else:
                logger.warning("Failed to reset name at 0x%X" % self.start_ea)
        elif ida_name.force_name(self.start_ea, new_name):
            self.name = idaapi.get_name(self.start_ea)
            if self.name != new_name:
                logger.info('IDA changed name "%s" to "%s"' % (new_name, self.name))
            return self.name
        else:
            logger.warning("Failed to rename at 0x%X" % self.start_ea)

    @property
    def api_calls(self) -> collections.Counter:
        """
        Returns counter containing API calls and the number of times they were called.
        """
        if self._api_calls:
            return self._api_calls

        api_calls = collections.Counter()
        for ea, func_ea in self.calls_from:
            func_name = ida_name.get_name(func_ea)
            if func_name:
                api_calls.update([func_name])

        self._api_calls = api_calls
        return self._api_calls

    @property
    def is_library(self) -> bool:
        """
        Is the function a library?
        """
        return bool(self.function_obj.flags & idc.FUNC_LIB)

    @property
    def calls_to(self) -> Iterable[int]:
        """Iterates addresses that call this function."""
        for ea in self.xrefs_to:
            if idc.print_insn_mnem(ea) == "call":
                yield ea

    @property
    def calls_from(self) -> Iterable[Tuple[int, int]]:
        """Iterates call address and callee address of the calls within this function."""
        for ea in self.heads():
            if idc.print_insn_mnem(ea) == "call":
                for xref in idautils.XrefsFrom(ea, idaapi.XREF_FAR):
                    func_ea = xref.to
                    if func_ea:
                        yield ea, func_ea

    @property
    def callers(self) -> Iterable["Function"]:
        """Iterates Function objects that call this function."""
        cache = set()
        for ea in self.calls_to:
            try:
                func = Function(ea)
            except AttributeError:
                continue
            if func.name not in cache:
                yield func
                cache.add(func.name)

    @property
    def callees(self) -> Iterable["Function"]:
        """Iterates Function objects that this function calls."""
        cache = set()
        for ea, func_ea in self.calls_from:
            try:
                func = Function(func_ea)
            except AttributeError:
                continue
            if func.name not in cache:
                yield func
                cache.add(func.name)

    @property
    def data(self) -> bytes:
        """Returns all the bytes contained in the function."""
        return ida_bytes.get_bytes(self.start_ea, self.end_ea - self.start_ea)
