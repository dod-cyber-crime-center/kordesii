"""
Extra utility functions for interfacing with ida.
"""

# TODO: For lack of a better name, this is called "utils". Change this.

from __future__ import absolute_import

from typing import Union, List

import re
import logging

import idaapi
import ida_bytes
import ida_entry
import ida_funcs
import ida_nalt
import idc
import idautils


logger = logging.getLogger(__name__)


READ_LENGTH = 65536


def iter_imports(module_name=None, api_names=None):
    """
    Iterate the thunk function wrappers for API imports.
    Yields the module name, function name, and reference to function.

    .. code_block:: python

        for ea, name, module_name in utils.iter_imports():
            print("{}.{} function at: 0x{:0x}".format(module_name, name, ea))

        for ea, name, _ in utils.iter_imports("KERNEL32"):
            print("KERNEL32.{} function at: {}".format(name, ea))

        for ea, name, module_name in utils.iter_imports(api_names=["GetProcAddress", "GetFileSize"]):
            print("{}.{} function at: {}".format(module_name, name, ea))

        for ea, _, _ in utils.iter_imports("KERNEL32", "GetProcAddress"):
            print("KERNEL32.GetProcAddress function at: {}".format(ea))

    NOTE: The same function name can be yield more than once if it
    appears in multiple modules or has multiple thunk wrappers.

    Name is the original import name and does not necessarily reflect the function name.
    e.g. "GetProcAddress", "GetProcAddress_0", and "GetProcAddress_1" will all be "GetProcAddress"

    :param module_name: Filter imports to a specified library.
    :param api_names: Filter imports to specific API name(s).
        Can be a string of a single name or list of names.

    :yield: (ea, api_name, module_name)
    """
    if isinstance(api_names, str):
        api_names = [api_names]

    for i in range(ida_nalt.get_import_module_qty()):
        _module_name = ida_nalt.get_import_module_name(i)
        if not _module_name:
            continue
        if module_name and module_name.lower() != _module_name.lower():
            continue

        entries = []
        target_set = set(api_names) if api_names else None

        def callback(ea, name, ordinal):
            if name:
                # Sometimes IDA includes "__imp_" to the front of the name.
                # Strip this off to be more consistent to what you would see in the GUI.
                if name.startswith("__imp_"):
                    name = name[6:]

                # Collect name if matches filter or if no filter set.
                if target_set and (
                    name in target_set
                    or name.strip("_") in target_set
                    or any(re.match("_*{}_+[0-9]?".format(name_), name) for name_ in target_set)
                ):
                    entries.append((ea, name))
                    target_set.difference_update({name, name.strip("_")})
                    if not target_set:
                        # Found all targeted function names. stop enumeration.
                        return False
                elif not api_names:
                    entries.append((ea, name))
            return True  # continue enumeration

        ida_nalt.enum_import_names(i, callback)

        for ea, name in entries:
            # Yield thunk wrapper functions if they exists.
            for xref in idautils.XrefsTo(ea):
                func = ida_funcs.get_func(xref.frm)
                if not func:
                    continue
                if func.flags & ida_funcs.FUNC_THUNK:
                    yield xref.frm, name, _module_name

            # Yield reference in data segment signature
            # (yielding after thunks, since those are more likely to be used)
            yield ea, name, _module_name


def iter_exports():
    """
    Iterate API exports.

    :yield: (ea, name)
    """
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        yield ea, name


def iter_functions(func_names: Union[None, str, List[str]] = None):
    """
    Iterate all defined functions and yield their address and name.
    (This includes imported functions)

    :param func_names: Filter based on specific function names.

    :yield: (ea, name)
    """
    if isinstance(func_names, str):
        func_names = [func_names]

    # Yield declared functions.
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if (
            not func_names
            or name in func_names
            or name.strip("_") in func_names
            or any(re.match("_*{}_[0-9]?".format(name_), name) for name_ in func_names)
        ):
            yield ea, name

    # Also yield from imported.
    for ea, name, _ in iter_imports(api_names=func_names):
        yield ea, name


def get_import_addr(api_name, module_name=None):
    """
    Returns the first instance of a function that wraps the given API name.

    .. code_block:: python

        proc_func_ea = get_import_addr("GetProcAddress")

    :param api_name: Name of API
    :param module_name: Library of API

    :returns: Address of function start or None if not found.
    """
    for ea, _, _ in iter_imports(module_name, api_name):
        return ea


def get_export_addr(export_name):
    """
    Return the location of an export by name

    :param export_name: Target export

    :return: Location of target export or None
    """
    for ea, name in iter_exports():
        if name == export_name:
            return ea


def get_function_addr(func_name: str):
    """
    Obtain a function in the list of functions for the application by name.
    Supports using API resolved names if necessary.

    :param func_name: Name of function to obtain

    :return: start_ea of function or None
    """
    for ea, _ in iter_functions(func_name):
        return ea


def lines(start=None, end=None, reverse=False, max_steps=None):
    """
    Iterates through instructions within the start address and end addresses.

    :param start: Address of the starting instruction. (starts at beginning if not defined)
    :param end: Address of the end instruction.
    :param reverse: Iterates up if true.
    :param max_steps: Maximum number of steps to iterate.
    :yields: instructions addresses
    """
    max_ea = idaapi.cvar.inf.maxEA
    min_ea = idaapi.cvar.inf.minEA

    # Normalize start and end addresses.
    if reverse:
        if start is None:
            start = max_ea - 1
        if end is None:
            end = 0
        start = max(start, end)
    else:
        if start is None:
            start = min_ea
        if end is None:
            end = max_ea + 1
        start = min(start, end)

    steps = 0
    func = ida_bytes.prev_head if reverse else ida_bytes.next_head
    ea = ida_bytes.get_item_head(start)
    while ea != idc.BADADDR:
        yield ea
        ea = func(ea, end)
        steps += 1
        if max_steps and steps >= max_steps:
            break


def get_string(ea: int) -> bytes:
    """
    Returns a string from the given location.

    :param ea: starting address of string

    :return: A string
    """
    stype = idc.get_str_type(ea)
    return idc.get_strlit_contents(ea, strtype=stype)
