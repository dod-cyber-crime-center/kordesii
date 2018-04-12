import idaapi
import idc
import idautils

import re
from decoderutils import SuperFunc_t
from kordesii.kordesiiidahelper import append_debug

READ_LENGTH = 65536


class IterApis(object):
    """
    Object designed to iterate the APIs of a specified module in order to obtain their addresses. By default, all the
    APIs from an import module are obtained. If specified, targeted API names will be collected for the dictionary.

    Input Parameters:
    :param module_name: The import module name
    :param target_api_names: None by default, list of API names to obtain addresses for in the module

    Fields:
    :param targeted: Boolean value indicating if there are targeted API names
    :param api_addrs: Dictionary of API names and offsets
    """
    def __init__(self, module_name, target_api_names=None):
        self.module_name = module_name
        if target_api_names:
            self.target_api_names = target_api_names[:]
            self.targeted = True
        else:
            self.target_api_names = None
            self.targeted = False

        self.api_addrs = {}
        self._processed = False

    def __iter__(self):
        """Returns an iterator yielding a tuple of (api_name, offset). """
        if not self._processed:
            self.iter_module()
        return self.api_addrs.iteritems()

    def obtain_api_addr(self, api_name):
        """
        Attempt to obtain the address for an API name in the self.api_addrs dictionary.

        :param api_name: Name of API to acquire address for

        :return: Address for specified API name, or idc.BADADDR
        """
        if not self._processed:
            self.iter_module()
        return self.api_addrs.get(api_name, idc.BADADDR)

    def _obtain_targeted_apis_by_name(self, api_names):
        """
        Given a list of api_names attempt to locate them in the IDA database by name. If located add to the
        self.api_addrs dictionary.

        :param api_names: List of API names to locate by name

        :return:
        """
        for api_name in api_names:
            addr = obtain_function_by_name(api_name)
            if addr != idc.BADADDR:
                self.api_addrs[api_name] = addr
            else:
                append_debug('Address for %s was not located by name.' % api_name)

    def _callback_func(self, ea, name, ord):
        """
        Callback function for idaapi.enum_import_names.

        If targeting specific API names for the library module only collect those apis to add to the api_addrs
        dictionary. Remove an api_name after it is collected. If targeting and no targeted API names remain, stop
        iteration.

        If not targeting specific API names, add all named APIs in the module to the api_addrs dictionary.

        :param ea: API function address
        :param name: API function name (or None)
        :param ord: Ordinal (unused, but required for invoking)

        :return: Boolean value indicating if iteration should continue
        """
        if name:
            if self.targeted:
                if name in self.target_api_names:
                    self.api_addrs[name] = ea
                    self.target_api_names.remove(name)
            else:
                self.api_addrs[name] = ea

        if self.targeted and not self.target_api_names:
            return False
        return True

    def iter_module(self):
        """
        Iterate the import libraries to locate a specific import library and obtain the api addresses using the
        callback func. If the api_names are targeted and they were not obtained using idaapi.enum_import_names then
        attempt to obtain the targeted apis by function name.

        :return:
        """
        num_imports = idaapi.get_import_module_qty()
        for i in xrange(0, num_imports):
            name = idaapi.get_import_module_name(i)
            if name == self.module_name:
                idaapi.enum_import_names(i, self._callback_func)
        if self.targeted and self.target_api_names:
            self._obtain_targeted_apis_by_name(self.target_api_names)
        self._processed = True


def lines(start=None, end=None, reverse=False, max_steps=None):
    """
    Iterates through instructions within the start address and end addresses.

    :param start: Address of the starting instruction. (starts at beginning if not defined)
    :param end: Address of the end instruction.
    :param reverse: Iterates up if true.
    :param max_steps: If set, iteration will stop after the given number of steps.
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

    func = idc.PrevHead if reverse else idc.NextHead
    ea = idc.ItemHead(start)
    while ea != idc.BADADDR:
        yield ea
        ea = func(ea, end)


def get_string(ea):
    """
    Returns a string from the given location.

    :param ea: starting address of string

    :return: A string
    """
    stype = idc.GetStringType(ea)
    return idc.GetString(ea, strtype=stype)


SECTION_START = None


def _read_bytes(start_ea, end_ea):
    """
    Reads and returns the bytes from <start_ea> to <end_ea>. Reads are returned in sections READ_LENGTH in length to
    avoid potential memory concerns for extremely large ranges.

    :param start_ea: The start of the range
    :param end_ea: The end of the range

    :return: A string of the bytes in the given range
    """
    global SECTION_START

    block_start = start_ea
    block_end = end_ea
    while block_start < end_ea:
        while block_start < end_ea and idaapi.get_many_bytes(block_start, 1) is None:
            block_start += 1
        if block_start >= end_ea:
            break
        block_end = block_start + 1
        while block_end < end_ea and idaapi.get_many_bytes(block_end, 1) is not None:
            block_end += 1

        SECTION_START = block_start
        while block_start < block_end:
            yield idaapi.get_many_bytes(block_start, min(READ_LENGTH, block_end - block_start))
            SECTION_START += READ_LENGTH
            block_start += READ_LENGTH

        block_start = block_end + 1


def obtain_segment_data(segname):
    """
    Given a segment name, return the bytes within the segment.

    :param segname: Name of the segment

    :return: Data from the specified segment.
    """
    seg = idaapi.get_segm_by_name(segname)
    if seg:
        return _read_bytes(seg.startEA, seg.endEA)
    return None


def re_search_on_segment(ptn, segname):
    """
    Run a regex pattern on a specified segment.

    :param ptn: Regex pattern
    :param segname: Name of the segment

    :return: re.MatchObject for the regex pattern or None
    """
    segdata = obtain_segment_data(segname)
    if segdata:
        for entry in segdata:
            match = re.search(ptn, entry, re.DOTALL)
            if match:
                return match
    return None


def re_findall_on_segment(ptn, segname):
    """
    Run a regex pattern on a specified segment and obtain all matches

    :param ptn: Regex pattern
    :param segname: Name of the segment

    :return: List of strings for matches
    """
    segdata = obtain_segment_data(segname)
    matches = []
    if segdata:
        for entry in segdata:
            matches.extend(re.findall(ptn, entry, re.DOTALL))
    return matches


def obtain_function_by_name(func_name):
    """
    Obtain a function in the list of functions for the application by name, or idc.BADADDR.

    :param func_name: Name of function to obtain

    :return: startEA of function or idc.BADADDR
    """
    for func in idautils.Functions():
        if func_name == idc.GetFunctionName(func):
            return func
    return idc.BADADDR


def obtain_superfunct_by_name(func_name):
    """
    Obtain a decoderutils.SuperFunc_t object for a function by name.

    :param func_name: Name of function to obtain

    :return: decoderutils.SuperFunc_t object or None
    """
    start_ea = obtain_function_by_name(func_name)
    if start_ea != idc.BADADDR:
        return SuperFunc_t(start_ea)
    return None


def obtain_export_by_name(export_name):
    """
    Iterate the entry points to identify the location of an export by name

    :param export_name: Target export

    :return: Location of target export or idc.BADADDR
    """
    for (i, ordinal, ea, name) in idautils.Entries():
        if name == export_name:
            return ea
    return idc.BADADDR
