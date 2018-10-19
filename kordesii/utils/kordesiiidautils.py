
import itertools
import re
import numbers

import idaapi
import idc
import idautils

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


# TODO: Use SuperFunc_t.heads() instead.
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


class Segments(object):
    """
    Class that allow obtaining segment bytes more efficiently.
    """
    def __init__(self):
        self.segments = {}
    
    def _get_segment_bytes(self, start, end):
        """
        Obtain segment bytes, setting non-loaded bytes to NULL
        
        :param int start: segment start EA
        
        :param int end: segment end EA
        
        :return string: bytes contained in segment
        """
        # Reconstruct the segment, account for bytes which are not loaded.
        # Can't use xrange() here because we can get a "Python int too large to conver to C long" error
        seg_range = iter(itertools.count(start).next, end)  # a range from start -> end
        return str(bytearray(idc.Byte(i) if idc.isLoaded(i) else 0 for i in seg_range))
        
    def segment_bytes(self, val):
        """
        Will obtain segment bytes for the segment in which EA is contained or by segment name.  This will be on demand 
        and segment bytes will be cached if they have not already been obtained
        
        :param string|int val: either the name of a segment or an EA within a segment
        
        :return string: bytes which are contained with the segment
        """
        if isinstance(val, str):
            seg_start = idaapi.get_segm_by_name(val).startEA
            if seg_start is None:
                raise AssertionError("could not find segment for {}".format(val))
            
        elif isinstance(val, numbers.Number):
            seg_start = idc.GetSegmentAttr(val, idc.SEGATTR_START)
        
        seg_bytes = self.segments.get(seg_start)
        if seg_bytes is None:
            seg_end = idc.GetSegmentAttr(seg_start, idc.SEGATTR_END)
            seg_bytes = self._get_segment_bytes(seg_start, seg_end)
            self.segments[seg_start] = seg_bytes
            
        return seg_bytes


kordesiiidautils_segments = Segments()


class IDA_MatchObject(object):
    """
    Class that performs some voodoo on MatchObjects.
    """
    def __init__(self, match, seg_start):
        self._match = match
        self._start = seg_start

    def __getattr__(self, item):
        """
        Redirects anything that this class doesn't support back to the matchobject class

        :param item:

        :return:
        """
        return getattr(self._match, item, None)

    def start(self, group=None):
        """
        Returns the match object start value with respect to the segment start.

        :param group: optional group to obtain the start of

        :return: virtual start address
        """
        if group:
            return self._match.start(group) + self._start

        return self._match.start() + self._start

    def end(self, group=None):
        """
        Returns the match object end value with respect to the segment start.

        :param group: optional group to obtain the end of

        :return: virtual end address
        """
        if group:
            return self._match.end(group) + self._start

        return self._match.end() + self._start


class IDA_re(object):
    """
    Class to perform regex operations within IDA.
    """
    def __init__(self, ptn, flags=0):
        if isinstance(ptn, basestring):
            self._re = re.compile(ptn, flags=flags)
        else:
            self._re = ptn

    def _get_segments(self, segname=None):
        """
        Obtain the bytes of the segment specified in segname or all segments as an iterable.
        
        :param str segname: segment name or None
        
        :yield: seg_start, seg_bytes
        """
        if segname and isinstance(segname, str):
            segments = [idaapi.get_segm_by_name(segname).startEA]
        
        else:
            segments = idautils.Segments()
            
        for segment in segments:
            yield segment, kordesiiidautils_segments.segment_bytes(segment)

    def search(self, segname=None):
        """
        Performs the search functionality on the entire file, searching each segment individually.

        :return: match object modified to match the segment start address
        """
        for seg_start, seg_bytes in self._get_segments(segname):
            match = self._re.search(seg_bytes)
            if match:
                return IDA_MatchObject(match, seg_start)

            return None

    def finditer(self, segname=None):
        """
        Performs the finditer functionality on the entire file, searching each segment individually.

        :param segname: Restrict searching to segment with provided name

        :yield: match object
        """
        for seg_start, seg_bytes in self._get_segments(segname):
            for match in self._re.finditer(seg_bytes):
                yield IDA_MatchObject(match, seg_start)

    def findall(self, segname=None):
        """
        Performs the findall functionality on the entire file.

        :return: list of match objects
        """
        matches = []
        for _, seg_bytes in self._get_segments(segname):
            matches.extend(self._re.findall(seg_bytes))

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
