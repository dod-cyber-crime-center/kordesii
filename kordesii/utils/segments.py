"""
Utility for interfacing with segments more efficiently.
"""

import numbers

import ida_bytes
import ida_segment
import idc

_cache = {}


def get_start(name_or_addr):
    """
    Retrieves the starting address for the segment containing the given name or address.

    :param string|int name_or_addr: either the name of a segment or an EA within a segment
    """
    if isinstance(name_or_addr, str):
        segment = ida_segment.get_segm_by_name(name_or_addr)
        if segment is None:
            raise AssertionError("could not find segment for {}".format(name_or_addr))
        return segment.start_ea
    elif isinstance(name_or_addr, numbers.Number):
        return idc.get_segm_attr(name_or_addr, idc.SEGATTR_START)
    else:
        raise ValueError("Invalid value: {}".format(name_or_addr))


def _obtain_bytes(start, end):
    """
    Obtain bytes efficiently, sets non-loaded bytes to \x00

    :param int start: starting address
    :param int end: ending address

    :return bytes: bytes contained within range
    """
    # Reconstruct the segment, account for bytes which are not loaded.
    # Can't use xrange() here because we can get a "Python int too large to conver to C long" error
    bytes_range = range(start, end)  # a range from start -> end
    return bytes(bytearray(ida_bytes.get_wide_byte(i) if idc.is_loaded(i) else 0 for i in bytes_range))


def get_bytes(name_or_addr):
    """
    Obtains segment bytes for the segment in which EA is contained or by segment name.
    This will be on demand and segment bytes will be cached if they have not already been obtained

    :param string|int name_or_addr: either the name of a segment or an EA within a segment

    :return bytes: bytes which are contained with the segment
    """
    seg_start = get_start(name_or_addr)
    seg_bytes = _cache.get(seg_start)
    if seg_bytes is None:
        seg_end = idc.get_segm_attr(seg_start, idc.SEGATTR_END)

        # This check will make an adjustment to seg_end based on whether the previous address has a value
        # or not.  In some instances, seg_end will throw us into an adjacent section which has data and
        # we'll end up getting bad values here.
        if idc.is_loaded(seg_end) and not idc.is_loaded(seg_end - 1):
            seg_end -= 1

        # Need to find the actual end address of the section data since IDA returns addresses that have
        # no data...
        while not idc.is_loaded(seg_end):
            seg_end -= 1

        seg_bytes = _obtain_bytes(seg_start, seg_end)
        _cache[seg_start] = seg_bytes

    return seg_bytes


def clear_cache():
    """
    Clears the internal cache of segment bytes.
    Calling this will be necessary if you have patched in new bytes into the IDB.
    """
    global _cache
    _cache = {}
