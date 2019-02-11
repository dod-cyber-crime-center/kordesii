"""Utility tool for running YARA within IDA."""

import logging
import os
import warnings

import yara

import idc
import idaapi
import idautils


from kordesii.utils import yara


logger = logging.getLogger(__name__)

_YARA_MATCHES = []
READ_LENGTH = 10485760  # 10 MB
SECTION_START = 0
FROM_FILE = False


def _yara_callback(data):
    """
    Description:
        Generic yara callback.

    Input:
        As defined by YARA. See YARA's documentation for more info.

    Output:
        A list of tuples: (offset, identifier) where offsets are always item heads
    """
    if not data['matches']:
        return False

    for datum in data['strings']:
        if FROM_FILE:
            _YARA_MATCHES.append((idc.get_item_head(idaapi.get_fileregion_ea(datum[0])), datum[1]))
        else:
            _YARA_MATCHES.append((idc.get_item_head(datum[0] + SECTION_START), datum[1]))

    return yara.CALLBACK_CONTINUE


def _read_bytes(start_ea, end_ea):
    """
    Description:
        Reads and returns the bytes from <start_ea> to <end_ea>. Reads are returned in sections
        READ_LENGTH in length to avoid potential memory concerns for extremely large ranges.

    Input:
        start_ea - The start of the range
        end_ea - The end of the range

    Output:
        A string of the bytes in the given range
    """
    global SECTION_START

    block_start = start_ea
    block_end = end_ea
    while block_start < end_ea:
        while block_start < end_ea and idc.get_bytes(block_start, 1) is None:
            block_start += 1
        if block_start >= end_ea:
            break
        block_end = block_start + 1
        while block_end < end_ea and idc.get_bytes(block_end, 1) is not None:
            block_end += 1

        SECTION_START = block_start
        while block_start < block_end:
            yield idc.get_bytes(block_start, min(READ_LENGTH, block_end - block_start))
            SECTION_START += READ_LENGTH
            block_start += READ_LENGTH

        block_start = block_end + 1


def run_yara_on_segment(rule_text, name=None, start_ea=None, callback_func=_yara_callback):
    """
    Description:
        Applies yara rule to the bytes in the specified segment and returns raw results.
        Segments may be specified by name or start EA, but one or the other is required.
        Clears the matches each time to prevent duplicates.

    Input:
        name - The name of the target segment
        start_ea - The start EA of the target segment
        callback_func - A pointer to the callback function for YARA's matching to use

    Output:
        Returns a list of YARA's match results with items (location, description)
    """
    warnings.warn(
        'run_yara_segment() is deprecated. Please use kordesii.utils.yara.match_strings() instead.', DeprecationWarning)
    return yara.match_strings(rule_text, segment=name or start_ea)


def run_yara_on_segments(rule_text, names=None, excluded_names=None, start_eas=None, excluded_eas=None,
                         callback_func=_yara_callback):
    """
    Description:
        Applies yara rule to the bytes in the specified segments and returns raw results.
        Segments may be specified by name or start EA, but one or the other is required.
        Alternatively, names or start EAs may be provided to exclude. In this case all other segments will be scanned.
        Clears the matches each time to prevent duplicates.

    Input:
        names - The names of the target segments
        excluded_names - The names of the excluded segments
        start_eas - The start EAs of the target segments
        excluded_eas - The start EAs of the excluded segments
        callback_func - A pointer to the callback function for YARA's matching to use

    Output:
        Returns a list of YARA's match results with items (location, description)
    """
    warnings.warn('run_yara_on_segments() is deprecated. Please use kordesii.utils.yara instead.', DeprecationWarning)

    if names is None and excluded_names is None and start_eas is None and excluded_eas is None:
        raise Exception(
            "Either segment names, start EAs, excluded names, or excluded EAs are required to YARA scan by segment.")

    if (names and excluded_names) or (start_eas and excluded_eas):
        raise Exception("Do not specify names and excluded names or start eas and excluded eas.")

    results = []
    if names:
        for name in names:
            results.extend(run_yara_on_segment(rule_text, name=name, callback_func=callback_func))
    elif start_eas:
        for start_ea in start_eas:
            results.extend(run_yara_on_segment(rule_text, start_ea=start_ea, callback_func=callback_func))
    else:
        segs_eas = list(idautils.Segments())
        if excluded_names:
            for seg_ea in segs_eas:
                seg_name = idaapi.get_segm_name(idaapi.getseg(seg_ea))
                if seg_name not in excluded_names:
                    results.extend(run_yara_on_segment(rule_text, name=seg_name, callback_func=callback_func))
        elif excluded_eas:
            for seg_ea in segs_eas:
                if seg_ea not in excluded_eas:
                    results.extend(run_yara_on_segment(rule_text, start_ea=seg_ea, callback_func=callback_func))

    return results


def run_yara_on_range(rule_text, start_ea, end_ea, callback_func=_yara_callback):
    """
    Description:
        Applies yara rule to the bytes in the specified range and returns raw results.
        Clear the matches each time to prevent duplicates.

    Input:
        start_ea - The start of the range
        end_ea - The end of the range
        callback_func - A pointer to the callback function for YARA's matching to use

    Output:
        Returns a list of YARA's match results with items (location, description)
    """
    warnings.warn('run_yara_on_range() is deprecated. Please use kordesii.utils.yara instead.', DeprecationWarning)

    global _YARA_MATCHES, FROM_FILE
    _YARA_MATCHES = []
    FROM_FILE = False

    rule = yara.compile(source=rule_text)
    for bites in _read_bytes(start_ea, end_ea):
        rule.match(data=bites, callback=callback_func)
    return _YARA_MATCHES


def run_yara_on_file(rule_text, input_file_path=None, callback_func=_yara_callback):
    """
    Description:
        Applies yara rule and returns raw results. If the input_file_path cannot be found or is None,
        each segment will be scanned.
        Clear the matches each time to prevent duplicates.

    Input:
        rule_text - A string containing a YARA rule
        input_file_path - The filepath of the file used to create the IDB
        callback_func - A pointer to the callback function for YARA's matching to use

    Output:
        Returns a list of YARA's match results with items (location, description)
    """
    warnings.warn('run_yara_on_file() is deprecated. Please use kordesii.utils.yara instead.', DeprecationWarning)

    if input_file_path is not None and os.path.exists(input_file_path):
        return yara.match_strings(rule_text, input_file_path, input_file=True)
    else:
        return run_yara_on_segments(rule_text, start_eas=list(idautils.Segments()), callback_func=callback_func)
