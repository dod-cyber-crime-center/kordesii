"""
Utility for running re within IDA.

This utility extends and overwrites the existing re API to work correctly within IDA.
This module works just like the builtin re module, but adjusts offsets to be virtual addresses
and allows for searching specific segments.

usage::
    from kordesii.utils import ida_re


    ptn = ida_re.compile('some pattern')

    for match in ptn.finditer('.text'):
        print('found marker at 0x{:0x}'.format(match.start()))
"""

from __future__ import absolute_import

import re

import idautils
import ida_segment

from kordesii.utils import segments


class Match(object):
    """
    Wraps the SRE_Match object returned by re.
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


class Pattern(object):
    """
    Wraps the SRE_Pattern object returned by re.
    """
    def __init__(self, ptn, flags=0):
        if isinstance(ptn, (str, bytes)):
            self._re = re.compile(ptn, flags=flags)
        else:
            self._re = ptn

    def _get_segments(self, segname=None):
        """
        Obtain the bytes of the segment specified in segname or all segments as an iterable.

        :param str segname: segment name or None

        :yield: seg_start, seg_bytes
        """
        if segname:
            seg_starts = [ida_segment.get_segm_by_name(segname).start_ea]
        else:
            seg_starts = idautils.Segments()

        for ea in seg_starts:
            yield ea, segments.get_bytes(ea)

    def search(self, segname=None):
        """
        Performs the search functionality on the entire file, searching each segment individually.

        :return: match object modified to match the segment start address
        """
        for seg_start, seg_bytes in self._get_segments(segname):
            match = self._re.search(seg_bytes)
            if match:
                return Match(match, seg_start)
        return None

    def finditer(self, segname=None):
        """
        Performs the finditer functionality on the entire file, searching each segment individually.

        :param segname: Restrict searching to segment with provided name

        :yield: match object
        """
        for seg_start, seg_bytes in self._get_segments(segname):
            for match in self._re.finditer(seg_bytes):
                yield Match(match, seg_start)

    def findall(self, segname=None):
        """
        Performs the findall functionality on the entire file.

        :return: list of match objects
        """
        matches = []
        for _, seg_bytes in self._get_segments(segname):
            matches.extend(self._re.findall(seg_bytes))

        return matches


def compile(pattern, flags=0):
    """Compile a regular expression returning a Pattern object."""
    return Pattern(pattern, flags=flags)


def search(pattern, segname=None, flags=0):
    """Search with regular expression, returning a Match object."""
    return Pattern(pattern, flags=flags).search(segname=segname)


def finditer(pattern, segname=None, flags=0):
    """Iterator of non-overlapping matches."""
    ptn = Pattern(pattern, flags=flags)
    for match in ptn.finditer(segname=segname):
        yield match


def findall(pattern, segname=None, flags=0):
    """Returns a list of non-overlapping matches."""
    return Pattern(pattern, flags=flags).findall(segname=segname)
