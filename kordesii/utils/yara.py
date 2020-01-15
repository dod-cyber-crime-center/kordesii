"""
Utilities for running YARA within IDA.

This utility extends and overwrites the existing YARA API to work correctly within IDA.

usage::
    from kordesii.utils import yara

    rule = yara.compile(source=rule_text)
    matches = rule.match()  # No parameter needed for match to run on entire input file.

    # Can also be used to run on segments.
    matches = rule.match(segment='_text')

    # We can also just look for matching strings.
    for offset, identifer in rule.match_strings():
        # ...
    for offset, identifer in rule.match_strings(segment='_text'):
        # ...
"""

from __future__ import absolute_import, print_function

import logging

import idc
import idaapi

import yara
from yara import *

from kordesii.utils import segments


logger = logging.getLogger(__name__)

READ_LENGTH = 10485760  # 10 MB


class Match(object):
    """
    Patches yara.Match to provide convert string offsets to virtual addresses.

    NOTE: We can't inherit yara.Match because they don't expose that class.

    :param yara.Match match_object: Original match object created by YARA
    :param int offset: Optional offset to offset string offsets by
    :param bool input_offset: Whether string offsets will be the file offset
        and should be converted.
    """

    def __init__(self, match_object, offset=None, file_offset=False):
        self._match = match_object
        self._offset = offset
        self._file_offset = file_offset
        self._strings = None

    def __getattr__(self, item):
        return getattr(self._match, item)

    def __str__(self):
        return str(self._match)

    def __repr__(self):
        return repr(self._match)

    @property
    def strings(self):
        # Before returning strings, fixup the offsets to be virtual addresses.
        if self._strings is None:
            self._strings = []
            for offset, identifier, data in self._match.strings:
                if self._offset is not None:
                    offset += self._offset
                if self._file_offset:
                    offset = idaapi.get_fileregion_ea(offset)
                self._strings.append((idc.get_item_head(offset), identifier, data))
        return self._strings


class Rules(object):
    """
    Patches yara.Rules to use our patched Match object when match() is called.

    NOTE: We can't inherit yara.Rules because they don't expose that class.
    """

    def __init__(self, rules_object):
        self._rules = rules_object
        self._infos = None

    def __getattr__(self, item):
        return getattr(self._rules, item)

    def _extract_info(self):
        """
        Retrieve information about the rule by performing a kludgy dance with callbacks.
        YARA should allow an easier way to give this information!
        """
        if self._infos is None:
            # YARA doesn't provide any easy way to get rule info, so we are going to have
            # to fake a match to get the info dictionary.
            self._infos = []
            def _callback(info):
                self._infos.append(info)
                return yara.CALLBACK_CONTINUE
            self._rules.match(data=b'', callback=_callback, which_callbacks=yara.CALLBACK_NON_MATCHES)
        return self._infos

    @property
    def names(self):
        """Returns names of all the rules contained within."""
        infos = self._extract_info()
        return [info['rule'] for info in infos]

    def match(self, *args, **kwargs):
        """
        Patched to use our patched Match() object and allow for automatically running
        on IDB input file.

        Besides the default yara parameters, this implementation also includes:
            :param bool input_offset: Whether to apply input file offset to string offsets.
            :param int offset: Optional offset to offset string offsets by.
            :param str|int segment: Name or EA of segment to match to.
        """
        input_offset = kwargs.pop('input_offset', False)
        offset = kwargs.pop('offset', None)
        segment = kwargs.pop('segment', None)

        # Run on segment.
        if segment:
            kwargs['data'] = segments.get_bytes(segment)
            offset = offset or segments.get_start(segment)
        # Run on input file.
        elif not (args or kwargs):
            args = (idc.get_input_file_path(),)
            input_offset = True

        return [Match(match, offset=offset, file_offset=input_offset)
                for match in self._rules.match(*args, **kwargs)]

    def match_strings(self, *args, **kwargs):
        """
        Runs match() but then returns tuples containing matched strings instead of Match objects.

        (This replicates the original legacy _YARA_MATCHES output)

        :returns: Tuple containing: (offset, identifier)
        """
        matched_strings = []
        for match in self.match(*args, **kwargs):
            for offset, identifier, _ in match.strings:
                matched_strings.append((offset, identifier))
        return matched_strings


def compile(*args, **kwargs):
    """Wraps compiled rule in our patched Rules object."""
    return Rules(yara.compile(*args, **kwargs))


def load(*args, **kwargs):
    """Wraps loaded rule in our patched Rules object."""
    return Rules(yara.load(*args, **kwargs))


# Convenience functions ==============


def match(rule_text, *args, **kwargs):
    rule = compile(source=rule_text)
    return rule.match(*args, **kwargs)


def match_strings(rule_text, *args, **kwargs):
    rule = compile(source=rule_text)
    return rule.match_strings(*args, **kwargs)

# ====================================
