"""
Base interface for decoders
"""

import ast
from collections import namedtuple
import re
import logging
import os

import kordesii

Source = namedtuple("Source", ("name", "path"))


logger = logging.getLogger(__name__)


class Decoder(object):
    def __init__(self, script_path, name=None, source=None):
        """
        Initializes Decoder object.
        :param script_path: Path to script to run within dissasembler.
        :param name: Name of decoder, file basename is used it not provided.
        :param source: Optional Source namedtuple containing (source_name, source_path)
        """
        self._doc_string = None
        self._author = None
        self._description = None
        self.script_path = script_path
        # Just use directory name of script if source not provided.
        directory = os.path.dirname(script_path)
        self.source = source or Source(directory, directory)
        if name:
            self.name = name
        else:
            self.name, _ = os.path.splitext(os.path.basename(script_path))
            # Remove legacy postfix if it exists.
            if self.name.endswith("_StringDecode"):
                self.name = self.name[: -len("_StringDecode")]
        self.full_name = "{}:{}".format(self.source.name, self.name)

    def __repr__(self):
        return "<{} Decoder at {}>".format(self.name, self.script_path)

    @property
    def docstring(self):
        """Retrieves the docstring within the decoder source or '' if no docstring exists."""
        if self._doc_string is not None:
            return self._doc_string
        # Open up script file and parse for docstring.
        # (We can't import because these decoders are designed to work within a disassembler and
        #  will explode if we try to import them on the outside.)
        with open(self.script_path, "r") as fo:
            mod = ast.parse(fo.read(), self.script_path)
            try:
                self._doc_string = ast.get_docstring(mod)
            except TypeError:
                self._doc_string = ""
        return self._doc_string

    # TODO: Use the same "@" syntax used by ghidra.
    @property
    def description(self):
        """Retrieves description from docstring or '' if not found."""
        if self._description is not None:
            return self._description
        docstring = self.docstring
        if not docstring:
            self._description = ""
            return self._description
        match = re.search("Description:(.*?)$", docstring, re.MULTILINE)
        if match:
            self._description = match.group(1).strip()
        else:
            self._description = ""
        return self._description

    @property
    def author(self):
        """Retrieves author from docstring or '' if not found."""
        if self._author is not None:
            return self._author
        docstring = self.docstring
        if not docstring:
            self._author = ""
            return self._author
        match = re.search("Author:(.*?)$", docstring, re.MULTILINE)
        if match:
            self._author = match.group(1).strip()
        else:
            self._author = ""
        return self._author

    def run(self, input_file, reporter, **run_config):
        """
        Runs decoder on given input_file.

        :param input_file: File path to input file to run decoder on.
        :param reporter: Reporter object to use for reporting metadata.
        :param run_config: Run configuration to pass along to kordesii.run_ida()
        """
        # IDA doesn't like backslashes in it's argv.
        input_file = input_file.replace("\\", "/").strip()
        script_path = self.script_path.replace("\\", "/").strip()

        kordesii.run_ida(reporter, script_path, input_file, **run_config)
