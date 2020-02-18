"""
Interface for registering and accessing decoders.
"""

from collections import namedtuple
import os
import logging

import pkg_resources

from .decoder import Decoder


logger = logging.getLogger(__name__)
Source = namedtuple("Source", ("name", "path"))
# Set of decoder source names mapped to a directory path.
_sources = {}
_default_source = None


def get_default_source():
    return _default_source


def get_sources():
    """
    Returns list of Source namedtuples containing name and path.
    """
    return _sources.values()


def set_default_source(source_name):
    """
    Sets a default parser source to use if not explicitly defined.
    If this is not set, all sources will be considered.

    :param source_name: The name of the source to set.
    """
    global _default_source
    _default_source = source_name


def clear_default_source():
    """
    Clears a previously set default source.
    """
    global _default_source
    _default_source = None


def register_entry_points():
    """
    Registers decoders found in entry_point: "kordesii.decoders"
    """
    for entry in pkg_resources.iter_entry_points("kordesii.decoders"):
        package = entry.load()
        register_decoder_package(package, source_name=entry.name)


def register_decoder_directory(directory, source_name=None):
    """
    Registers decoders found in directory. This function allows you to register one-off decoders
    that are not part of an installed python package.

    :param str directory: An extra directory to look for one-off decoders.
    :param source_name: Unique name to give to the source. (uses directory path otherwise)

    :raises ValueError: If loaded config file is invalid.
    """
    global _sources

    if not os.path.isdir(directory):
        raise ValueError(u"Decoder directory not found or not a directory: {!r}".format(directory))

    # # Ensure this directory can be converted to a package and pull config_file_path if available.
    # package = _create_package(directory)

    if not source_name:
        source_name = directory

    _sources[source_name] = Source(source_name, directory)


def register_decoder_package(package, source_name=None):
    """
    Registers Python package containing Kordesii decoders.

    :param package: An Python package containing submodules that contain Kordesii decoders.
        NOTE: Package must be discoverable in subprocesses without modifying the python path.
              Please use register_decoder_directory() instead if that is not possible.
    :param source_name: Unique name to give to the source. (uses package name otherwise)
    """
    if not hasattr(package, "__path__"):
        raise ValueError(u"{!r} is not a Python package".format(package))

    if not source_name:
        source_name = package.__name__.lower()

    # We must register as directories because we will eventually to need
    # to get the script path to run it.
    register_decoder_directory(os.path.dirname(package.__file__), source_name=source_name)


def iter_decoders(name=None, source=None):
    """
    Iterates paths to all registered decoders.

    :param str name: Filters decoder based on a particular name. (":" notation is also supported)
    :param str source: Filters decoder based on a particular source.
                       (source is either the name of a python package or path to local directory)

    :yields: tuple containing: (Source tuple, decoder_path)

    :raises ValueError: If a decoder name or source could not be found.
    """
    global _sources

    if name and not source:
        # If name is using ":" notation, assume it is being organized by "source_name:decoder_name"
        # (os.path.basename is necessary in-case source is a file path containing ":"'s)
        orig_name = name
        _, _, name = os.path.basename(name).rpartition(":")
        source = orig_name[: -(len(name) + 1)]

    # Use default source if one is not provided.
    source = source or _default_source or None

    sources = []
    if source:
        if source in _sources:
            sources.append((source, _sources[source]))
    else:
        sources += _sources.items()

    for source_name, source in sources:
        # Get script path for decoder.
        if name:
            # Pull script using a "." notation to indicate subpackages.
            script_path = os.path.join(source.path, *name.split(".")) + ".py"
            # Also try with legacy postfix if it doesn't exists.
            if not os.path.exists(script_path):
                script_path = script_path[:-3] + "_StringDecode.py"
            if os.path.exists(script_path):
                yield Decoder(script_path, name=name, source=source)
            else:
                logger.debug("Unable to find {}:{} decoder.".format(source_name, name))
        else:
            # Extract all decoders within the directory
            for root, directories, filenames in os.walk(source.path):
                for filename in filenames:
                    if filename.endswith(".py") and not filename.startswith("_"):
                        script_path = os.path.join(root, filename)
                        rel_path, _ = os.path.splitext(os.path.relpath(script_path, source.path))
                        _name = rel_path.replace(os.path.sep, ".")
                        yield Decoder(script_path, name=_name, source=source)


def get_decoder_descriptions(name=None, source=None):
    """
    Retrieve list of decoder descriptions

    :param str name: Filters parser based on a particular name. (":" notation is also supported)
    :param str source: Filters parser based on a particular source.
                       (source is either the name of a python package or path to local directory)

    Returns list of tuples per parser. Tuple contains parser name, author, and description.
    """
    descriptions = []
    for decoder in iter_decoders(name=name, source=source):
        descriptions.append((decoder.name, decoder.source.name, decoder.author, decoder.description))
    return sorted(descriptions, key=lambda e: tuple(sub.lower() for sub in e))  # Case-insensitive sorting.
