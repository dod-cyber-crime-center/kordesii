"""
Interfaces for higher level elements such as open files or registry keys.
"""
import ntpath
import os
from copy import deepcopy
import logging
from typing import Iterable


logger = logging.getLogger(__name__)


class ObjectMap(object):
    """
    Stores set of high level instantiated objects for a specific CPU context state.
    """

    MIN_HANDLE = 0x80  # Max the lowest handle reasonable
    MAX_HANDLE = 0xFFFFFFFF - 1  # set the highest handle value

    def __init__(self, cpu_context):
        self._cpu_context = cpu_context
        self._objects = []  # stores objects with index indicating handle.

    def __repr__(self):
        return "<ObjectMap : \n\t{}\n>".format("\n\t".join(map(repr, self._objects)))

    def __deepcopy__(self, memo):
        """
        Custom implementation of deepcopy to improve efficiency.
        """
        copy = ObjectMap(deepcopy(self._cpu_context, memo))
        memo[id(self)] = copy
        copy._objects = [deepcopy(_object, memo) for _object in self._objects]
        return copy

    def __iter__(self) -> Iterable["Object"]:
        return iter(self._objects)

    def __getitem__(self, handle: int) -> "Object":
        """Gets an Object by handle."""
        if not isinstance(handle, int):
            raise ValueError(f"Invalid handle: {repr(handle)}")
        index = handle - self.MIN_HANDLE
        if index < len(self._objects):
            return self._objects[index]
        else:
            raise KeyError(f"Object with handle {handle} is not found.")

    def __contains__(self, handle: int) -> bool:
        """Determines if an object for the given handle exists."""
        if not isinstance(handle, int):
            raise ValueError(f"Invalid handle: {repr(handle)}")
        return 0 <= (handle - self.MIN_HANDLE) < len(self._objects)

    def __len__(self):
        return len(self._objects)

    def get(self, handle: int, default=None) -> "Object":
        """Gets a variable by handle."""
        try:
            return self[handle]
        except KeyError:
            return default

    def add(self, obj: "Object"):
        """
        Adds given Object instance to the map.
        This will add a handle to the object.
        """
        obj.handle = self.MIN_HANDLE + len(self._objects)
        self._objects.append(obj)
        logger.debug("Added object: %r", obj)


class Object(object):
    """
    Represents an high level instantiated object during emulation.
    """

    def __init__(self):
        # These get set when added to ObjectMap
        self.handle = None
        self.references = []  # list of instruction pointers where the Object was encountered.

    def __deepcopy__(self, memo):
        copy = self.__new__(self.__class__)
        memo[id(self)] = copy
        copy.handle = self.handle
        copy.references = list(self.references)
        return copy

    def add_reference(self, ip):
        """Adds ip to list of references for this file."""
        # Ignore duplicate calls.
        if self.references and ip == self.references[-1]:
            return
        self.references.append(ip)


class File(Object):
    """
    Stores information for opened files for a specific CPU context state.
    """

    def __init__(self, path=None, mode=""):
        super(File, self).__init__()
        self._path = path      # the file path
        self.mode = mode      # the mode this file was opened with
        self.data = b""
        self.closed = False
        self.deleted = False
        self.history = []      # Keeps history of filenames

    def __deepcopy__(self, memo):
        copy = super(File, self).__deepcopy__(memo)
        copy._path = self._path
        copy.mode = self.mode
        copy.data = self.data
        copy.closed = self.closed
        copy.deleted = self.deleted
        copy.history = list(self.history)
        return copy

    def __repr__(self):
        data_str = repr(self.data[:10])
        if len(self.data) > 10:
            data_str = data_str[:-1] + "..." + data_str[-1]
        return (
            f"<File 0x{self.handle:08X}"
            f" : path = {self.path}"
            f" : mode = {self.mode}"
            f" : size = {len(self.data)}"
            f" : data = {data_str}"
            f">"
        )

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, new_path):
        """Used when setting a new path to the file."""
        if not new_path:
            logger.debug("Ignoring attempt to change file path to empty string.")
            return
        # Save old path in history.
        self.history.append(self.path)
        logger.debug("Renamed file: %s -> %s", self._path, new_path)
        self._path = new_path

    @property
    def name(self):
        """The base name of the file."""
        return ntpath.basename(self.path)

    def write(self, data):
        self.data += data

    def close(self):
        self.closed = True

    def delete(self):
        self.deleted = True


class RegKey(Object):
    """
    Stores information for opened registry keys for a specific CPU context state.
    """

    def __init__(self, root_key: str, sub_key: str):
        super(RegKey, self).__init__()
        self.root_key = root_key
        self.sub_key = sub_key

    def __deepcopy__(self, memo):
        copy = super(RegKey, self).__deepcopy__(memo)
        copy.root_key = self.root_key
        copy.sub_key = self.sub_key
        return copy

    def __repr__(self):
        return f"<RegKey 0x{self.handle:08X} : {self.path}>"

    @property
    def path(self):
        """The full path of the registry key."""
        return "\\".join([self.root_key, self.sub_key])
