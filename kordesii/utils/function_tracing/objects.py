"""
Interfaces for higher level elements such as open files or registry keys.
"""
import ntpath
import logging
from copy import deepcopy
from typing import Iterable, Type, TypeVar

from .actions import *


logger = logging.getLogger(__name__)
T = TypeVar("T")


class ObjectMap(object):
    """
    Interface for obtaining high-level representations of objects encountered during emulation.

    NOTE: Generated objects are immutable and are not bound to the current cpu context after generation.
        (This is different to other item types like Variable, FunctionSignature, Operand, etc.)
    """

    # The bounds on handles that can be used for Objects
    MIN_HANDLE = 0x80
    MAX_HANDLE = 0xFFFFFFFF - 1

    def __init__(self, cpu_context):
        self._cpu_context = cpu_context
        self._next_handle = self.MIN_HANDLE

    def __repr__(self):
        objs = "\n\t".join([repr(obj) for obj in self])
        return f"<ObjectMap : \n\t{objs}\n>"

    def __deepcopy__(self, memo):
        """
        Custom implementation of deepcopy to improve efficiency.
        """
        copy = ObjectMap(deepcopy(self._cpu_context, memo))
        copy._next_handle = self._next_handle
        return copy

    # TODO: Look into caching this if the actions haven't changed.
    #   Perhaps cache within ActionList instead?
    def __getitem__(self, handle: int) -> "Object":
        """Gets an object by handle"""
        if handle not in self:
            raise KeyError(f"Object with handle: {hex(handle)} does not exist.")

        actions = [
            action
            for action in self._cpu_context.actions
            if getattr(action, "handle", None) == handle
        ]
        # Determine the type of object to yield by peeking at the first action.
        # Default to generic Object.
        if actions:
            for object_class in Object.__subclasses__():
                if isinstance(actions[0], object_class.action_types):
                    return object_class(handle, actions)

        # Default to generic Object
        return Object(handle, actions)

    def get(self, handle: int, default=None) -> "Object":
        """Gets an object by handle"""
        try:
            return self[handle]
        except KeyError:
            return default

    def __len__(self) -> int:
        return self._next_handle - self.MIN_HANDLE

    def __contains__(self, handle: int) -> bool:
        return self.MIN_HANDLE <= handle < self._next_handle

    def __bool__(self):
        return self._next_handle > self.MIN_HANDLE

    def _iter(self, reverse=False) -> Iterable["Object"]:
        """
        Yields all known objects based on current set of actions in the cpu context.
        """
        for handle in reversed(self.handles) if reverse else self.handles:
            yield self[handle]

    def __iter__(self):
        """
        Yields all known objects based on current set of actions in the cpu context.
        Iterates least recently used to most.
        """
        yield from self._iter()

    def __reversed__(self):
        """
        Yields all known objects based on current set of actions in cpu context.
        Iterates most recently used to least.
        """
        yield from self._iter(reverse=True)

    @property
    def handles(self) -> List[int]:
        """
        List of allocated handles.
        """
        return list(range(self.MIN_HANDLE, self._next_handle))

    def alloc(self) -> int:
        """
        Allocates and returns the next available handle address.
        """
        if self._next_handle > self.MAX_HANDLE:
            raise ValueError("Too many handles created.")
        handle = self._next_handle
        self._next_handle += 1
        return handle

    def get_or_alloc(self, obj_type: Type["Object"], **query) -> int:
        """
        Returns the handle of a known object or a new handle if an object
        of type `obj_type` containing the attribute(s) equivalent to those
        found in `query` does not exist.
        """
        # First grab the most recent object containing the handle.
        # Reverse to ensure we get the most recent one.
        for obj in self.query(obj_type, reverse=True, **query):
            return obj.handle
        return self.alloc()

    def query(self, obj_type: Type[T], reverse=False, **conditions) -> Iterable[T]:
        """
        Returns the handle of a known object
        :param obj_type: Type of object to query for.
        :param reverse: Whether to produce objects from most recently used to least.
        :param conditions: Attributes to look for.
        :return:
        """
        for obj in (reversed(self) if reverse else self):
            if isinstance(obj, obj_type) \
                    and all(getattr(obj, attr_name) == value for attr_name, value in conditions.items()):
                yield obj

    def at(self, ip: int) -> List["Object"]:
        """
        Retrieves the objects referenced at the given instruction address.

        :param ip: Instruction address to get pointers from.
        :return: List of Object objects that were found within the given instruction.

        :raises ValueError: If instruction has not been executed yet.
        """
        if ip not in self._cpu_context.executed_instructions:
            raise ValueError(
                f"Unable to get objects. Instruction at 0x{ip:0x} has not been executed."
            )
        return [obj for obj in self if ip in obj.references]


class Object(object):
    """
    Represents an high level instantiated object during emulation.
    """

    # The type of Actions that builds the object.
    # TODO: Create a __new__() to validate action types are unique per class.
    action_types = tuple()

    def __init__(self, handle: int, actions: List[Action]):
        # The list of actions that are relevant to this object.
        self.handle = handle
        self.actions = actions

    @property
    def references(self) -> List[int]:
        """The address locations where this object has been encountered."""
        return [action.ip for action in self.actions]


class File(Object):
    """
    Stores information for opened files for a specific CPU context state.
    """

    action_types = (
        FileCreated, FileOpened, FileTruncated, FileDeleted, FileMoved, FileWritten, FileClosed
    )
    file_creation_types = (FileCreated, FileOpened, FileTruncated)

    def __repr__(self):
        data = self.data
        data_str = repr(data[:10])
        if len(data) > 10:
            data_str = data_str[:-1] + "..." + data_str[-1]
        return (
            f"<File 0x{self.handle:08X}"
            f" : path = {self.path}"
            f" : mode = {self.mode}"
            f" : size = {len(data)}"
            f" : data = {data_str}"
            f">"
        )

    @property
    def data(self):
        """The data written to the file."""
        return b"".join([action.data for action in self.actions if isinstance(action, FileWritten)])

    @property
    def path(self) -> Optional[str]:
        """The path of the file."""
        for action in reversed(self.actions):
            if isinstance(action, self.file_creation_types + (FileDeleted,)):
                return action.path
            elif isinstance(action, FileMoved):
                return action.new_path

    @property
    def name(self) -> Optional[str]:
        """The base name of the file."""
        if self.path:
            return ntpath.basename(self.path)

    @property
    def history(self) -> List[str]:
        """List of previous file paths."""
        history = []
        for action in self.actions:
            if isinstance(action, FileMoved):
                history.append(action.old_path)
        return history

    @property
    def mode(self) -> Optional[str]:
        """The mode the file was last opened with."""
        for action in reversed(self.actions):
            if isinstance(action, self.file_creation_types):
                return action.mode

    @property
    def closed(self) -> Optional[bool]:
        """
        Whether or not the file has been closed.
        If None, this information is unknown.
        """
        for action in reversed(self.actions):
            if isinstance(action, FileClosed):
                return True
            elif isinstance(action, self.file_creation_types):
                return False

    @property
    def deleted(self) -> Optional[bool]:
        """
        Whether or not the file has been deleted.
        If None, this information is unknown.
        """
        for action in reversed(self.actions):
            if isinstance(action, FileDeleted):
                return True
            elif isinstance(action, self.file_creation_types):
                return False


class RegKey(Object):
    """
    Stores information for opened registry keys for a specific CPU context state.
    """

    action_types = (
        RegKeyOpened, RegKeyDeleted, RegKeyValueDeleted, RegKeyValueSet
    )

    def __repr__(self):
        return (
            f"<RegKey 0x{self.handle:08X}"
            f" : root_key = {self.root_key}"
            f" : sub_key = {self.sub_key}"
            f">"
        )

    @property
    def root_key(self) -> Optional[str]:
        """The root key of the registry key."""
        for action in reversed(self.actions):
            if isinstance(action, RegKeyOpened):
                return action.root_key

    @property
    def sub_key(self) -> Optional[str]:
        """The sub key of the registry key."""
        for action in reversed(self.actions):
            if isinstance(action, RegKeyOpened):
                return action.sub_key

    @property
    def path(self) -> Optional[str]:
        """The full path of the registry key."""
        if self.root_key and self.sub_key:
            return "\\".join([self.root_key, self.sub_key])


class Service(Object):
    """
    Stores information pertaining to a service
    """

    action_types = (
        ServiceCreated, ServiceOpened, ServiceDeleted, ServiceDescriptionChanged
    )

    def __repr__(self):
        return (
            f"<Service 0x{self.handle:08X}"
            f" : name = {self.name}"
            f" : description = {self.description}"
            f">"
        )

    @property
    def name(self) -> Optional[str]:
        """The name of the service."""
        for action in reversed(self.actions):
            if isinstance(action, ServiceCreated) or isinstance(action, ServiceOpened):
                return action.name

    @property
    def description(self) -> Optional[str]:
        """The description of the service"""
        for action in reversed(self.actions):
            if isinstance(action, ServiceDescriptionChanged):
                return action.description
