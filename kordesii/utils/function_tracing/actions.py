"""
Interface for interesting actions.
"""

from dataclasses import dataclass
import logging
from typing import Union, List, Optional, Iterable
from .call_hooks.win_api import win_constants

logger = logging.getLogger(__name__)


@dataclass
class Action:
    ip: int


class ActionList(object):
    """
    Represents a reverse linked list of actions that have occurred up
    to a specific ProcessorContext.
    """

    def __init__(self, *actions: Action):
        self.tail: Optional[ActionNode] = None
        for action in actions:
            self.add(action)

    def __repr__(self):
        return f"ActionList({repr(self.tail) if self.tail else ''})"

    def __deepcopy__(self, memo):
        copy = ActionList()
        copy.tail = self.tail
        return copy

    def __iter__(self):
        if self.tail:
            yield from self.tail

    def __reversed__(self):
        if self.tail:
            yield from reversed(self.tail)

    def __getitem__(self, index: int):
        return list(self)[index]

    def __len__(self):
        return len(list(self))

    def __bool__(self):
        return bool(self.tail)

    def __contains__(self, item):
        return any(item == action for action in self)

    def add(self, action: Action):
        self.tail = ActionNode(action, prev=self.tail)


class ActionNode(object):
    """
    Represents a node of a reverse linked list of actions that have occurred up
    to a specific ProcessorContext.
    """

    def __init__(self, action: Action, prev: Optional["ActionNode"] = None):
        self.action = action
        self.prev = prev

    def __repr__(self):
        if self.prev:
            return f"{self.prev!r} -> {self.action}"
        else:
            return f"{self.action}"

    def __iter__(self):
        """
        Iterates actions from the least recent action that has occurred to
        the most recent action that has occurred.
        """
        if self.prev:
            yield from self.prev
        yield self.action

    def __reversed__(self):
        """
        Iterates actions from the most recent action that has occurred to
        the least recent action that has occurred.
        """
        yield self.action
        if self.prev:
            yield from reversed(self.prev)


@dataclass
class CommandExecuted(Action):
    command: str
    visibility: win_constants.Visibility = None


@dataclass
class DirectoryCreated(Action):
    path: str


@dataclass
class FileCreated(Action):
    handle: int
    path: str
    mode: str


@dataclass
class FileOpened(Action):
    handle: int
    path: str
    mode: str


@dataclass
class FileTruncated(Action):
    handle: int
    path: str
    mode: str


@dataclass
class FileDeleted(Action):
    handle: int
    path: str


@dataclass
class FileMoved(Action):
    handle: int
    old_path: str
    new_path: str


@dataclass
class FileClosed(Action):
    handle: int


@dataclass
class FileWritten(Action):
    handle: int
    data: bytes


@dataclass
class RegKeyOpened(Action):
    handle: int
    path: str
    root_key: str
    sub_key: str


@dataclass
class RegKeyDeleted(Action):
    handle: int
    path: str


@dataclass
class RegKeyValueDeleted(Action):
    handle: int
    path: str
    value_name: str


@dataclass
class RegKeyValueSet(Action):
    handle: int
    path: str
    data_type: str
    data: Union[bytes, str, List[str], int, None]


@dataclass
class ServiceCreated(Action):
    handle: int
    name: str
    access: win_constants.ServiceAccess
    service_type: win_constants.ServiceType
    start_type: win_constants.ServiceStart
    display_name: str
    binary_path: str


@dataclass
class ServiceOpened(Action):
    handle: int
    name: str


@dataclass
class ServiceDeleted(Action):
    handle: int


@dataclass
class ServiceDescriptionChanged(Action):
    handle: int
    description: str


@dataclass
class ShellOperation(Action):
    operation: str
    path: str
    parameters: str
    directory: str
    visibility: win_constants.Visibility = None
