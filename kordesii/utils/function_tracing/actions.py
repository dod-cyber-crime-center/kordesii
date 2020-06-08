"""
Interface for interesting actions.
"""

import logging
from typing import NamedTuple, Union, List
from .call_hooks.win_api import win_constants

logger = logging.getLogger(__name__)


class CommandExecuted(NamedTuple):
    ip: int
    command: str
    visibility: win_constants.Visibility = None


class DirectoryCreated(NamedTuple):
    ip: int
    path: str


class FileCreated(NamedTuple):
    ip: int
    path: str


class FileOpened(NamedTuple):
    ip: int
    path: str


class FileTruncated(NamedTuple):
    ip: int
    path: str


class FileDeleted(NamedTuple):
    ip: int
    path: str


class FileMoved(NamedTuple):
    ip: int
    old_path: str
    new_path: str


class RegKeyOpened(NamedTuple):
    ip: int
    path: str


class RegKeyDeleted(NamedTuple):
    ip: int
    path: str


class RegKeyValueDeleted(NamedTuple):
    ip: int
    path: str
    value_name: str


class RegKeyValueSet(NamedTuple):
    ip: int
    path: str
    data_type: str
    data: Union[bytes, str, List[str], int, None]


class ServiceCreated(NamedTuple):
    ip: int
    name: str
    access: win_constants.ServiceAccess
    service_type: win_constants.ServiceType
    start_type: win_constants.ServiceStart
    display_name: str
    binary_path: str
