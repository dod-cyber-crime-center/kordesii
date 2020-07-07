"""
CPU Emulator Built-in Windows API functions

These functions are used to emulate the effects of "useful" Windows API functions.

Add any builtin functions that need to be handled below.  The function should be declared as such

# Using the same function for multiple API functions
@builtin_func("GetSystemDirectoryA")
@builtin_func("GetSystemDirectoryW")
#typespec("UINT GetSystemDirectoryA(char* lpBuffer, UINT uSize);")
def memmove(cpu_context, func_name, func_args):
    logger.debug("Emulating GetSystemDirectoryA")

"""
import logging
import random

from mwcp.utils import construct

from . import win_constants as wc
from ... import constants
from ...call_hooks import builtin_func
from ... import actions

logger = logging.getLogger(__name__)


@builtin_func("ShellExecuteA")
@builtin_func("ShellExecuteW")
#typespec("HINSTANCE ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);)")
def shell_execute(cpu_context, func_name, func_args):
    """
    Performs an operation on a specified file
    """
    wide = func_name.endswith("W")

    _, operation_ptr, file_ptr, params_ptr, dir_ptr, visibility = func_args

    filepath = cpu_context.read_data(
        file_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")

    if params_ptr:
        params = cpu_context.read_data(
            params_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
        ).decode("utf-16-le" if wide else "utf8")
    else:
        params = u""

    if operation_ptr:
        operation = cpu_context.read_data(
            operation_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
        ).decode("utf-16-le" if wide else "utf8")
    else:
        operation = u""

    if dir_ptr:
        directory = cpu_context.read_data(
            dir_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
        ).decode("utf-16-le" if wide else "utf8")
    else:
        directory = u""

    logger.debug(f"{func_name}: {operation} {filepath}")
    cpu_context.actions.append(
        actions.ShellOperation(cpu_context.ip, operation, filepath, params, directory, visibility)
    )

    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


@builtin_func("SHGetFolderPathA")
@builtin_func("SHGetFolderPathW")
#typespec("SHFOLDERAPI SHGetFolderPathA(HWND hwnd, int    csidl,HANDLE hToken,DWORD  dwFlags,LPSTR  pszPath);")
def sh_get_folder_path(cpu_context, func_name, func_args):
    """
    Retrieves the CSIDL folder mapping for the provided CSIDL Enumeration

    Does not attempt to expand upon the folder path
    """
    wide = func_name.endswith("W")
    _, csidl, _, _, path_ptr = func_args
    csidl_int = construct.Int32ul.build(csidl)
    try:
        folder = construct.KnownFolderID(construct.Int32ul).parse(csidl_int)
    except construct.ConstructError:
        logger.warning(f"Could not acquire a folder for CSIDL {csidl}")
        folder = f"{csidl}"
    logger.debug(f"Writing CSIDL {folder} to 0x{path_ptr:08x}")
    cpu_context.write_data(path_ptr, folder, data_type=constants.WIDE_STRING if wide else constants.STRING)
    return wc.ERROR_SUCCESS


@builtin_func("SHGetSpecialFolderPathA")
@builtin_func("SHGetSpecialFolderPathW")
#typespec("BOOL SHGetSpecialFolderPathA(HWND hwnd, LPSTR pszPath, int csidl, BOOL fCreate);")
def sh_get_special_folder_path(cpu_context, func_name, func_args):
    """
    Retrieves the CSIDL folder mapping for the provided CSIDL Enumeration

    Does not attempt to expand upon the folder path
    """
    wide = func_name.endswith("W")
    _, path_ptr, csidl, _ = func_args
    csidl_int = construct.Int32ul.build(csidl)
    try:
        folder = construct.KnownFolderID(construct.Int32ul).parse(csidl_int)
    except construct.ConstructError:
        logger.warning(f"Could not acquire a folder for CSIDL {csidl}")
        folder = f"{csidl}"
    logger.debug(f"Writing CSIDL {folder} to 0x{path_ptr:08x}")
    cpu_context.write_data(path_ptr, folder, data_type=constants.WIDE_STRING if wide else constants.STRING)
    return True
