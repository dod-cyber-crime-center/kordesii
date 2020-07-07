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
from ... import actions, utils, constants, objects
from ...call_hooks import builtin_func

logger = logging.getLogger(__name__)


@builtin_func("SHGetFolderPathA")
@builtin_func("SHGetFolderPathW")
#typespec("SHFOLDERAPI SHGetFolderPathA(HWND hwnd, int    csidl,HANDLE hToken,DWORD  dwFlags,LPSTR  pszPath);")
def shgetfolderpath(cpu_context, func_name, func_args):
    """
    Hook for SHGetFolderPath Windows API
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
def shgetfolderpath(cpu_context, func_name, func_args):
    """
    Hook for SHGetFolderPath Windows API
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
