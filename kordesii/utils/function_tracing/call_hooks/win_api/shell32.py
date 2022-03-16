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

    logger.debug("%s: %r %r", func_name, operation, filepath)
    cpu_context.actions.add(
        actions.ShellOperation(cpu_context.ip, operation, filepath, params, directory, wc.Visibility(visibility))
    )

    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


# Dictionary mapping CSIDL values to their default values on 64-bit Windows 10. Created by taking the listing from the
# SpecialFoldersView.exe utility from NirSoft and then cleaning it up to use more appropriate environment variables.
CSIDL_DICT_WIN10x64 = {
    wc.CSIDL.CSIDL_PROGRAMS: r"%AppData%\Microsoft\Windows\Start Menu\Programs",
    wc.CSIDL.CSIDL_PERSONAL: r"%UserProfile%\Documents",
    wc.CSIDL.CSIDL_FAVORITES: r"%UserProfile%\Favorites",
    wc.CSIDL.CSIDL_STARTUP: r"%AppData%\Microsoft\Windows\Start Menu\Programs\Startup",
    wc.CSIDL.CSIDL_RECENT: r"%AppData%\Microsoft\Windows\Recent",
    wc.CSIDL.CSIDL_SENDTO: r"%AppData%\Microsoft\Windows\SendTo",
    wc.CSIDL.CSIDL_STARTMENU: r"%AppData%\Microsoft\Windows\Start Menu",
    wc.CSIDL.CSIDL_MYMUSIC: r"%UserProfile%\Music",
    wc.CSIDL.CSIDL_MYVIDEO: r"%UserProfile%\Videos",
    wc.CSIDL.CSIDL_DESKTOPDIRECTORY: r"%UserProfile%\Desktop",
    wc.CSIDL.CSIDL_NETHOOD: r"%AppData%\Microsoft\Windows\Network Shortcuts",
    wc.CSIDL.CSIDL_FONTS: r"%SystemRoot%\Fonts",
    wc.CSIDL.CSIDL_TEMPLATES: r"%AppData%\Microsoft\Windows\Templates",
    wc.CSIDL.CSIDL_COMMON_STARTMENU: r"%AllUsersProfile%\Microsoft\Windows\Start Menu",
    wc.CSIDL.CSIDL_COMMON_PROGRAMS: r"%AllUsersProfile%\Microsoft\Windows\Start Menu\Programs",
    wc.CSIDL.CSIDL_COMMON_STARTUP: r"%AllUsersProfile%\Microsoft\Windows\Start Menu\Programs\Startup",
    wc.CSIDL.CSIDL_COMMON_DESKTOPDIRECTORY: r"%Public%\Desktop",
    wc.CSIDL.CSIDL_APPDATA: r"%AppData%",
    wc.CSIDL.CSIDL_PRINTHOOD: r"%AppData%\Microsoft\Windows\Printer Shortcuts",
    wc.CSIDL.CSIDL_LOCAL_APPDATA: r"%LocalAppData%",
    wc.CSIDL.CSIDL_COMMON_FAVORITES: r"%UserProfile%\Favorites",
    wc.CSIDL.CSIDL_INTERNET_CACHE: r"%LocalAppData%\Microsoft\Windows\INetCache",
    wc.CSIDL.CSIDL_COOKIES: r"%LocalAppData%\Microsoft\Windows\INetCookies",
    wc.CSIDL.CSIDL_HISTORY: r"%LocalAppData%\Microsoft\Windows\History",
    wc.CSIDL.CSIDL_COMMON_APPDATA: r"%AllUsersProfile%",
    wc.CSIDL.CSIDL_WINDOWS: r"%WinDir%",
    wc.CSIDL.CSIDL_SYSTEM: r"%SystemRoot%\System32",
    wc.CSIDL.CSIDL_PROGRAM_FILES: r"%ProgramFiles%",
    wc.CSIDL.CSIDL_MYPICTURES: r"%UserProfile%\Pictures",
    wc.CSIDL.CSIDL_PROFILE: r"%UserProfile%",
    wc.CSIDL.CSIDL_SYSTEMX86: r"%SystemRoot%\SysWOW64",
    wc.CSIDL.CSIDL_PROGRAM_FILESX86: r"%ProgramFiles(x86)%",
    wc.CSIDL.CSIDL_PROGRAM_FILES_COMMON: r"%CommonProgramFiles%",
    wc.CSIDL.CSIDL_PROGRAM_FILES_COMMONX86: r"%CommonProgramFiles(x86)%",
    wc.CSIDL.CSIDL_COMMON_TEMPLATES: r"%AllUsersProfile%\Microsoft\Windows\Templates",
    wc.CSIDL.CSIDL_COMMON_DOCUMENTS: r"%Public%\Documents",
    wc.CSIDL.CSIDL_COMMON_ADMINTOOLS: r"%AllUsersProfile%\Microsoft\Windows\Start Menu\Programs\Administrative Tools",
    wc.CSIDL.CSIDL_ADMINTOOLS: r"%AppData%\Microsoft\Windows\Start Menu\Programs\Administrative Tools",
    wc.CSIDL.CSIDL_COMMON_MUSIC: r"%Public%\Music",
    wc.CSIDL.CSIDL_COMMON_PICTURES: r"%Public%\Pictures",
    wc.CSIDL.CSIDL_COMMON_VIDEO: r"%Public%\Videos",
    wc.CSIDL.CSIDL_CDBURN_AREA: r"%LocalAppData%\Microsoft\Windows\Burn\Burn"
}


@builtin_func("SHGetFolderPathA")
@builtin_func("SHGetFolderPathW")
@builtin_func("SHGetSpecialFolderPathA")
@builtin_func("SHGetSpecialFolderPathW")
#typespec("SHFOLDERAPI SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags,  LPSTR  pszPath);")
#typespec("BOOL SHGetSpecialFolderPathA(HWND hwnd, LPSTR pszPath, int csidl, BOOL fCreate);")
def sh_get_folder_path(cpu_context, func_name, func_args):
    """
    Retrieves the CSIDL folder mapping for the provided CSIDL Enumeration

    Attempts to expand folder based on default 64-bit Windows 10 values.
    """
    wide = func_name.endswith("W")
    if "Special" in func_name:
        _, path_ptr, csidl, _ = func_args
    else:
        _, csidl, _, _, path_ptr = func_args

    # Mask off any CSIDL flags
    csidl &= 0xff
    if csidl in CSIDL_DICT_WIN10x64:
        folder = CSIDL_DICT_WIN10x64[csidl]
    else:
        logger.warning("Could not acquire a folder for CSIDL %d", csidl)
        folder = f"{csidl}"

    logger.debug("Writing CSIDL %s to 0x%08X", folder, path_ptr)
    cpu_context.write_data(path_ptr, folder, data_type=constants.WIDE_STRING if wide else constants.STRING)
    return wc.ERROR_SUCCESS
