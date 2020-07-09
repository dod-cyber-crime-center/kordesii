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
import ntpath

from ... import constants
from ...call_hooks import builtin_func


logger = logging.getLogger(__name__)


@builtin_func("PathAppendA")
@builtin_func("PathAppendW")
#typedef(BOOL PathAppendA(LPSTR  pszPath,LPCSTR pszMore);)
def pathappend(cpu_context, func_name, func_args):
    """
    Appends one path to the end of another
    """
    wide = func_name.endswith(u"W")
    path_ptr, more_ptr = func_args

    curr_path = cpu_context.read_data(
        path_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")
    more_path = cpu_context.read_data(
        more_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")

    full_path = ntpath.join(curr_path, more_path)
    cpu_context.write_data(path_ptr, full_path, data_type=constants.WIDE_STRING if wide else constants.STRING)
    return True
