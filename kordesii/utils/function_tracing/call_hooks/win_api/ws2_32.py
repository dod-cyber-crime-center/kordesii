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

from mwcp.utils import construct

from ...call_hooks import builtin_func
from ... import constants


logger = logging.getLogger(__name__)


@builtin_func("inet_addr")
#typespec("unsigned long inet_addr(const char *cp);")
def inet_addr(cpu_context, func_name, func_args):
    """
    Convert the provided inet_address to an IPv4 address
    """
    src = func_args[0]
    addr_str = cpu_context.read_data(src, data_type=constants.STRING)
    if not addr_str:
        return 0
    try:
        addr = construct.IP4Address.build(addr_str.decode())
    except construct.ConstructError:
        logger.debug("Failed to convert value %s to an IPv4 address", addr_str)
        return 0
    return construct.Int32ul.parse(addr)


@builtin_func("htons")
#typespec("u_short htons(u_short hostshort);")
def htons(cpu_context, func_name, func_args):
    """
    Convert the provided 16-bit number in host byte order (little-endian) to network byte order (big-endian)
    """
    le_port = func_args[0]
    port_str = construct.Int16ul.build(le_port)
    return construct.Int16ub.parse(port_str)


