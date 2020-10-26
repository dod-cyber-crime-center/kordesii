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
from ... import actions, utils, constants, objects
from ...call_hooks import builtin_func

logger = logging.getLogger(__name__)


def _get_reg_key(cpu_context, root_key_handle, sub_key_ptr, wide=False):
    """
    Retrieves the root key and sub key strings from the given hKey and lpSubKey arguments.

    :param root_key_handle: The hKey argument (the HKEY handle for the root key)
    :param sub_key_ptr: The lpSubKey argument (the pointer to the sub key string)
    :param wide: Whether strings are utf16 or utf8
    """
    # Get root key
    if root_key_handle in cpu_context.objects:
        root_key = cpu_context.objects[root_key_handle].path
    elif root_key_handle in wc.RegistryKey.__members__.values():
        # root key is a predefined enum.
        root_key = wc.RegistryKey(root_key_handle).name
    else:
        logger.warning("Invalid registry key 0x%X, using hex string.", root_key_handle)
        root_key = hex(root_key_handle)

    # Get sub key
    if not sub_key_ptr:
        sub_key = None
    else:
        sub_key = cpu_context.read_data(
            sub_key_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
        ).decode("utf-16-le" if wide else "utf8")

    return root_key, sub_key


@builtin_func("RegOpenKeyA")
@builtin_func("RegOpenKeyW")
@builtin_func("RegOpenKeyExA")
@builtin_func("RegOpenKeyExW")
@builtin_func("RegCreateKeyA")
@builtin_func("RegCreateKeyW")
@builtin_func("RegCreateKeyExA")
@builtin_func("RegCreateKeyExW")
#typespec("LSTATUS RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)")
#typespec("int RegCreateKeyA(HKEY hKey, char* lpSubKey, HKEY* phkResult);")
#typespec("int RegCreateKeyW(HKEY hKey, wchar* lpSubKey, HKEY* phkResult);")
#typespec("int RegCreateKeyExA(HKEY hKey, char* lpSubKey, DWORD, char* lpClass, DWORD dwOptions, REGSAM samDesired, const SECURITY_ATTRIBUTES* lpSecurityAttributes, HKEY* phkResult, DWORD* lpdwDisposition);")
#typespec("int RegCreateKeyExA(HKEY hKey, wchar* lpSubKey, DWORD, wchar* lpClass, DWORD dwOptions, REGSAM samDesired, const SECURITY_ATTRIBUTES* lpSecurityAttributes, HKEY* phkResult, DWORD* lpdwDisposition);")
def reg_open_key(cpu_context, func_name, func_args):
    """
    Opens/Creates the specified registry key

    We are merging RegOpenKey* and RegCreateKey* because their effects are essentially same except
    for the extra disposition argument.
    """
    wide = func_name.endswith("W")
    root_key_handle, sub_key_ptr, *rest = func_args
    if func_name.startswith("RegCreateKeyEx"):
        result_ptr = rest[-2]  # RegCreateKeyEx has an extra disposition argument at the end.
    else:
        result_ptr = rest[-1]  # result pointer is last argument in both Ex and non-Ex versions.

    root_key, sub_key = _get_reg_key(cpu_context, root_key_handle, sub_key_ptr, wide)

    # If subkey is null or an empty string, result is the same as the root key handle.
    if not sub_key:
        disposition = wc.REG_OPENED_EXISTING_KEY
        cpu_context.mem_write(
            result_ptr, utils.struct_pack(root_key_handle, width=cpu_context.byteness)
        )
        logger.debug("Opening existing registry key: %s", root_key)

    # Otherwise create new RegKey object.
    else:
        disposition = wc.REG_CREATED_NEW_KEY
        reg_key = objects.RegKey(root_key, sub_key)
        cpu_context.objects.add(reg_key)
        cpu_context.mem_write(
            result_ptr, utils.struct_pack(reg_key.handle, width=cpu_context.byteness)
        )
        cpu_context.actions.append(actions.RegKeyOpened(cpu_context.ip, reg_key.path))
        logger.debug("Opening registry key: %s", reg_key.path)

    # Need to report disposition if RegCreateKeyEx*
    if func_name.startswith("RegCreateKeyEx"):
        disposition_ptr = func_args[-1]
        if disposition_ptr:
            cpu_context.write_data(disposition_ptr, disposition, data_type=constants.DWORD)

    return wc.ERROR_SUCCESS


@builtin_func("RegDeleteKeyA")
@builtin_func("RegDeleteKeyW")
@builtin_func("RegDeleteKeyExA")
@builtin_func("RegDeleteKeyExW")
#typespec("int RegDeleteKeyA(HKEY hKey, char* lpSubKey);")
#typespec("int RegDeleteKeyW(HKEY hKey, wchar* lpSubKey);")
#typespec("int RegDeleteKeyExA(HKEY hKey, char* lpSubKey, REGSAM samDesired, DWORD Reserved);")
#typespec("int RegDeleteKeyExW(HKEY hKey, wchar* lpSubKey, REGSAM samDesired, DWORD Reserved);")
def reg_delete_key(cpu_context, func_name, func_args):
    """
    Deletes a subkey and its values.
    """
    wide = func_name.endswith("W")
    root_key_handle, sub_key_ptr, *_ = func_args

    root_key, sub_key = _get_reg_key(cpu_context, root_key_handle, sub_key_ptr, wide)

    if not sub_key:
        logger.warning("Sub key is null")
        return

    path = "\\".join([root_key, sub_key])
    cpu_context.actions.append(actions.RegKeyDeleted(cpu_context.ip, path))
    logger.debug("Deleting registry key: %s", path)

    return wc.ERROR_SUCCESS


@builtin_func("RegDeleteKeyValueA")
@builtin_func("RegDeleteKeyValueW")
#typespec("int RegDeleteKeyValueA(HKEY hKey, char* lpSubKey, char* lpValueName);")
#typespec("int RegDeleteKeyValueW(HKEY hKey, wchar* lpSubKey, wchar* lpValueName);")
def reg_delete_key_value(cpu_context, func_name, func_args):
    """
    Removes the specified value from the specified registry key and subkey.
    """
    wide = func_name.endswith("W")
    root_key_handle, sub_key_ptr, value_name_ptr = func_args

    root_key, sub_key = _get_reg_key(cpu_context, root_key_handle, sub_key_ptr, wide)
    value_name = cpu_context.read_data(
        value_name_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")

    path = "\\".join([root_key, sub_key or ""])
    cpu_context.actions.append(actions.RegKeyValueDeleted(cpu_context.ip, path, value_name))
    logger.debug("Deleting value %s from registry key %s", value_name, path)

    return wc.ERROR_SUCCESS


@builtin_func("RegDeleteValueA")
@builtin_func("RegDeleteValueW")
#typespec("int RegDeleteValueA(HKEY hKey, char* lpValueName);")
#typespec("int RegDeleteValueW(HKEY hKey, wchar* lpValueName);")
def reg_delete_value(cpu_context, func_name, func_args):
    """
    Removes a named value from the specified registry key.
    """
    wide = func_name.endswith("W")
    root_key_handle, value_name_ptr = func_args

    root_key, _ = _get_reg_key(cpu_context, root_key_handle, 0, wide)
    value_name = cpu_context.read_data(
        value_name_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")

    path = root_key
    cpu_context.actions.append(actions.RegKeyValueDeleted(cpu_context.ip, path, value_name))
    logger.debug("Deleting value %s from registry key %s", value_name, path)

    return wc.ERROR_SUCCESS


@builtin_func("RegSetValueA")
@builtin_func("RegSetValueW")
@builtin_func("RegSetValueExA")
@builtin_func("RegSetValueExW")
#typespec("int RegSetValueA(HKEY hKey, char* lpSubKey, DWORD dwType, char* lpData, DWORD cbData);")
#typespec("int RegSetValueA(HKEY hKey, wchar* lpSubKey, DWORD dwType, wchar* lpData, DWORD cbData);")
#typespec("int RegSetValueExA(HKEY, char* lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);")
#typespec("int RegSetValueExA(HKEY, wchar* lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);")
def reg_set_value(cpu_context, func_name, func_args):
    """
    Sets the data for the default or unnamed value of a specified registry key.
    """
    wide = func_name.endswith("W")
    root_key_handle, sub_key_ptr, *_, data_type, data_ptr, data_size = func_args

    root_key, sub_key = _get_reg_key(cpu_context, root_key_handle, sub_key_ptr, wide)

    path = "\\".join([root_key, sub_key or ""])
    data_type = wc.RegistryDataType(data_type)

    # Data is a null-terminated string
    if data_type.name in ("REG_SZ", "REG_LINK", "REG_EXPAND_SZ"):
        data = cpu_context.read_data(data_ptr, data_type=constants.STRING)
        data = data.decode("utf8")

    # Data is a sequence of null-terminated strings, terminated by an empty string (\0)
    elif data_type.name == "REG_MULTI_SZ":
        # Since the last string is empty, this terminates as a double null,
        # which allows us to use WIDE_STRING.
        data = cpu_context.read_data(data_ptr, data_type=constants.WIDE_STRING)
        data = [string.decode("utf8") for string in data.split(b'\x00') if string]

    elif data_type.name == "REG_BINARY":
        data = cpu_context.read_data(data_ptr, size=data_size)

    elif data_type.name == "REG_DWORD":
        data = cpu_context.read_data(data_ptr, data_type=constants.DWORD)

    elif data_type.name == "REG_QWORD":
        data = cpu_context.read_data(data_ptr, data_type=constants.QWORD)

    elif data_type.name == "REG_NONE":
        data = None

    else:
        raise NotImplementedError(f"Unsupported data type: {data_type.name}")

    cpu_context.actions.append(actions.RegKeyValueSet(cpu_context.ip, path, data_type.name, data))
    logger.debug("Setting value %r to registry key %s", data, path)

    return wc.ERROR_SUCCESS


@builtin_func("OpenSCManagerA")
@builtin_func("OpenSCManagerW")
#typespec("HANDLE OpenSCManagerA(char* lpMachineName, char* lpDatabasename, DWORD dwDesiredAccess);")
#typespec("HANDLE OpenSCManagerA(wchar* lpMachineName, wchar* lpDatabasename, DWORD dwDesiredAccess);")
def open_sc_manager(cpu_context, func_name, func_args):
    """
    Establishes a connection to the service control manager on the specified computer
    and opens the specified service control manager database.
    """
    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


@builtin_func("CreateServiceA")
@builtin_func("CreateServiceW")
#typespec("HANDLE CreateServiceA(HANDLE hSCManager, char* lpServiceName, char* lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, char* lpBinaryPathName, char* lpLoadOrderGroup, DWORD* lpdwTagId, char* lpDependencies, char* lpServiceStartName, char* lpPassword);")
#typespec("HANDLE CreateServiceW(HANDLE hSCManager, wchar* lpServiceName, wchar* lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, wchar* lpBinaryPathName, wchar* lpLoadOrderGroup, DWORD* lpdwTagId, wchar* lpDependencies, wchar* lpServiceStartName, wchar* lpPassword);")
def create_service(cpu_context, func_name, func_args):
    """
    Creates a service object and adds it to the specified service control manager database.
    """
    wide = func_name.endswith("W")
    service_name_ptr = func_args[1]
    display_name_ptr = func_args[2]
    desired_access = func_args[3]
    service_type = func_args[4]
    start_type = func_args[5]
    binary_path_ptr = func_args[7]

    service_name = cpu_context.read_data(service_name_ptr).decode("utf-16-le" if wide else "utf8")
    display_name = cpu_context.read_data(display_name_ptr).decode("utf-16-le" if wide else "utf8")
    binary_path = cpu_context.read_data(binary_path_ptr).decode("utf-16-le" if wide else "utf8")
    desired_access = wc.ServiceAccess(desired_access)
    service_type = wc.ServiceType(service_type)
    start_type = wc.ServiceStart(start_type)

    action = actions.ServiceCreated(
        ip=cpu_context.ip,
        name=service_name,
        access=desired_access,
        service_type=service_type,
        start_type=start_type,
        display_name=display_name,
        binary_path=binary_path,
    )
    cpu_context.actions.append(action)
    logger.debug("Created: %r", action)

    # TODO: Keep track of service handles like we do with files?
    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)
