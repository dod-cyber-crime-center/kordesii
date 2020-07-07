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

import time
import random
import logging

import ida_nalt

from . import win_constants as wc
from ...call_hooks import builtin_func
from ... import constants
from ... import actions

logger = logging.getLogger(__name__)


# Maps environment variables to the most common values.
ENV_VAR_MAP = {
    "comspec": "C:\\Windows\\system32\\cmd.exe",
    "windir": "C:\\Windows",
    "systemroot": "C:\\Windows",
    "systemdrive": "C:",
    "homedrive": "C:",
}


@builtin_func("GetEnvironmentVariableA")
@builtin_func("GetEnvironmentVariableW")
#typespec("DWORD GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize)")
def get_environment_variable(cpu_context, func_name, func_args):
    """
    Retrieves the contents of the specified variable from the environment block of the calling process.
    """
    wide = func_name.endswith("W")
    var_name_ptr, buffer_ptr, max_size = func_args
    var_name = cpu_context.read_data(
        var_name_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")

    # Replace some common environment variables, and add %'s for others.
    # - 1 for null terminator
    name = ENV_VAR_MAP.get(var_name.lower(), f"%{var_name}%")[:max_size - 1]
    cpu_context.write_data(buffer_ptr, name, data_type=constants.WIDE_STRING if wide else constants.STRING)
    logger.debug("Getting environment variable: %s -> %s", var_name, name)

    return len(name)


@builtin_func("GetCurrentDirectoryA")
@builtin_func("GetCurrentDirectoryW")
#typespec("DWORD GetCurrentDirectory(DWORD  nBufferLength, LPTSTR lpBuffer);")
def get_current_directory(cpu_context, func_name, func_args):
    """
    Retrieves the current working directory

    Using value "." to represent the current working directory for this emulator
    """
    wide = func_name.endswith("W")
    max_size, buffer_ptr = func_args

    cwd = u"."[:max_size]

    logger.debug(f"Writing current working directory {cwd} to 0x{buffer_ptr:08x}")
    cpu_context.write_data(buffer_ptr, cwd, data_type=constants.WIDE_STRING if wide else constants.STRING)

    return len(cwd)


@builtin_func("GetModuleFileNameA")
@builtin_func("GetModuleFileNameW")
#typespec("DWORD GetModuleFileNameA_1(HMODULE hModule, LPSTR lpFilename, DWORD nSize);")
def get_module_file_name(cpu_context, func_name, func_args):
    r"""
    Get the fully qualified path for the file that contains the specified module.

    Using the real filename prefixed by "%INPUT_FILE_DIR%\" to indicate the file path for this emulator.
    """
    wide = func_name.endswith("W")
    module_handle, filename_ptr, max_size = func_args

    # We don't support getting filename for modules that aren't itself.
    if module_handle != 0:
        return

    # Getting input file path as module path.
    # Since we shouldn't expose the user's real file path structure we'll use %INPUT_FILE_DIR% instead.
    # Must be truncated to fit in max_size filename_ptr (-1 for the terminator)
    file_path = "%INPUT_FILE_DIR%\\" + ida_nalt.get_root_filename()
    file_path = file_path[:max_size - 1]

    logger.debug("Writing module path %s to 0x%08X", file_path, filename_ptr)
    cpu_context.write_data(
        filename_ptr,
        file_path,
        data_type=constants.WIDE_STRING if wide else constants.STRING,
    )

    return len(file_path)


@builtin_func("GetShortPathNameA")
@builtin_func("GetShortPathNameW")
#typespec("DWORD GetShortPathNameA(LPCSTR lpszLongPath, LPSTR lpszShortPath, DWORD cchBuffer)")
def get_short_path_name(cpu_context, func_name, func_args):
    """
    Retrieves the short path form of the specified path.
    """
    # We aren't going to bother actually shortening the path name.
    # This hook is just here to ensure the destination gets filled in.
    wide = func_name.endswith("W")
    long_path_ptr, short_path_ptr, short_path_size = func_args

    long_path = cpu_context.read_data(
        long_path_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")

    short_path = long_path[:short_path_size]
    cpu_context.write_data(
        short_path_ptr, short_path, data_type=constants.WIDE_STRING if wide else constants.STRING
    )
    logger.debug("Copying %r from 0x%08X -> 0x%08X", short_path, long_path_ptr, short_path_ptr)

    return len(short_path)


@builtin_func("GetSystemDirectoryA")
@builtin_func("GetSystemDirectoryW")
#typespec("UINT GetSystemDirectoryA(char* lpBuffer, UINT uSize);")
#typespec("UINT GetSystemDirectoryW(wchar* lpbuffer, UINT uSize);")
def get_system_directory(cpu_context, func_name, func_args):
    r"""
    Retrieves the path of the system directory.

    Using unexpanded "%WinDir%\System32" to indicate the system directory for this emulator.
    """
    wide = func_name.endswith("W")
    buffer_ptr, max_size = func_args

    system_dir = r"%WinDir%\System32"[:max_size]

    logger.debug("Writing system directory %s to 0x%08X", system_dir, buffer_ptr)
    cpu_context.write_data(
        buffer_ptr,
        system_dir,
        data_type=constants.WIDE_STRING if wide else constants.STRING,
    )

    return len(system_dir)


@builtin_func("GetTempPathA")
@builtin_func("GetTempPathW")
#typespec("DWORD GetTempPathA(DWORD nBufferLength,LPSTR lpBuffer);")
def get_temp_path(cpu_context, func_name, func_args):
    """
    Retrieves the path of the temp directory

    Using unexpanded "%Temp%\" to indicate the temp directory for this emulator
    """
    wide = func_name.endswith("W")
    max_size, buffer_ptr = func_args

    # The returned string ends with a backslash
    temp_dir = u"%Temp%\\"[:max_size]

    logger.debug(f"Writing temp directory {temp_dir} to 0x{buffer_ptr:08x}")
    cpu_context.write_data(buffer_ptr, temp_dir, data_type=constants.WIDE_STRING if wide else constants.STRING)

    return len(temp_dir)


@builtin_func("GetTickCount")
@builtin_func("GetTickCount64")
#typespec("DWORD GetTickCount();")
#typespec("ULONGLONG GetTickCount64();")
def get_tick_count(cpu_context, func_name, func_args):
    """
    Retrieves the number of milliseconds that have elapsed since the system was started, up to 49.7 days.
    """
    # TODO: Should we allow users to specify a specific tick count or provide permission
    #   to use the real time when setting up Emulator?
    # mask = 0xFFFFFFFFFFFFFFFF if func_name == "GetTickCount64" else 0xFFFFFFFF
    # return int(time.time()) & mask

    # Returning a fake tick count in order for results to be more deterministic.
    return 1587410693


@builtin_func("GetWindowsDirectoryA")
@builtin_func("GetWindowsDirectoryW")
#typespec("UINT GetWindowsDirectoryA(char* lpBuffer, UINT uSize);")
#typespec("UINT GetWindowsDirectoryW(wchar* lpBuffer, UINT uSize);")
def get_windows_directory(cpu_context, func_name, func_args):
    """
    Retrieves the path of the Windows directory.

    Using unexpanded "%WinDir%" to indicate the windows directory for this emulator.
    """
    wide = func_name.endswith("W")
    buffer_ptr, max_size = func_args

    win_dir = "%WinDir%"[:max_size]
    logger.debug("Writing windows directory %s to 0x%08X", win_dir, buffer_ptr)
    cpu_context.write_data(
        buffer_ptr,
        win_dir,
        data_type=constants.WIDE_STRING if wide else constants.STRING,
    )

    return len(win_dir)


@builtin_func("CreateNamedPipeA")
#typespec("HANDLE CreateNamedPipeA(char* lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, SECURITY_ATTRIBUTES* lpSecurityAttributes);")
def create_named_pipe(cpu_context, func_name, func_args):
    """
    Creates an instance of a named pipe and returns a handle for subsequent pip operations.
    """
    # TODO: Create high level NamedPipe objects to keep track of data stored in pipes.
    #   This should work similar if not the same to the File objects we already keep track of.
    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


@builtin_func("GetComputerNameA")
@builtin_func("GetComputerNameW")
#typespec("BOOL GetComputerNameA(char* lpBuffer, DWORD* nSize);")
#typespec("BOOL GetComputerNameW(wchar* lpBuffer, DWORD* nSize);")
def get_computer_name(cpu_context, func_name, func_args):
    """
    Retrieves the NetBIOS name of the local computer.
    This name is established at system startup, when the system reads it
    from the registry.

    Using the computer name "KORDESII_COMP" for this emulator.
    TODO: Should we allow user to provide their own computer name when setting up Emulator?
    """
    wide = func_name.endswith("W")
    buffer_ptr, size_ptr = func_args

    computer_name = "KORDESII_COMP"
    logger.debug("Writing computer name %s to 0x%08X", computer_name, buffer_ptr)
    cpu_context.write_data(
        buffer_ptr,
        computer_name,
        data_type=constants.WIDE_STRING if wide else constants.STRING
    )
    cpu_context.write_data(size_ptr, len(computer_name), data_type=constants.DWORD)

    return 1  # return success


@builtin_func("GetUserNameA")
@builtin_func("GetUserNameW")
#typespec("BOOL GetUserNameA(char* lpBuffer, DWORD* pcbBuffer);")
#typespec("BOOL GetUserNameW(wchar* lpBuffer, DWORD* pcbBuffer);")
def get_user_name(cpu_context, func_name, func_args):
    """
    Retrieves the name of the user associated with the current thread.

    Using the user name "kordesii" for this emulator.
    TODO: Should we allow user to provide their own user name when setting up Emulator?
    """
    wide = func_name.endswith("W")
    buffer_ptr, size_ptr = func_args

    user_name = "kordesii"
    logger.debug("Writing user name %s to 0x%08X", user_name, buffer_ptr)
    cpu_context.write_data(
        buffer_ptr,
        user_name,
        data_type=constants.WIDE_STRING if wide else constants.STRING,
    )
    cpu_context.write_data(size_ptr, len(user_name), data_type=constants.DWORD)

    return 1  # return success


@builtin_func("CreateProcessA")
@builtin_func("CreateProcessW")
#typespec("BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)")
def create_process(cpu_context, func_name, func_args):
    """
    Create a new process.
    """
    wide = func_name.endswith("W")

    app_ptr = func_args[0]
    cmd_ptr = func_args[1]

    cmd = cpu_context.read_data(
        cmd_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
    ).decode("utf-16-le" if wide else "utf8")
    if app_ptr:
        app = cpu_context.read_data(
            app_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING
        ).decode("utf-16-le" if wide else "utf8")
        cmd = app + " " + cmd

    logger.debug(f"{func_name}: {cmd}")
    cpu_context.actions.append(actions.CommandExecuted(cpu_context.ip, cmd))

    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


@builtin_func("WinExec")
#typespec("UINT WinExec(char* lpCmdLine, UINT nCmdShow);")
def win_exec(cpu_context, func_name, func_args):
    """
    Runs the specified application.
    """
    cmd_ptr, visibility = func_args
    cmd = cpu_context.read_data(cmd_ptr).decode("utf8")

    logger.debug("WinExec: %r", cmd)
    cpu_context.actions.append(
        actions.CommandExecuted(cpu_context.ip, cmd, wc.Visibility(visibility))
    )

    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


@builtin_func("CreateDirectoryA")
@builtin_func("CreateDirectoryW")
#typespec("BOOL CreateDirectoryA(char* lpPathName, SECURITY_ATTRIBUTES* lpSecurityAttributes);")
#typespec("BOOL CreateDirectoryw(wchar* lpPathName, SECURITY_ATTRIBUTES* lpSecurityAttributes);")
def create_directory(cpu_context, func_name, func_args):
    """
    Creates a new directory.
    """
    wide = func_name.endswith("W")
    path_ptr = func_args[0]

    path = cpu_context.read_data(path_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING)
    path = path.decode("utf-16-le" if wide else "utf8")
    logger.debug("Create Directory: %r", path)

    if path:
        cpu_context.actions.append(actions.DirectoryCreated(cpu_context.ip, path))

    return 1  # return success


@builtin_func("CreateFileA")
@builtin_func("CreateFileW")
#typespec("HANDLE CreateFileA(char* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, SECURITY_ATTRIBUTES* lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);")
#typespec("HANDLE CreateFileW(wchar* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, SECURITY_ATTRIBUTES* lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);")
def create_file(cpu_context, func_name, func_args):
    """
    Creates or opens a file or I/O device.
    The function returns a handle that can be used to access the file or device for various
    types of I/O depending on the file or device and the flags and attributes specified.
    """
    wide = func_name.endswith("W")
    name_ptr = func_args[0]

    path = cpu_context.read_data(name_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING)
    path = path.decode("utf-16-le" if wide else "utf8")

    create_disposition = func_args[4]
    if create_disposition in [wc.CREATE_NEW, wc.CREATE_ALWAYS]:
        logger.debug("Created file: %s", path)
        cpu_context.actions.append(actions.FileCreated(cpu_context.ip, path))
    elif create_disposition in [wc.OPEN_EXISTING, wc.OPEN_ALWAYS]:
        logger.debug("Opened file: %s", path)
        cpu_context.actions.append(actions.FileOpened(cpu_context.ip, path))
    elif create_disposition == wc.TRUNCATE_EXISTING:
        logger.debug("Truncated file: %s", path)
        cpu_context.actions.append(actions.FileTruncated(cpu_context.ip, path))

    mode = ""
    desired_access = func_args[1]
    if desired_access & wc.GENERIC_READ:
        mode += "r"
    if desired_access & wc.GENERIC_WRITE:
        mode += "w"

    file = cpu_context.open_file(path, mode=mode)
    file.add_reference(cpu_context.ip)
    return file.handle


@builtin_func("WriteFile")
#typespec("BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)")
def write_file(cpu_context, func_name, func_args):
    """
    Writes data to the specified file.
    """
    handle = func_args[0]
    data_ptr = func_args[1]
    num_bytes_to_write = func_args[2]
    bytes_written_ptr = func_args[3]

    file = cpu_context.get_file(handle)
    if not file:
        logger.warning("File handle 0x%x was never opened.", handle)
        return 1

    logger.debug("Writing %d bytes to file %s", num_bytes_to_write, file.path)
    data = cpu_context.mem_read(data_ptr, num_bytes_to_write)
    file.write(data)
    file.add_reference(cpu_context.ip)

    if bytes_written_ptr:
        cpu_context.write_data(bytes_written_ptr, len(data), data_type=constants.DWORD)

    return 1  # return success


@builtin_func("MoveFileA")
@builtin_func("MoveFileExA")
def move_file(cpu_context, func_name, func_args):
    """
    Moves an existing file (or directory) to new location.
    """
    old_name_ptr, new_name_ptr, *_ = func_args
    old_path = cpu_context.read_data(old_name_ptr).decode("utf8")
    new_path = cpu_context.read_data(new_name_ptr).decode("utf8")
    logger.debug("Moving file: %s -> %s", old_path, new_path)
    cpu_context.actions.append(actions.FileMoved(cpu_context.ip, old_path, new_path))

    # Retreive file and then change it's name.
    # If file was never opened previously, open the file temporarily.
    file = cpu_context.get_file(old_path)
    if file:
        file.path = new_path
    else:
        file = cpu_context.open_file(old_path)
        file.path = new_path
        file.close()
    file.add_reference(cpu_context.ip)

    return 1  # return success


@builtin_func("CloseHandle")
#typespec("BOOL __stdcall CloseHandle(HANDLE hObject)")
def close_file(cpu_context, func_name, func_args):
    """
    Closes an open object handle.
    """
    handle = func_args[0]
    file = cpu_context.get_file(handle)
    if file:
        logger.debug("Closing file: %s", file.path)
        file.close()
    file.add_reference(cpu_context.ip)

    return 1  # return success


@builtin_func("DeleteFileA")
@builtin_func("DeleteFileW")
#typespec("BOOL DeleteFileA(char* lpFileName);")
#typespec("BOOL DeleteFileW(wchar* lpFileName);")
def delete_file(cpu_context, func_name, func_args):
    """
    Deletes an existing file.
    """
    wide = func_name.endswith("W")
    path_ptr = func_args[0]
    path = cpu_context.read_data(path_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING)
    path = path.decode("utf16le" if wide else "utf8")
    logger.debug("Deleting: %s", path)
    cpu_context.actions.append(actions.FileDeleted(cpu_context.ip, path))

    file = cpu_context.get_file(path)
    if file:
        file.delete()
    else:
        file = cpu_context.open_file(path)
        file.close()
        file.delete()
    file.add_reference(cpu_context.ip)

    return 1  # return success


@builtin_func("CreateMutexA")
@builtin_func("CreateMutexW")
@builtin_func("CreateMutexExA")
@builtin_func("CreateMutexExW")
#typespec("HANDLE CreateMutexA(SECURITY_ATTRIBUTES* lpMutexAttributes, BOOL bInitialOwner, char* lpName);")
#typespec("HANDLE CreateMutexW(SECURITY_ATTRIBUTES* lpMutexAttributes, BOOL bInitialOwner, wchar* lpName);")
#typespec("HANDLE CreateMutexExA(SECURITY_ATTRIBUTES* lpMutexAttributes, char* lpName, DWROD dwFlags, DWORD dwDesiredAccess);")
#typespec("HANDLE CreateMutexExW(SECURITY_ATTRIBUTES* lpMutexAttributes, wchar* lpName, DWORD dwFlags, DWORD dwDesiredAccess);")
def create_mutex(cpu_context, func_name, func_args):
    """
    Creates or opens a named or unnamed mutex object and returns a handle to the object.
    """
    # TODO: Create high level Mutex object.
    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


@builtin_func("CreateEventA")
@builtin_func("CreateEventW")
@builtin_func("CreateEventExA")
@builtin_func("CreateEventEXW")
#typespec("HANDLE CreateEventA(SECURTIY_ATTRIBUTES* lpEventAttributes, BOOL bManualReset, BOOL bInitialState, char* lpName);")
#typespec("HANDLE CreateEventW(SECURTIY_ATTRIBUTES* lpEventAttributes, BOOL bManualReset, BOOL bInitialState, wchar* lpName);")
#typespec("HANDLE CreateEventExA(SECURITY_ATTRIBUTES* lpEventAttributes, char* lpName, DWORD dwFlags, DWORD dwDesiredAccess);")
#typespec("HANDLE CreateEventExW(SECURITY_ATTRIBUTES* lpEventAttributes, wchar* lpName, DWORD dwFlags, DWORD dwDesiredAccess);")
def create_event(cpu_context, func_name, func_args):
    """
    Creates or opens a named or unnamed event object and returns a handle to the object.
    """
    # TODO: Create high level Event object.
    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)


@builtin_func("CreateSemaphoreA")
@builtin_func("CreateSemaphoreW")
@builtin_func("CreateSemaphoreExA")
@builtin_func("CreateSemaphoreExW")
#typespec("HANDLE CreateSemaphoreA(SECURITY_ATTRIBUTES* lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, char* lpName);")
#typespec("HANDLE CreateSemaphoreW(SECURITY_ATTRIBUTES* lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, wchar* lpName);")
#typespec("HANDLE CreateSemaphoreExA(SECURITY_ATTRIBUTES* lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, char* lpName, DWORD dwFlags, DWORD dwDesiredAccess);")
#typespec("HANDLE CreateSemaphoreExW(SECURITY_ATTRIBUTES* lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, wchar* lpName, DWORD dwFlags, DWORD dwDesiredAccess);")
def create_semaphore(cpu_context, func_name, func_args):
    """
    Creates or opens a named or unnamed semaphore object and returns a handle to the object.
    """
    return random.randint(wc.MIN_HANDLE, wc.MAX_HANDLE)
