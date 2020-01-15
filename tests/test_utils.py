"""
Tests utility functions.
"""

import pytest


@pytest.mark.in_ida
def test_iter_functions():
    from kordesii.utils import utils

    assert list(utils.iter_exports()) == [(0x4014e0, 'start')]
    assert list(utils.iter_imports()) == [
        (0x40a000, 'GetCommandLineA', 'KERNEL32'),
        (0x40a004, 'EnterCriticalSection', 'KERNEL32'),
        (0x40a008, 'LeaveCriticalSection', 'KERNEL32'),
        (0x40a00c, 'TerminateProcess', 'KERNEL32'),
        (0x40a010, 'GetCurrentProcess', 'KERNEL32'),
        (0x40a014, 'UnhandledExceptionFilter', 'KERNEL32'),
        (0x40a018, 'SetUnhandledExceptionFilter', 'KERNEL32'),
        (0x40a01c, 'IsDebuggerPresent', 'KERNEL32'),
        (0x40a020, 'GetModuleHandleW', 'KERNEL32'),
        (0x40a024, 'Sleep', 'KERNEL32'),
        (0x40a028, 'GetProcAddress', 'KERNEL32'),
        (0x40a02c, 'ExitProcess', 'KERNEL32'),
        (0x40a030, 'WriteFile', 'KERNEL32'),
        (0x40a034, 'GetStdHandle', 'KERNEL32'),
        (0x40a038, 'GetModuleFileNameA', 'KERNEL32'),
        (0x40a03c, 'FreeEnvironmentStringsA', 'KERNEL32'),
        (0x40a040, 'GetEnvironmentStrings', 'KERNEL32'),
        (0x40a044, 'FreeEnvironmentStringsW', 'KERNEL32'),
        (0x40a048, 'WideCharToMultiByte', 'KERNEL32'),
        (0x40a04c, 'GetLastError', 'KERNEL32'),
        (0x40a050, 'GetEnvironmentStringsW', 'KERNEL32'),
        (0x40a054, 'SetHandleCount', 'KERNEL32'),
        (0x40a058, 'GetFileType', 'KERNEL32'),
        (0x40a05c, 'GetStartupInfoA', 'KERNEL32'),
        (0x40a060, 'DeleteCriticalSection', 'KERNEL32'),
        (0x40a064, 'TlsGetValue', 'KERNEL32'),
        (0x40a068, 'TlsAlloc', 'KERNEL32'),
        (0x40a06c, 'TlsSetValue', 'KERNEL32'),
        (0x40a070, 'TlsFree', 'KERNEL32'),
        (0x40a074, 'InterlockedIncrement', 'KERNEL32'),
        (0x40a078, 'SetLastError', 'KERNEL32'),
        (0x40a07c, 'GetCurrentThreadId', 'KERNEL32'),
        (0x40a080, 'InterlockedDecrement', 'KERNEL32'),
        (0x40a084, 'HeapCreate', 'KERNEL32'),
        (0x40a088, 'VirtualFree', 'KERNEL32'),
        (0x40a08c, 'HeapFree', 'KERNEL32'),
        (0x40a090, 'QueryPerformanceCounter', 'KERNEL32'),
        (0x40a094, 'GetTickCount', 'KERNEL32'),
        (0x40a098, 'GetCurrentProcessId', 'KERNEL32'),
        (0x40a09c, 'GetSystemTimeAsFileTime', 'KERNEL32'),
        (0x40a0a0, 'GetCPInfo', 'KERNEL32'),
        (0x40a0a4, 'GetACP', 'KERNEL32'),
        (0x40a0a8, 'GetOEMCP', 'KERNEL32'),
        (0x40a0ac, 'IsValidCodePage', 'KERNEL32'),
        (0x409b0e, 'RtlUnwind', 'KERNEL32'),
        (0x40a0b0, 'RtlUnwind', 'KERNEL32'),
        (0x40a0b4, 'LoadLibraryA', 'KERNEL32'),
        (0x40a0b8, 'InitializeCriticalSectionAndSpinCount', 'KERNEL32'),
        (0x40a0bc, 'HeapAlloc', 'KERNEL32'),
        (0x40a0c0, 'VirtualAlloc', 'KERNEL32'),
        (0x40a0c4, 'HeapReAlloc', 'KERNEL32'),
        (0x40a0c8, 'GetConsoleCP', 'KERNEL32'),
        (0x40a0cc, 'GetConsoleMode', 'KERNEL32'),
        (0x40a0d0, 'FlushFileBuffers', 'KERNEL32'),
        (0x40a0d4, 'LCMapStringA', 'KERNEL32'),
        (0x40a0d8, 'MultiByteToWideChar', 'KERNEL32'),
        (0x40a0dc, 'LCMapStringW', 'KERNEL32'),
        (0x40a0e0, 'GetStringTypeA', 'KERNEL32'),
        (0x40a0e4, 'GetStringTypeW', 'KERNEL32'),
        (0x40a0e8, 'GetLocaleInfoA', 'KERNEL32'),
        (0x40a0ec, 'SetFilePointer', 'KERNEL32'),
        (0x40a0f0, 'HeapSize', 'KERNEL32'),
        (0x40a0f4, 'CloseHandle', 'KERNEL32'),
        (0x40a0f8, 'WriteConsoleA', 'KERNEL32'),
        (0x40a0fc, 'GetConsoleOutputCP', 'KERNEL32'),
        (0x40a100, 'WriteConsoleW', 'KERNEL32'),
        (0x40a104, 'SetStdHandle', 'KERNEL32'),
        (0x40a108, 'CreateFileA', 'KERNEL32')
    ]
    assert list(utils.iter_functions('GetProcAddress')) == [(0x40a028, 'GetProcAddress')]
    assert list(utils.iter_functions('memcpy')) == [(0x405c00, '_memcpy'), (0x408d50, '_memcpy_0')]
    assert list(utils.iter_functions('_memcpy')) == [(0x405c00, '_memcpy'), (0x408d50, '_memcpy_0')]
    assert list(utils.iter_functions('_memcpy_0')) == [(0x408d50, '_memcpy_0')]
