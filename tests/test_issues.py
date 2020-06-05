"""
Tests for bug fixes reported on GitHub.
"""

import pytest


@pytest.mark.in_ida
def test_issue_7():
    """Tests the use of WIDE_STRING for read_data()"""
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()
    context = emulator.new_context()

    wide_string = b"/\x00f\x00a\x00v\x00.\x00i\x00c\x00o\x00"
    context.memory.write(0x123000, wide_string)
    assert context.read_data(0x123000, data_type=function_tracing.WIDE_STRING) == wide_string
    wide_string = b"\x00/\x00f\x00a\x00v\x00.\x00i\x00c\x00o"
    context.memory.write(0x123000, wide_string)
    assert context.read_data(0x123000, data_type=function_tracing.WIDE_STRING) == wide_string


@pytest.mark.in_ida
def test_function_case_senstivity():
    """Tests issue with case sensitivity when hooking functions."""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing.call_hooks import stdlib

    emulator = function_tracing.Emulator()

    # Test with known builtin func
    assert emulator.get_call_hook("lstrcpya") == stdlib.builtin_funcs.strcpy
    assert emulator.get_call_hook("lStrcpyA") == stdlib.builtin_funcs.strcpy
    assert emulator.get_call_hook("lstrcpyA") == stdlib.builtin_funcs.strcpy

    # Test user defined
    def dummy(ctx, func_name, func_args):
        return

    assert emulator.get_call_hook("SuperFunc") is None
    assert emulator.get_call_hook("SUPERfunc") is None
    assert emulator.get_call_hook("superfunc") is None
    emulator.hook_call("SuperFunc", dummy)
    assert emulator.get_call_hook("SuperFunc") == dummy
    assert emulator.get_call_hook("SUPERfunc") == dummy
    assert emulator.get_call_hook("superfunc") == dummy
