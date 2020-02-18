"""
Tests for bug fixes reported on GitHub.
"""

import pytest


@pytest.mark.in_ida
def test_issue_7():
    """Tests the use of WIDE_STRING for read_data()"""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing.cpu_context import ProcessorContext

    context = ProcessorContext.from_arch()

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
    from kordesii.utils.function_tracing import builtin_funcs

    # Test with known builtin func
    assert builtin_funcs.get("lstrcpya") == builtin_funcs.strcpy
    assert builtin_funcs.get("lStrcpyA") == builtin_funcs.strcpy
    assert builtin_funcs.get("lstrcpyA") == builtin_funcs.strcpy

    def dummy(ctx, func_name, func_args):
        return

    # Test user defined with global tracer cache
    function_tracing.hook_tracers("SuperFunc", dummy)
    tracer = function_tracing.get_tracer(0x00401058)
    assert builtin_funcs.get("SuperFunc") is None
    assert builtin_funcs.get("SUPERfunc") is None
    assert builtin_funcs.get("superfunc") is None
    with builtin_funcs.hooks(tracer._hooks):
        assert builtin_funcs.get("SuperFunc") == dummy
        assert builtin_funcs.get("SUPERfunc") == dummy
        assert builtin_funcs.get("superfunc") == dummy

    # Test user defined with local tracer
    tracer = function_tracing.FunctionTracer(0x00401058)
    tracer.hook("SuperFunc", dummy)
    assert builtin_funcs.get("SuperFunc") is None
    assert builtin_funcs.get("SUPERfunc") is None
    assert builtin_funcs.get("superfunc") is None
    with builtin_funcs.hooks(tracer._hooks):
        assert builtin_funcs.get("SuperFunc") == dummy
        assert builtin_funcs.get("SUPERfunc") == dummy
        assert builtin_funcs.get("superfunc") == dummy
