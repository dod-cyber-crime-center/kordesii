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

    wide_string = b'/\x00f\x00a\x00v\x00.\x00i\x00c\x00o\x00'
    context.memory.write(0x123000, wide_string)
    assert context.read_data(0x123000, data_type=function_tracing.WIDE_STRING) == wide_string
    wide_string = b'\x00/\x00f\x00a\x00v\x00.\x00i\x00c\x00o'
    context.memory.write(0x123000, wide_string)
    assert context.read_data(0x123000, data_type=function_tracing.WIDE_STRING) == wide_string
