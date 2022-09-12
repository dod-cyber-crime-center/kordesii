"""
Tests function_tracing's memory emulation.
"""

import os
from textwrap import dedent

import pytest


@pytest.mark.in_ida
def test_memory():
    """Tests the memory controller."""
    from kordesii.utils.function_tracing.memory import Memory

    m = Memory()

    # basic test
    assert m.read(0x00121000, 10) == b"\x00" * 10

    # test reading across pages
    m.write(0x00121FFB, b"helloworld")
    assert m.read(0x00121FFB, 10) == b"helloworld"
    assert m.read(0x00121FFB + 10, 10) == b"\x00" * 10
    assert m.read(0x00121FFB + 5, 10) == b"world" + b"\x00" * 5

    # test reading segment data
    assert m.read(0x0040C000, 11) == b"Idmmn!Vnsme"
    assert m.read(0x00401150, 3) == b"\x55\x8B\xEC"

    # test str print
    assert str(m) == dedent(
        """\
        Base Address             Address Range            Size
        0x00121000               0x00121000 - 0x00123000  8192
        0x00401000               0x00401000 - 0x0040F000  57344
    """
    )

    # test searching
    assert m.find(b"helloworld", start=0x0011050) == 0x00121FFB
    assert m.find(b"helloworld") == 0x00121FFB
    assert m.find(b"helloworld", start=0x00121FFC) == -1
    assert m.find(b"helloworld", end=0x10) == -1
    assert m.find(b"helloworld", start=0x0011050, end=0x00121FFB) == -1
    assert m.find(b"helloworld", start=0x0011050, end=0x00122000) == -1
    assert m.find(b"helloworld", start=0x0011050, end=0x00122100) == 0x00121FFB
    assert m.find(b"`QFBWF") == 0x0040C120
    assert m.find(b"Idmmn!Vnsme") == 0x0040C000
    assert m.find_in_segment(b"Idmmn!Vnsme", ".data") == 0x0040C000
    assert m.find_in_segment(b"Idmmn!Vnsme", ".text") == -1
    assert m.find(b"\x5F\x5E\xC3", start=0x004035BD) == 0x004035E0

    # test bugfix when searching single length characters
    assert m.find(b"h", start=0x0011050) == 0x00121FFB
    assert m.find(b"h", start=0x0011050, end=0x00121FFB) == -1
    assert m.find(b"h", start=0x0011050, end=0x00121FFB + 1) == 0x00121FFB
    assert m.find(b"o", start=0x0011050) == 0x00121FFB + 4

    # tests allocations
    first_alloc_ea = m.alloc(10)
    assert first_alloc_ea == m.HEAP_BASE
    second_alloc_ea = m.alloc(20)
    assert second_alloc_ea == m.HEAP_BASE + 10 + m.HEAP_SLACK
    m.write(second_alloc_ea, b"im in the heap!")
    assert m.read(second_alloc_ea, 15) == b"im in the heap!"
    assert m.find_in_heap(b"the heap!") == second_alloc_ea + 6
    m.write(second_alloc_ea, b"helloworld")
    assert m.find_in_heap(b"helloworld") == second_alloc_ea

    # tests reallocations
    assert m.realloc(first_alloc_ea, 40) == first_alloc_ea  # no relocation
    assert m.realloc(first_alloc_ea, m.PAGE_SIZE * 5) == second_alloc_ea + 20 + m.HEAP_SLACK  # relocation
    assert m.realloc(second_alloc_ea, 40) == second_alloc_ea  # no relocation
    second_alloc_realloced_ea = m.realloc(second_alloc_ea, m.PAGE_SIZE * 6)
    assert second_alloc_realloced_ea != second_alloc_ea
    assert m.read(second_alloc_realloced_ea, 10) == b"helloworld"  # data should be copied over.


@pytest.mark.in_ida
def test_streaming():
    """
    Tests creating a file-like stream for emulated memory.
    """
    from kordesii.utils import function_tracing
    emulator = function_tracing.Emulator()
    context = emulator.new_context()

    with context.memory.open() as stream:
        assert stream.tell() == 0
        assert stream.tell_address() == 0x401000

        stream.seek_address(0x40C000)
        assert stream.read(11) == b"Idmmn!Vnsme"

        data = stream.read()
        assert len(data) == 12277  # length of data is larger than in rugosa due to lack of stripping uninitialized data.
        assert data.startswith(b' \x00\x00\x00\x00Vgqv"qvpkle"ukvj"ig{')

    with context.memory.open(0x40C000) as stream:
        assert stream.read(11) == b"Idmmn!Vnsme"
        assert stream.write(b"hello") == 5
        assert stream.tell() == 16
        assert stream.seek(-5, os.SEEK_CUR) == 11
        assert context.memory.read(0x40C000 + 11, 5) == b"hello"
        assert stream.read(5) == b"hello"
