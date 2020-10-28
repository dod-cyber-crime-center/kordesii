
import pytest


@pytest.mark.in_ida
def test_find_string_data():
    from kordesii.utils import find_string_data

    # General test of mixture of utf-8 and utf-16
    data = b"h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00test\x00\x00\x00joe\x00\x00w\x00o\x00r\x00l\x00d"
    assert list(find_string_data(data)) == [
        (0, b"h\x00e\x00l\x00l\x00o\x00\x00\x00", "utf-16-le"),
        (14, b"test\x00", "utf-8"),
        (21, b"joe\x00", "utf-8"),
        (25, b"\x00w\x00o\x00r\x00l\x00d", "utf-16-be"),
    ]

    # Test arbitrary number of null bytes in between strings.
    data = b"\x00\x00\x00hello\x00\x00\x00\x00\x00\x00w\x00o\x00r\x00l\x00d\x00\x00\x00\x00\x00\x00"
    assert list(find_string_data(data)) == [
        (3, b"hello\x00", "utf-8"),
        (14, b"w\x00o\x00r\x00l\x00d\x00\x00\x00", "utf-16-le"),
    ]

    # Test falling back on single character strings.
    data = b"1\x000\x00\x00\x00hello\x00world\x00"
    assert list(find_string_data(data)) == [
        (0, b"1\x000\x00\x00\x00", "utf-16-le"),
        (6, b"hello\x00", "utf-8"),
        (12, b"world\x00", "utf-8"),
    ]
    data = b"1\x000\x00hello\x00world\x00"
    assert list(find_string_data(data)) == [
        (0, b"1\x00", "utf-8"),
        (2, b"0\x00", "utf-8"),
        (4, b"hello\x00", "utf-8"),
        (10, b"world\x00", "utf-8"),
    ]
