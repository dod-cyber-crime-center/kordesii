"""
Tests serializer.
"""

import pytest

from kordesii import serialization


@serialization.serializable_class
class DummyObject(object):
    a = "a"
    b = "b"

    def __init__(self, c):
        self.c = c


expected_serialized = u"""\
entry_1: !!binary |
  c29tZSBkYXRh
entry_2: !ReadOnlyObject
  __yaml_name__: DummyObject
  a: a
  b: b
  c: c
entry_3:
- 1
- 2
- 3
"""


def test_Serializer(tmpdir):
    """Tests Serializer class"""
    yaml_file = tmpdir / "test.yml"
    dummy_object = DummyObject("c")

    with serialization.Serializer(str(yaml_file)) as serializer:
        assert not yaml_file.exists()

        serializer.set("entry_1", b"some data")
        serializer.set("entry_2", dummy_object)
        serializer.set("entry_3", [1, 2, 3])
        with pytest.raises(ValueError):
            # We can't reuse an already set attribute.
            serializer.set("entry_2", b"boop")

        assert yaml_file.exists()
        assert serializer.get("entry_1") == b"some data"
    # Must close manually because of hack needed to keep it global.
    serializer.close()

    # Test that our entry has been serialized.
    assert yaml_file.read_text("utf8") == expected_serialized


def test_deserialize(tmpdir):
    """Tests deserialization."""
    yaml_file = tmpdir / "test.yml"
    yaml_file.write_text(expected_serialized, "utf8")

    # Test deserialization by setting up a Serializer object as
    # well as using the deserialize() function.
    results = [
        serialization.deserialize(expected_serialized),
        # NOTE: this method doesn't work for now.
        # serialization.Serializer(str(yaml_file)).as_dict(),
    ]
    for result in results:
        assert result["entry_1"] == b"some data"
        assert result["entry_3"] == [1, 2, 3]
        dummy_object = result["entry_2"]
        assert isinstance(dummy_object, serialization.ROObject)
        assert dummy_object.a == "a"
        assert dummy_object.b == "b"
        assert dummy_object.c == "c"
