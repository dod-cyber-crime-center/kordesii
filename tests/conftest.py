
import os

import pytest

import kordesii.decoders


@pytest.fixture
def strings_exe(tmpdir):
    """Creates and returns a copy of the strings.exe file in a temporary directory."""
    orig_path = os.path.join(os.path.dirname(kordesii.decoders.__file__), 'tests', 'strings.exe')
    new_path = os.path.join(str(tmpdir), 'strings.exe')
    with open(orig_path, 'rb') as orig_file:
        with open(new_path, 'wb') as new_file:
            new_file.write(orig_file.read())
    return new_path


@pytest.fixture
def Sample_decoder(tmpdir):
    """Creates and returns the Sample decoder stored in a temporary directory."""
    orig_path = os.path.join(os.path.dirname(kordesii.decoders.__file__), 'Sample.py')
    new_path = os.path.join(str(tmpdir), 'Sample.py')
    with open(orig_path, 'rb') as orig_file:
        with open(new_path, 'wb') as new_file:
            new_file.write(orig_file.read())
    return new_path
