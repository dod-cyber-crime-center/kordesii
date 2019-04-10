
import os
import shutil

import pytest

import kordesii.decoders


@pytest.fixture
def strings_exe(tmpdir):
    """Creates and returns a copy of the strings.exe file in a temporary directory."""
    orig_path = os.path.join(os.path.dirname(kordesii.decoders.__file__), 'tests', 'strings.exe')
    new_path = tmpdir / 'strings.exe'
    shutil.copy(orig_path, str(new_path))
    return new_path


@pytest.fixture
def Sample_decoder(tmpdir):
    """Creates and returns the Sample decoder stored in a temporary directory."""
    orig_path = os.path.join(os.path.dirname(kordesii.decoders.__file__), 'Sample.py')
    new_path = tmpdir / 'Sample.py'
    shutil.copy(orig_path, str(new_path))
    return new_path
