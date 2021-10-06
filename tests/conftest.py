
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import kordesii
import kordesii.decoders


DECODERS_PATH = pathlib.Path(kordesii.decoders.__file__).parent


@pytest.fixture
def strings_exe(tmpdir):
    """Creates and returns a copy of the strings.exe file in a temporary directory."""
    orig_path = DECODERS_PATH / "tests" / "strings.exe"
    new_path = tmpdir / "strings.exe"
    shutil.copy(str(orig_path), str(new_path))
    return new_path


@pytest.fixture
def strings_arm(tmpdir):
    """Creates and returns a copy of the strings_arm file in a temporary directory."""
    orig_path = DECODERS_PATH / "tests" / "strings_arm"
    new_path = tmpdir / "strings_arm"
    shutil.copy(str(orig_path), str(new_path))
    return new_path


@pytest.fixture
def Sample_decoder(tmpdir):
    """Creates and returns the Sample decoder stored in a temporary directory."""
    orig_path = os.path.join(os.path.dirname(kordesii.decoders.__file__), "Sample.py")
    new_path = tmpdir / "Sample.py"
    shutil.copy(orig_path, str(new_path))
    return new_path


def pytest_configure(config):
    # register in_ida marker
    config.addinivalue_line("markers", "marks tests to be run within IDA")


def pytest_generate_tests(metafunc):
    """Sets up parametrization of the run_in_ida fixture to pass in appropriate strings_* fixture."""
    item = metafunc.definition
    x86_marker = bool(list(item.iter_markers(name="in_ida")) + list(item.iter_markers(name="in_ida_x86")))
    arm_marker = bool(list(item.iter_markers(name="in_ida_arm")))

    params = []
    if x86_marker:
        params.append(pytest.param("strings_exe", id="x86"))
    if arm_marker:
        params.append(pytest.param("strings_arm", id="arm"))

    if params:
        metafunc.parametrize("run_in_ida", params, indirect=True)


@pytest.fixture(autouse=True)
def run_in_ida(request):
    """Runs unit tests marked to be run within IDA."""
    # Ignore if no params are set. This means either we are already in IDA or it is not a marked test.
    if not hasattr(request, "param"):
        return

    # Ignore if we are already in IDA.
    if kordesii.in_ida:
        return

    item = request.node

    # Otherwise, pass along the in_ida test to be run within the strings.exe or strings_arm idb.

    test_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    test_path = os.path.join(test_path, item.nodeid)

    # Pull appropriate input file path by executing the fixture passed into parameter.
    input_path = request.getfixturevalue(request.param)

    # Remove repeated nodeid if in command line already.
    cli_args = sys.argv[1:]
    for arg in cli_args[:]:
        if "::" in arg:
            cli_args.remove(arg)

    pytest_args = " ".join(['"{}"'.format(test_path)] + cli_args)

    # TODO: Use a premade IDB?
    log_file_path = pathlib.Path(input_path).parent / (input_path.basename + ".log")
    ida_stub = pathlib.Path(__file__).parent / "ida_stub.py"
    assert ida_stub.exists()
    command = [
        kordesii.find_ida(),
        "-P",
        "-A",
        f'-S""{ida_stub}" {pytest_args}"',
        f'-L"{log_file_path}"',
        f'"{input_path}"',
    ]
    command = " ".join(command)  # doesn't work unless we convert to a string!
    print("Running IDA with command: {}".format(command))

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=sys.platform != "win32")

    stdout, stderr = process.communicate()
    print(stdout)
    print(stderr, file=sys.stderr)

    if log_file_path.exists():
        print(log_file_path.read_text())

    assert process.returncode == 0

    # Now skip the original so we don't try to actually run the code outside of IDA.
    # NOTE: We just have to know that a skipped test that was marked as
    #   "in_ida" means it passed successfully.
    #   My pytest-fu is not strong enough to figure out how to make it say it passed.
    pytest.skip("Test ran successfully in IDA!")
