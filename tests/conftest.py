
import os
import shutil
import subprocess
import sys

import pytest

import kordesii
import kordesii.decoders


@pytest.fixture
def strings_exe(tmpdir):
    """Creates and returns a copy of the strings.exe file in a temporary directory."""
    orig_path = os.path.join(os.path.dirname(kordesii.decoders.__file__), "tests", "strings.exe")
    new_path = tmpdir / "strings.exe"
    shutil.copy(orig_path, str(new_path))
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


@pytest.fixture(autouse=True)
def run_in_ida(request, tmpdir, strings_exe):
    """Runs unit tests marked to be run within IDA."""
    item = request.node
    in_ida_marker = bool(list(item.iter_markers(name="in_ida")))

    # Allow in_ida tests to be run if in IDA.
    if kordesii.in_ida:
        if not in_ida_marker:
            pytest.skip("Test to be run outside of IDA.")
        return

    # Allow non-in_ida tests to run if not in IDA.
    if not in_ida_marker:
        return

    # Otherwise, pass along the in_ida test to be run within the strings.exe idb.

    log_file_path = tmpdir / "ida.log"
    test_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    test_path = os.path.join(test_path, item.nodeid)

    # Remove repeated nodeid if in command line already.
    cli_args = sys.argv[1:]
    for arg in cli_args[:]:
        if "::" in arg:
            cli_args.remove(arg)

    pytest_args = " ".join(['"{}"'.format(test_path)] + cli_args)

    # TODO: Use a premade IDB?
    command = [
        kordesii.find_ida(),
        "-P",
        "-A",
        '-S""{script_path}" {pytest_args}"'.format(
            script_path=os.path.join(os.path.dirname(__file__), "ida_stub.py"), pytest_args=pytest_args
        ),
        '-L"{}"'.format(str(log_file_path)),
        '"{}"'.format(str(strings_exe)),
    ]
    command = " ".join(command)  # doesn't work unless we convert to a string!
    print("Running IDA with command: {}".format(command))

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=sys.platform != "win32")

    stdout, stderr = process.communicate()
    print(stdout)
    print(stderr, file=sys.stderr)

    if log_file_path.exists():
        print(log_file_path.read())

    assert process.returncode == 0

    # Now skip the original so we don't try to actually run the code outside of IDA.
    # NOTE: We just have to know that a skipped test that was marked as
    #   "in_ida" means it passed successfully.
    #   My pytest-fu is not strong enough to figure out how to make it say it passed.
    pytest.skip("Test ran successfully in IDA!")
