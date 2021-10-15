"""
Stub used to run tests within IDA.
"""

import pytest

import kordesii

if __name__ == "__main__" and kordesii.in_ida:
    import idc

    idc.auto_wait()
    print(idc.get_input_file_path())
    print(idc.ARGV)

    args = idc.ARGV[1:]
    print("Running: pytest {}".format(" ".join(args)))
    idc.qexit(pytest.main(args))
