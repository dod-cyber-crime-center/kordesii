"""
Stub used to run tests within IDA.
"""

import pytest
import sys

import kordesii


if __name__ == '__main__' and kordesii.in_ida:
    import idc

    idc.auto_wait()
    print(idc.ARGV)

    args = ['-m', 'in_ida'] + idc.ARGV[1:]
    print('Running: pytest {}'.format(' '.join(args)))
    idc.qexit(pytest.main(args))
