"""
Tests the CLI tools.
"""

from __future__ import print_function

import json
import sys



def test_parse(tmpdir, script_runner, strings_exe):
    """Test running a decoder"""
    # Change working directory so we can cleanup outputted files.
    cwd = str(tmpdir)

    # Run the foo parser on the test input file.
    ret = script_runner.run('kordesii', 'parse', 'Sample', strings_exe, '-t', '0', cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert ret.stdout == \
'''\
----Decoded Strings----

Hello World!
Test string with key 0x02
The quick brown fox jumps over the lazy dog.
Oak is strong and also gives shade.
Acid burns holes in wool cloth.
Cats and dogs each hate the other.
Open the crate but don't break the glass.
There the flood mark is ten inches.
1234567890
CreateProcessA
StrCat
ASP.NET
kdjsfjf0j24r0j240r2j09j222
32897412389471982470
The past will look brighter tomorrow.
Cars and busses stalled in sand drifts.
The jacket hung on the back of the wide chair.
32908741328907498134712304814879837483274809123748913251236598123056231895712

----Debug----

[+] Found XOR encrypt function at: 0x401000
[+] IDA return code = 0

'''

    # Test the json formating
    ret = script_runner.run('kordesii', 'parse', '--json', 'Sample', strings_exe, '-t', '0', cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert json.loads(ret.stdout) == [
        {
            "debug": [
                "[+] Found XOR encrypt function at: 0x401000",
                "[+] IDA return code = 0"
            ],
            "strings": [
                "Hello World!",
                "Test string with key 0x02",
                "The quick brown fox jumps over the lazy dog.",
                "Oak is strong and also gives shade.",
                "Acid burns holes in wool cloth.",
                "Cats and dogs each hate the other.",
                "Open the crate but don't break the glass.",
                "There the flood mark is ten inches.",
                "1234567890",
                "CreateProcessA",
                "StrCat",
                "ASP.NET",
                "kdjsfjf0j24r0j240r2j09j222",
                "32897412389471982470",
                "The past will look brighter tomorrow.",
                "Cars and busses stalled in sand drifts.",
                "The jacket hung on the back of the wide chair.",
                "32908741328907498134712304814879837483274809123748913251236598123056231895712"
            ]
        }
    ]
