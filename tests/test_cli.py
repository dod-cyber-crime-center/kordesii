"""
Tests the CLI tools.
"""

import hashlib
import json
import sys

import pytest

from kordesii import cli


def test_get_malware_repo_path(tmpdir, strings_exe):
    """Tests generating malware repo path."""
    malware_repo = tmpdir.mkdir("malware_repo")
    sample_path = cli._get_malware_repo_path(str(strings_exe), str(malware_repo))
    assert sample_path == str(malware_repo / "e1b6" / "e1b6be6c0c2db8b3d4dca56062ca6301")


def test_add_to_malware_repo(tmpdir, strings_exe):
    """Tests adding a file to the malware repo."""
    malware_repo = tmpdir.mkdir("malware_repo")
    sample_path = cli._add_to_malware_repo(str(strings_exe), str(malware_repo))
    expected_sample_path = malware_repo / "e1b6" / "e1b6be6c0c2db8b3d4dca56062ca6301"
    assert sample_path == str(expected_sample_path)
    assert expected_sample_path.exists()
    assert expected_sample_path.read_binary() == strings_exe.read_binary()


def test_list(tmpdir, script_runner, Sample_decoder):
    """
    Tests displaying a list of decoders.

    (This is also where we test the decoder registration flags.)
    """
    # First ensure our Sample decoder is registered via entry_points.
    ret = script_runner.run("kordesii", "list", "--json")
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    results = json.loads(ret.stdout)
    assert len(results) > 1
    for name, source_name, author, description in results:
        if name == u"Sample":
            assert source_name == u"kordesii"
            assert author == u"DC3"
            assert description == u"Sample decoder"
            break
    else:
        pytest.fail("Sample decoder was not listed.")

    # Now try adding a decoder using the --decoder-dir flag.
    decoder_dir = Sample_decoder.dirname
    ret = script_runner.run("kordesii", "--decoder-dir", str(decoder_dir), "list", "--json")
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    results = json.loads(ret.stdout)
    assert len(results) > 1
    for name, source_name, author, description in results:
        if source_name == str(decoder_dir):
            assert name == u"Sample"
            assert author == u"DC3"
            assert description == u"Sample decoder"
            break
    else:
        pytest.fail("Sample decoder from decoder directory was not listed.")

    # If we set --decoder-source we should only get our registered decoder from the directory.
    decoder_dir = Sample_decoder.dirname
    ret = script_runner.run(
        "kordesii", "--decoder-dir", str(decoder_dir), "--decoder-source", str(decoder_dir), "list", "--json"
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    results = json.loads(ret.stdout)
    assert results == [[u"Sample", str(decoder_dir), u"DC3", u"Sample decoder"]]


def test_parse(tmpdir, script_runner, strings_exe):
    """Test running a decoder"""
    # Change working directory so we can cleanup outputted files.
    cwd = str(tmpdir)

    # Run the foo parser on the test input file.
    ret = script_runner.run("kordesii", "parse", "Sample", str(strings_exe), "-t", "0", cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert (
        ret.stdout
        == """\
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

"""
    )

    # Test the json formating
    ret = script_runner.run("kordesii", "parse", "--json", "Sample", str(strings_exe), "-t", "0", cwd=cwd)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success
    assert json.loads(ret.stdout) == [
        {
            "debug": ["[+] Found XOR encrypt function at: 0x401000", "[+] IDA return code = 0"],
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
                "32908741328907498134712304814879837483274809123748913251236598123056231895712",
            ],
        }
    ]


def test_add_testcase(tmpdir, script_runner, strings_exe):
    """Tests adding a decoder testcase."""
    # Create a dummy malware repo
    malware_repo = tmpdir.mkdir("malware_repo")

    # Create a dummy test case directory
    test_case_dir = tmpdir.mkdir("testcases")

    # Add a test case for our sample decoder.
    ret = script_runner.run(
        "kordesii",
        "test",
        "Sample",
        "--testcase-dir",
        str(test_case_dir),
        "--malware-repo",
        str(malware_repo),
        "--add",
        str(strings_exe),
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    # Ensure test file got placed in the right location.
    test_sample = malware_repo / "e1b6" / "e1b6be6c0c2db8b3d4dca56062ca6301"
    assert test_sample.exists()
    assert test_sample.read_binary() == strings_exe.read_binary()

    # Ensure the test case was created correctly.
    test_case_file = test_case_dir / "Sample.json"
    assert test_case_file.exists()
    assert json.loads(test_case_file.read_text("utf8")) == [
        {
            u"debug": [u"[+] Found XOR encrypt function at: 0x401000", u"[+] IDA return code = 0"],
            u"input_file": str(test_sample),
            u"strings": [
                u"Hello World!",
                u"Test string with key 0x02",
                u"The quick brown fox jumps over the lazy dog.",
                u"Oak is strong and also gives shade.",
                u"Acid burns holes in wool cloth.",
                u"Cats and dogs each hate the other.",
                u"Open the crate but don't break the glass.",
                u"There the flood mark is ten inches.",
                u"1234567890",
                u"CreateProcessA",
                u"StrCat",
                u"ASP.NET",
                u"kdjsfjf0j24r0j240r2j09j222",
                u"32897412389471982470",
                u"The past will look brighter tomorrow.",
                u"Cars and busses stalled in sand drifts.",
                u"The jacket hung on the back of the wide chair.",
                u"32908741328907498134712304814879837483274809123748913251236598123056231895712",
            ],
        }
    ]

    # Now test the deletion of the test case.
    ret = script_runner.run(
        "kordesii",
        "test",
        "Sample",
        "--testcase-dir",
        str(test_case_dir),
        "--malware-repo",
        str(malware_repo),
        "--delete",
        str(strings_exe),
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    # Make sure we did NOT remove the file from the malware repo.
    assert test_sample.exists()
    assert test_sample.read_binary() == strings_exe.read_binary()

    # Check that the test case has been removed, but the test case file still exists.
    assert test_case_file.exists()
    assert json.loads(test_case_file.read_text("utf8")) == []


def test_add_filelist_testcase(tmpdir, script_runner):
    """Tests bulk adding testcases with --add-filelist flag."""
    # Create a dummy malware repo
    malware_repo = tmpdir.mkdir("malware_repo")

    # Create a dummy test case directory
    test_case_dir = tmpdir.mkdir("testcases")

    # Create a file list of paths.
    filelist = []
    for i in range(10):
        file = tmpdir / "file_{}".format(i)
        data = "this is file {}".format(i).encode()
        file.write_binary(data)
        filelist.append((str(file), hashlib.md5(data).hexdigest()))

    filelist_txt = tmpdir / "filelist.txt"
    filelist_txt.write_text(u"\n".join(file_path for file_path, _ in filelist), "utf8")

    # Add a test case for our sample decoder.
    ret = script_runner.run(
        "kordesii",
        "test",
        "Sample",
        "--testcase-dir",
        str(test_case_dir),
        "--malware-repo",
        str(malware_repo),
        "--add-filelist",
        str(filelist_txt),
    )
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.success

    # Ensure a sample was added for each file and exists in the testcase.
    test_case_file = test_case_dir / "Sample.json"
    assert test_case_file.exists()
    testcases = json.loads(test_case_file.read_text("utf8"))
    input_files = [testcase[u"input_file"] for testcase in testcases]
    assert len(input_files) == len(filelist)
    for _, md5 in filelist:
        test_sample = malware_repo / md5[:4] / md5
        assert test_sample.exists()
        assert hashlib.md5(test_sample.read_binary()).hexdigest() == md5
        assert str(test_sample) in input_files
