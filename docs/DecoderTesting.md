# Testing Decoders

The DC3-Kordesii framework produces JSON results for given samples
run against specified config parsers. Since the JSON output is already easily parseable,
the output of a decoder itself can be used to represent both expected results and act as a test case.
By using JSON output that is known to be valid as a test case, the creation of test cases
becomes simplified and streamlined.

The `kordesii test` command line utility has been created for users to genereate and run test cases.

- [Executing Existing Test Cases](#executing-existing-test-cases)
- [Creating or Adding Test Cases](#creating-or-adding-test-cases)
    - [Determining files to use as test cases](#determining-file-to-use-as-test-cases)
   - [Adding test cases](#adding-test-cases)
- [Updating Test Cases](#updating-test-cases)
- [Removing Test Cases](#removing-test-cases)
- [Testing External Parsers](#testing-external-parsers)
- [Using a Malware Repository](#using-a-malware-repository)


### Guides
- [Decoder Development](DecoderDevelopment.md)
- [Decoder Installation](DecoderInstallation.md)
- [Decoder Testing](DecoderTesting.md)


## Executing Existing Test Cases

Possibly the most routine action is to execute existing test cases.

```console
> kordesii test foo

Running test cases. May take a while...
All Passed = True
```

If a decoder is not provided all registered decoders will be tested.

```console
> kordesii test

DECODER argument not provided. Run tests for ALL decoders? [Y/n]:
Running tests cases. May take a while...
```

Please see `kordesii test -h` to view all options.

The following command line options can also be used to modify how the results are output to the console:
* `-f / --show-passed` : Display details only for failed test cases
* `-s / --silent` : Silent. Only display a simple statement saying whether all test cases passed or not.

## Creating or Adding test cases

The basic steps in creating test cases are:
1. Identify list of files which serve as effective test cases
2. Add the test case files to the test cases
3. Validate that the test cases work


## Determining files to use as test cases

Using wild cards is a simple way to run a directory of files against a decoder in DC3-Kordesii.

For example:
```console
> kordesii parse foo ./malwarez/**/*
```

Once run, manually view the results produced by each file. Ensure each result is meaningful - 
decoder worked properly, results show valuable decrypted strings and/or metadata, etc.


## Adding Test Cases

`kordesii test` with the `--add` flag can be used to add new test case files.

```console
> mwcp test foo --add=file1.exe --add=file2.exe

Updating results for file1.exe in mwcp\parsers\tests\foo.json
Updating results for file2.exe in mwcp\parsers\tests\foo.json
```

## Updating Test Cases

When a parser is updated or any other situation requires all the existing test cases to be regenerated, 
the `--update` option should be used. It will simply re-run the metadata
extraction for all the input files in the current test cases and replace the results.

```console
> kordesii test foo --update

Updating results for file1.exe in mwcp\parsers\tests\foo.json
Updating results for file2.exe in mwcp\parsers\tests\foo.json
Updating results for file3.exe in mwcp\parsers\tests\foo.json
```

## Removing Test Cases

Test cases can be removed using the `--delete` option and specifying the path to a test file.

```console
> kordesii test foo --delete=file1.exe --delete=file2.exe

Removing results for file1.exe in mwcp\parsers\tests\foo.json
Removing results for file2.exe in mwcp\parsers\tests\foo.json
```


## Testing External Parsers

By default, DC3-Kordesii will only support running and updating tests that come with kordesii or have been
installed by a [parser package](ParserInstallation.md#formal-parser-packaging).
If you would like to use `kordesii test` with your own external parsers you will need
to use the `--kordesii-dir` and `--testcase-dir` to tell kordesii where the decoders and test cases reside.

```console
> mwcp --decoder-dir=C:\decoders test --testcase-dir=C:\decoders\tests foo
> mwcp --decoder-dir=C:\decoders test --testcase-dir=C:\decoders\tests foo --update
```

## Using a Malware Repository

If desired, all test files can be automatically added to an external malware repository 
which is a separate directory that organizes the samples by md5.

To use, add `--malware-repo` pointing to your repository when adding or deleting tests:

```console
> kordesii test --malware-repo=X:\MalwareRepo foo -a ./malware.bin
> kordesii test --malware-repo=X:\MalwareRepo foo -x ./malware.bin
```

For more persistence, you can add the environment variable `KORDESII_MALWARE_REPO` which points 
to your malware repository. This will cause `--malware-repo` to automatically apply if not supplied. 

```console
> set KORDESII_MALWARE_REPO="X:\MalwareRepo"
> kordesii test foo -a ./malware.bin
> kordesii test foo -x ./malware.bin
```
