# DC3-Kordesii
[Changelog](CHANGELOG.md) | [Releases](https://github.com/Defense-Cyber-Crime-Center/kordesii/releases)

DC3-Kordesii is a framework for decoding encoded strings and files in malware via IDA Pro IDAPython scripting. 
One parser module is usually created per malware family. 
It is designed to ease the burden of encoded string extraction by doing it in an automated, 
static way as well as to provide a standard set of functionality and methodologies. 
It supports both an analyst directed analysis and large-scale automated executing, 
utilizing either the REST API, the CLI or by manually running decoders in IDA. 

DC3-Kordesii is authored by the Department of Defense Cyber Crime Center (DC3).

- [Install](#install)
- [Usage](#usage)
    - [CLI Tool](#cli-tool)
    - [REST API](#rest-api)
- [Logging](#logging)
- [CPU Emulation](#cpu-emulation)
- [IDA Proxy](#ida-proxy)

### Guides
- [CPU Emulation](docs/CPUEmulation.md)
- [Decoder Development](docs/DecoderDevelopment.md)
- [Decoder Installation](docs/DecoderInstallation.md)
- [Decoder Testing](docs/DecoderTesting.md)

## Dependencies
DC3-Kordesii requires the following:
- python 2.7 (32 bit)
- IDA Pro 7.* (tested with 7.0)
- *(optional)* Hex Ray's Decompiler for x86/x64 architectures
    - (Used to improve accuracy of getting function arguments in `function_tracing`)

## Install
```console
> pip install kordesii
```

Alternatively you can clone this repo and install locally.
```console
> git clone https://github.com/Defense-Cyber-Crime-Center/kordesii.git
> pip install ./kordesii
```

For a development mode use the `-e` flag to install in editable mode:

```console
> git clone https://github.com/Defense-Cyber-Crime-Center/kordesii.git
> pip install -e ./kordesii
```

### Setup IDA location

By default kordesii assumes you are on Windows and have installed IDA under the default location `C:/Program Files/IDA Pro *`.
If you have installed IDA at a different location or running on another operating system, please set the `IDA_DIR` environment
to point to where IDA has been installed.

## Usage

DC3-Kordesii is designed to standardize automation of a task typically done by one-off scripts.
Most automated processing systems will use a condition, such as a YARA signature match, 
to trigger execution of a particular DC3-Kordesii decoder.

There are 2 options for integration of DC3-Kordesii:
- CLI: `kordesii`
- REST API: ```kordesii serve```

### CLI tool

The `kordesii` tool provides functionality to run and test decoders on files:

```console
> kordesii parse Sample ./kordesii/decoders/tests/strings.exe
[+] (kordesii): Parsing: ./kordesii/decoders/tests/strings.exe
[+] (kordesii.core): IDA return code = 0
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

[+] IDA return code = 0

> kordesii test Sample
Running test cases. May take a while...
 1/1 - kordesii:Sample strings.exe 8.9183s

Test stats:

Top 10 Slowest Test Cases:
 1. kordesii:Sample strings.exe 8.9183s

Top 10 Fastest Test Cases:
 1. kordesii:Sample strings.exe 8.9183s

Mean Running Time: 8.9183s
Median Running Time: 8.9183s
Cumulative Running Time: 0:00:08.918259

Total Running Time: 0:00:09.480942
All Passed = True
```

see ```kordesii -h``` for full set of options

### REST API

The REST API provides two commonly used functions:

* ```/run_decoder/<decoder>``` -- executes a decoder on uploaded file
* ```/descriptions``` -- provides list of available parsers

To use, first start the server by running:
```console
> kordesii serve
```

The following curl commands demonstrate how to use this web service:
```console
> curl --form data=@README.md http://localhost:8080/run_decoder/foo
> curl http://localhost:8080/descriptions
```

A simple HTML interface is also available at the same address.
Individual samples can be submitted and results
saved as JSON, plain text, or ZIP archives.

## Logging
DC3-Kordesii uses Python's builtin in `logging` module to log all messages.
By default, logging is configured using the [log_config.yml](kordesii/config/log_config.yml) configuration
file. Which is currently set to log all messages to the console and error messages to `%LOCALAPPDATA%/kordesii/errors.log`. 
You can provide your own custom log configuration file by adding the path
to the environment variable `KORDESII_LOG_CFG`. (Please see [Python's documentation](http://docs.python.org/dev/library/logging.config.html) for more information on how to write your own configuration file.)

You may also use the `--verbose` or `--debug` flags to adjust the logging level when using the `kordesii` tool.


## CPU Emulation
DC3-Kordesii includes an experimental tracing utility called `function_tracing` that can be used to statically emulate
and trace instructions within a function.

Please see the [CPU Emulation](docs/CPUEmulation.md) documentation for more information.


## IDA Proxy
DC3-Kordesii includes an **experimental** utility that can be used to run IDAPython commands remotely
from another Python interpreter. This is accomplished by hooking IDA imports with proxy wrapper using [Pyro4](http://pyro4.readthedocs.io/en/stable).

**WARNING: This feature is intended to be used in one-off scripts during analysis. 
It is not recommended for this feature to be used in production code.**

To install, you'll need Pyro4 and dill installed in IDA's python folder.
However, these can be installed somewhere else, as long as it is discoverable within IDA's interpreter.

```console
> pip install Pyro4 dill --target=%IDA_DIR%\python
```


To use, pass the file path you want to analyze to `kordesii.IDA()` in a `with` statement.
Within this statement, you can now import and use IDA modules like normal.

```python
import kordesii


with kordesii.IDA(r'C:/data.exe'):
    import idc

    mnem = idc.print_insn_mnem(0x00401525) 
```

For a more interactive experience, you can also start and stop the proxy manually.

```python
>>> import kordesii
>>> ida = kordesii.IDA(r'C:/data.exe')
>>> ida.start()
>>> import idc
>>> idc.print_insn_mnem(0x00401525)
'push'
>>> ida.stop()
```


NOTE: This proxy is only limited to functions that can return serializable objects. Therefore, any function
that returns a `PySwigObject` object will not work. (e.g. `func_t`).
As a workaround, you can decorate a function using `kordesii.run_in_ida` to ensure the full function gets executed from within the IDA interpreter. This functions should not accept or return any non serializable
objects or be bounded to a class that could contain one. As well, globals are not transferred over, so
this function should not read or modify them.

```python
import kordesii


@kordesii.run_in_ida
def func_contains(func_ea, target_ea):
    import ida_funcs

    func = ida_funcs.get_func(func_ea)  # can't call directly in IDA proxy due to Swig object!
    return func.contains(target_ea)


with kordesii.IDA(r'C:/data.exe'):
    print(func_contains(0x004014F5, 0x00401525))
```

(This is also useful to help speed up a procedure that would otherwise be extremely slow due to the large 
number of proxy calls.)

