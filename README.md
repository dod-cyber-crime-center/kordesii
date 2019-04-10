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

### Guides
- [Decoder Development](docs/DecoderDevelopment.md)
- [Decoder Installation](docs/DecoderInstallation.md)
- [Decoder Testing](docs/DecoderTesting.md)

## Dependencies
DC3-Kordesii requires the following:
- Windows
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

## Usage

DC3-Kordesii is designed to standardize automation of a task typically done by one-off scripts.
Most automated processing systems will use a condition, such as a YARA signature match, 
to trigger execution of a particular DC3-Kordesii decoder.

There are 2 options for integration of DC3-Kordesii:
- CLI: `kordesii`
- REST API based on wsgi/bottle: ```kordesii-server```, ```kordesii-client```

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

`kordesii-client` and the following curl commands demonstrate how to use this web service:
```console
> curl --form data=@README.md http://localhost:8080/run_decoder/foo
> curl http://localhost:8080/descriptions
```


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

```python
from kordesii.utils import function_tracing

# First create a tracer for the function
addr = 0x401839
tracer = function_tracing.FunctionTracer(addr)

# Request the context for a particular address (within the function) to retreive
# operands, register values and memory data.
context = tracer.context_at(addr)
operand_1 = context.get_operand_value(0, size=12)
rbp = context.reg_read("RBP")
stack = context.mem_read(rbp, size=0x14)

# Get function arguments for a call instruction.
for context, args in tracer.get_function_args(0x40147f):
    for i, arg in enumerate(args):
        print "Arg {} -> 0x{:X}".format(i, arg)
        # If arg is a pointer, you can use the context to dereference it.
        value = context.mem_read(arg, size=100)


# NOTE: context_at() and get_function_args() will return the results for the first code path.
# Use iter_context_at() and iter_function_args() respectively to get results for all possible paths.
for context in tracer.iter_context_at(addr):
   # ...
```

*WARNING: `function_tracing` uses the Hex Ray's decompiler to help get more accurate function signatures for the `get_function_args()`.
You are more likely to get an incorrect number of arguments if it is not available.*
