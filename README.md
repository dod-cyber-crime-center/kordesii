# DC3-Kordesii
[Changelog](CHANGELOG.md) | [Releases](https://github.com/Defense-Cyber-Crime-Center/kordesii/releases)

DC3-Kordesii is a framework for decoding encoded strings and files in malware via IDA Pro IDAPython scripting. One parser module is usually created per malware family. DC3-Kordesii was designed to ease the burden of encoded string extraction by doing it in an automated, static way as well as to provide a standard set of functionality and methodologies. DC3-Kordesii supports both an analyst directed analysis and large-scale automated executing, utilizing either the REST API, the CLI or by manually running decoders in IDA. DC3-Kordesii is authored by the Department of Defense Cyber Crime Center (DC3).

## Dependencies
DC3-Kordesii requires the following:
- Windows
- python 2.7 (32 bit)
- IDA Pro 7.* (tested with 7.0)
- *(optional)* Hex Ray's Decompiler for x86/x64 architectures
    - (Used to improve accuracy of getting function arguments in `function_tracing`)

### Recommended Modules
The following modules are recommended as they are often used in decoders:
- pyCrypto

## Installation
```
pip install kordesii
```

Alternatively you can clone this repo and install locally.
```bash
git clone https://github.com/Defense-Cyber-Crime-Center/kordesii.git
pip install ./kordesii
```

For a development mode use the `-e` flag to install in editable mode:
```
git clone https://github.com/Defense-Cyber-Crime-Center/kordesii.git
pip install -e ./kordesii
```

### Decoder Installation
To make a decoder available for use, place it a directory with the name `<name>_StringDecoder.py`
Then pass the directory containing your decoders through the command line.
```bash
kordesii --decoderdir=C:\my_decoders -p <name> <input_file>
```

If no decoder directory is specified it will default to the decoder directory that comes with
this python package, which will be located in the site-packages. (e.g. C:\Python27\Lib\site-packages\kordesii\decoders)

## Use

DC3-Kordesii is designed to standardize automation of a task typically done by one-off scripts.

Most automated processing systems will use a condition, such as a YARA signature match, to trigger execution of a particular DC3-Kordesii decoder.

There are 2 options for integration of DC3-Kordesii:
- REST API based on wsgi/bottle: ```kordesii-server```, ```kordesii-client```
- CLI: `kordesii`

DC3-Kordesii also includes a utility for test case execution: ```kordesii-test```

### REST API

The REST API provides two commonly used functions:

* ```/run_decoder/<decoder>``` -- executes a decoder on uploaded file
* ```/descriptions``` -- provides list of available parsers

`kordesii-client` and the following curl commands demonstrate how to use this web service:
```sh
curl --form data=@README.md http://localhost:8080/run_decoder/foo
curl http://localhost:8080/descriptions
```

bottle (bottlepy.org) is required for the server. The bottle provided web server or another wsgi can be used.

### CLI tool

kordesii-tool provides functionality to run decoders on files:

```sh
kordesii -p foo README.md
```

see ```kordesii -h``` for full set of options


## Logging
DC3-Kordesii uses Python's builtin in `logging` module to log all messages.
By default, logging is configured using the [log_config.yml](kordesii/config/log_config.yml) configuration
file. Which is currently set to log all messages to the console and error messages to `%LOCALAPPDATA%/kordesii/errors.log`. 
You can provide your own custom log configuration file by adding the path
to the environment variable `KORDESII_LOG_CFG`. (Please see [Python's documentation](http://docs.python.org/dev/library/logging.config.html) for more information on how to write your own configuration file.)

You may also use the `--no-debug` or `--debug` flags to adjust the logging level when using the `kordesii-tool` tool.

To log messages within a decoder, make sure to use `kordesii.get_logger()` in order to ensure the 
decoder name will be properly added to the log message.

It is a good idea to use logging to help inform the user on the progress of the decoder and if the decoder may need to be updated due to a new variant of the sample.

```python
import kordesii

logger = kordesii.get_logger()

# ...

@kordesii.decoder_entry
def main():
    logger.info('Starting decoder.')
    key = get_key()
    if key:
        logger.info('Found key: {!r}'.format(key))
        # ...
    else:
        logger.warning('Unable to find the key! New variant?')
```


## Decoder Development

The high level steps for module development are:
- Create new `<your decoder directory>\<name>.py` module
- Import `kordesii` and then decorate your entry point with `kordesii.script_entry`
    - **WARNING:** It is important that the function you wrap with `kordesii.script_entry` is the last thing in the module.
    Anything declared after it will not available when the parser runs.

```python
import kordesii


@kordesii.script_entry
def main():
    # ...
```
- When possible, subclass ```StringTracer``` and implement its search method
- When necessary, subclass ```EncodedString```

```sample_StringDecoder.py``` is provided as an example and may be used as a template.

```stack_string_StringDecoder.py``` is provided as an example of how to traverse IDA's disassembly via IDAPython.

## CPU Emulation
DC3-Kordesii includes an experimental tracing utility called `function_tracingutils` that can be used to statically emulate
and trace instructions within a function.

```python
from kordesii.utils import function_tracingutils

# First create a tracer for the function
addr = 0x401839
tracer = function_tracingutils.FunctionTracer(addr)

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
# Use iter_context() and iter_function_args() respectively to get results for all possible paths.
for context in tracer.iter_context(addr):
   # ...
```

*WARNING: `function_tracingutils` uses the Hex Ray's decompiler to
help get more accurate function signatures for the `get_function_args()`.
You are more likely to get an incorrect number of arguments if it is not available.*


### Decoder Development Tips
- Use the functions in `decoderutils` and `function_tracingutils` where possible
 - When ```string_decoder_main``` cannot be used, use as many of it's main 5 functions as is feasible
  - ```yara_find_decode_functions``` (and ```generic_run_yara```)
  - ```find_encoded_strings``` (and ```find_encoded_strings_inline```)
  - ```decode_strings```
  - ```output_strings```
- Document the tracing algorithm in plain text
