# DC3-Kordesii
[Changelog](CHANGELOG.md) | [Releases](https://github.com/Defense-Cyber-Crime-Center/kordesii/releases)

DC3-Kordesii is a framework for decoding encoded strings and files in malware via IDA Pro IDAPython scripting. One parser module is usually created per malware family. DC3-Kordesii was designed to ease the burden of encoded string extraction by doing it in an automated, static way as well as to provide a standard set of functionality and methodologies. DC3-Kordesii supports both an analyst directed analysis and large-scale automated executing, utilizing either the REST API, the CLI or by manually running decoders in IDA. DC3-Kordesii is authored by the Department of Defense Cyber Crime Center (DC3).

## Dependencies
DC3-Kordesii requires the following:
- python 2.7 (32 bit)
- IDA Pro (tested with version 6.8)

### Recommended Modules
The following modules are recommended as they are often used in decoders:
- pyCrypto

## Installation
```bash
pip install kordesii
```

Alternatively you can clone this repo and then install with setup.py
```bash
git clone https://github.com/Defense-Cyber-Crime-Center/kordesii.git
cd kordesii
python setup.py install
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


## Decoder Development

The high level steps for module development are:
- Create new `<your decoder directory>\<name>_StringDecoder.py` module
- Add the following stub to the bottom of the module (where ```main``` is the entry point)

```python
if __name__ == '__main__':
    idc.Wait()
    main()
    if 'exit' in idc.ARGV:
        idc.Exit(0)
```
- When possible, subclass ```StringTracer``` and implement its search method
- When necessary, subclass ```EncodedString```

```sample_StringDecoder.py``` is provided as an example and may be used as a template.

```stack_string_StringDecoder.py``` is provided as an example of how to traverse IDA's disassembly via IDAPython.

### Decoder Development Tips
- Use the functions in decoderutils where possible
 - The main function ```string_decoder_main``` will likely handle most samples
 - When ```string_decoder_main``` cannot be used, use as many of it's main 5 functions as is feasible
  - ```yara_find_decode_functions``` (and ```generic_run_yara```)
  - ```find_encoded_strings``` (and ```find_encoded_strings_inline```)
  - ```decode_strings```
  - ```output_strings```
  - ```patch_strings```
- Document the tracing algorithm in plain text