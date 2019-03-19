# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]
### Added
- New `seralizer` module.
  - Access via `kordesii.get_serializer()`, and set key/value pairs
  with `serializer.set(key, value)`.
  - Retrieve serialized data from `Reporter` objects with the `other_data`
  attribute or `get_serialized()`.
- Support for using setuptool's entry_points to allow for formal python packaging of decoders. 
(See [documentation](docs/DecoderDevelopment.md#formal-decoder-packaging) for more information.)
- Ability to register decoder source(s) using `register_decoder_directory()` or `register_decoder_package()`
 functions.
- Support for relative input paths in test cases.
- Created a new command line tool called `kordesii` which encompasses parsing and testing in one tool.
    - This tool simplifies and cleans up the old CLI flags and uses subcommands for better organization.
- `--parser-config` flag to specify location of a parser configuration file for a custom parser directory.
- Ability to set a parser source with `--parser-source` flag.
- `FunctionTracer` caching with `function_tracing.TracerCache`
 
### Changed
- "decodertests" folder has been moved to within the "decoders" folder and renamed "tests".
- Improved CPU emulation results by modifying necessary registers to satisfy jump conditions.
  
### Deprecated
- The `decoderdir` attribute as well as the `list_decoders()` and `get_decoder_path()` functions
 in the Reporter class have been deprecated in favor of the new decoder registration methods.
- The `disabledebug` attribute in the Reporter class is deprecated. Log level should be set using the `logging` library.
- The `get_errors()`, `get_debug()`, `error()`, and `debug()` functions in Reporter are deprecated in favor
of using the logging library to log and handle messages.
- The `kordesii-tool` and `kordesii-test` tools are deprecated in exchange for using the new `kordesii` tool and
    will be removed in a future version.

### Fixed
- Fixed missing `log_config.yml` error.


## [1.3.0] - 2019-02-11
### Added
- Created `kordesii.decoder_entry` function decorator to be used to wrap the decoder entry point function. 
    - This replaces the need to create a `if __name__ == "__main__":` condition statement.
- Created `kordesii.utils.yara` which acts as a drop-in replacement for `yara` that effectively converts
    offsets to virtual addresses.
    - This is replaces many of the existing yara utility functions.

### Changed
- Renamed IDA API function calls to the new 7.* snake_case names. This removes the need to enable 
their compatibility layer: `AUTOIMPORT_COMPAT_IDA695`
- Renamed and moved modules:
    - `kordesii.utils.tracingutils` -> `kordesii.utils.tracing`
    - `kordesii.utils.function_tracingutils` - > `kordesii.utils.function_tracing`
    - `kordesii.utils.kordesiiidautils` -> `kordesii.utils.utils`
    - `kordesii.utils.functioncreator` -> `kordesii.utils.function_creator`
- Renamed and moved classes and functions:
    - `kordesii.kordesiireporter.kordesiireporter` -> `kordesii.reporter.Reporter`
    - `kordesii.kordesiitester.kordesiitester` -> `kordesii.tester.Tester`
- Removed `append_debug` from `kordesiiidahelper` in exchange for 
using Python's builtin `logging` functionality.
- Moved the content of `kordesii.kordesiiidahelper` to `kordesii` and provided easy import 
from within the root `kordesii` module.
- Removed the need for decoders to end with `_StringDecode`.

### Deprecated
- Old yara utility functions that have now been replace by `kordesii.utils.yara`
    - `decoderutils.generic_run_yara()`
    - All of `kordesii.utils.idayara`


## [1.2.0] - 2018-10-31
### Added
- `function_tracingutils` utility used for emulation and tracing
function parameters and operand values.
- multi-process testing infrastructure
- `EncodedStackString` object that can be used for strings pulled from stack.
- `factory` function in `EncodedString` object
- `IDA_re` object used to perform regex searching with offsets converted to virtual addresses.

### Changed
- Moved support from IDA 6.* to 7.*
    - (Stick to version 1.1.* for IDA 6.* support)
- Improvements to `SuperFunc_t` object
- Improved codec detection and added better decoding safety for `EncodedString` object.
- Testing now uses multiprocessing

### Deprecated
- `decoded_string` attribute in `EncodedString` object. Use `decoded_data` instead.
- Moved `patch_decoded` and `define_string` into `EncodedString` object.


## [1.1.0] - 2018-04-11
### Added
- This CHANGELOG
- Tagged releases.

### Changed
- Code cleanup and bugfixes
- Overhaul functioncreator algorithms (this changes the function names)
- Speed improvements and code simplification to tracingutils


## 1.0.0 - 2018-03-07
### Added
- Initial contribution.


[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.3.0...HEAD
[1.3.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.0.0...1.1.0
