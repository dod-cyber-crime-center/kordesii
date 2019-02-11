# Changelog
All notable changes to this project will be documented in this file.

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
- Removed the need for decoder to end with `_StringDecode`.

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
