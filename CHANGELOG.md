# Changelog
All notable changes to this project will be documented in this file.

## [1.6.1] - 2019-09-13

### Fixed
- Fixed typo in fpu computation opcodes causing an AttributeError. (@ddash-ct)

## [1.6.0] - 2019-09-10

### Added
- *function_tracing:*
    - Added `base_addr` attribute to `Operand` object. This attribute is the referenced memory address of an operand minus any indexing.
        (e.g. The `ebp+var_8` from `[ebp+ecx*2+var_8]`)
    - Added `variables` attribute to `ProcessorContext`. This object can be used to query variables that have been
    encountered during emulation. (See [documentation](docs/CPUEmulation.md#variables) for more information.)
    - Added initial support for x87 FPU registers and opcodes which involve loading, storing, and computing floating point numbers (e.g. FLD, FST, FADD)
        - Warning: Internal opcodes like FLDENV and FSAVE as well as proper handling of rounding and stack faults are not fully supported.
    - Added `callers` and `calls_to` properties to `SuperFunc_t`. 
        - These can be use to get the functions that call the given function and the addresses where the given function is called respectively.
    - Added `api_calls` property to `SuperFunc_t` which returns a `collections.Counter` object that contains API function names and the number of times they are called in the given function.
    - Added `num_args` parameter to `*_function_args()` functions which allows the user to force a specific
        number of arguments. 
        Extra arguments not detected by the disassmbler will be assumed to be "int" type.
    - Added `get_function_signature()` function to `ProcessorContext`, which returns a `FunctionSignature`
        object that allows for modification of the function signature before pulling argument values.
        (See [documentation](docs/CPUEmulation.md#modifying-function-signature) for more information.)
- `StackStringNG` decoder which uses `function_tracing` to extract stack strings.
- Added `iter_imports()`, `iter_exports()`, and `get_import_addr()` functions to `kordesii.utils.utils`.


### Changed
- Alternative IDA installation directory can now be provided with the `IDA_DIR` environment variable.
- Improved speed of CPU emulation.
- kordesii server is now implemented with Flask instead of Bottle.
    - If using the server as a WSGI app, the app instance must be created with
      the factory function `kordesii.tools.server.create_app()`.
- Renamed `obtain_export_by_name()` to `get_export_addr()`
- Renamed `obtain_function_by_name()` to `get_function_addr()`

### Fixed
- *function_tracing:*
    - Fixed case sensitivity for function hook lookups.
    - Fixed incorrect results that can occur when searching `Memory` for a single character.
    - Removed `__alloca_probe` function hook since it was producing an incorrect return value and is no longer required.
    - Fixed incorrect overflow flag calculation in some opcodes.
    - Fixed incorrect "sib" scale in operand displacement calculation.
    - Emulating paths with parent blocks at an address greater than itself is now fully supported.
- The `error` key in the API results now correctly contains a list of strings.
    
### Deprecated
- `ProcessorContext.get_variable_name()` is deprecated in favor of using the new `variables` attribute.
- The `error` key in the API results now correctly contains a list of strings.
- The `IterApis()` class is deprecated in favor of using `iter_imports()` or `iter_functions()`.


## [1.5.0] - 2019-06-20
### Added
- *function_tracing:*
    - Created a global `TracerCache` that can be accessible using the `get_tracer()` function.
        - (This removes the need for initiating your own tracer cache.)
    - Added `operands` attribute to `ProcessorContext` object. 
        - This attribute is a list of `Operand` objects for the current instruction (the instruction **to be** executed) 
     that can be used to query the characteristics of the operand as well
     as extract a value or referenced memory address.
    - Support for emulating some builtin C/C++ and Windows library functions
    - Support for hooking custom functions with the `hook()` function accessible from `FunctionTracer`, `TracerCache`, or through `hook_tracers()`.
        - (See [README](../README.md) for an example on how to hook a function.)
    - Support for emulating `rep*` instructions.
    - Support for `movdqa`, `movdqu`, and `movd` opcodes.
    - Ability to emulate the caller functions using the `depth` parameter.
    - Ability to access the history of a given pointer within a context using `get_pointer_history()`
    - Ability to access the original location of a pointer within a context using `get_original_location()`
- Added `publish()` function to `EncodedString` and `EncodedStackString` object.
- Documentation for [CPU Emulation](docs/CPUEmulation.md)

### Changed
- *function_tracing:*
    - Renamed `trace` and `trace_iter` in `FunctionTracer` to `get_operand_value` and `iter_operand_value` to improve clarity and consistency.
    - The `get_operand_value` and `iter_operand_value` no longer accepts a data type and now 
 returns a tuple containing the context and value (just like `get_function_args`).
        - This function returns either a contained value for operands like registers and immediates or a memory address
   for memory references (e.g. `[rsi+8]`). It is then up to the user to use the `read_data` function in the 
   context to read out the data they need.
   - `read_data()` function in `ProcessorContext` will now default to a C string if size isn't provided.
- Calling `calc_size()` from the `EncodedString` object is no longer necessary. Encoded data will automatically be extracted during initialization.
   
### Deprecated
- `decoderutils.INVALID` and `decoderutils.UNUSED` enums are deprecated in exchange for using `None` directly.
- `decoderutils.output_strings()` is deprecated in exchange for calling `.publish()` on the `EncodedString` object.
- `as_bytes`, `byte_length`, `calc_size()`, `get_bytes()`, and `size` are deprecated in the `EncodedString` object. Please access the `encoded_data` and `decoded_data` attributes directly instead.
- *function_tracing:*
    - `bfs_iter_heads()`, `bfs_iter_blocks()`, `dfs_iter_heads()`, and `dfs_iter_blocks()` in `FlowChart` are all deprecated in 
    favor of using the `heads()` and `blocks()` functions with the optional `dfs` parameter.
   
### Fixed
- Fixed issue with logs not being displayed if the log port was still bound to a previous process.
- *function_tracing:*
    - Fixed bug with `shr` opcode
    - Fixed issue with missing trailing null byte when extracting a little endian wide byte with `read_data()` (#7)
    - Refactored memory controller to eliminate unexpected mapping errors.
     

### Removed
- Removed `find_unrefd_encoded_strings()` function in `decoderutils`
   
   
## [1.4.1] - 2019-04-10
### Fixed
- Added more framework tests.
- Fixed tuple error when attempting to use the `--add-filelist` option in `kordesii test`.
- Fixed issue with external decoder sources not being detected correctly.


## [1.4.0] - 2019-03-20
### Added
- New `seralizer` module.
  - Access via `kordesii.get_serializer()`, and set key/value pairs
  with `serializer.set(key, value)`.
  - Retrieve serialized data from `Reporter` objects with the `other_data`
  attribute or `get_serialized()`.
- Support for using setuptool's entry_points to allow for formal python packaging of decoders. 
(See [documentation](docs/DecoderInstallation.md#formal-packaging) for more information.)
- Ability to register decoder source(s) using `register_decoder_directory()` or `register_decoder_package()`
 functions.
- Support for relative input paths in test cases.
- Created a new command line tool called `kordesii` which encompasses parsing and testing in one tool.
    - This tool simplifies and cleans up the old CLI flags and uses subcommands for better organization.
- Ability to set a parser source with `--parser-source` flag.
- `FunctionTracer` caching with `function_tracing.TracerCache`
 
### Changed
- "decodertests" folder has been moved to within the "decoders" folder and renamed "tests".
- Improved CPU emulation results by modifying necessary registers to satisfy jump conditions.
- Updated documentation!
  
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


[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.6.1...HEAD
[1.6.1]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.6.0...1.6.1
[1.6.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.5.0...1.6.0
[1.5.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.4.1...1.5.0
[1.4.1]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.4.0...1.4.1
[1.4.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.0.0...1.1.0
