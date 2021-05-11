# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed
- In IDA 7.6, imported functions are now function pointers, add checks accordingly


## [2.2.0] - 2020-10-30

### Added
- *function_tracing*
    - Added additional WinAPI function hook support
    - Added recording of ShellOperation actions
- Added `calls_from` and `callees` properties to `kordesii.utils.Function` object.
- Added `is_64bit` option when running a decoder. This allows the user to force the use of `ida64` or `ida` if option
    is `True` or `False` respectively. This option can also be set in the command line using the `--64bit` or `--32bit`
    flags.
    
### Changed
- Added `.split()` function to `EncodedString` class, which replaces `decoderutils.split_decoded_string()`

### Fixed
- Fix to account for getting the correct function data using the operand even if the offset is invalid. This provides better support for dynamically resolved function calls. (@ddash-ct)
- *function_tracing*
    - Fixed typo in `jnp` / `jpo` opcodes for `function_tracing`
    - Fixed incorrect handling of IDIV signed division
- General fixes to improve support when running under Linux.
    
### Deprecated
- `kordesii.utils.split_decoded_string()` is deprecated in favor of using `kordesii.utils.EncodedString.split()`


## [2.1.0] - 2020-06-05

### Added
- *function_tracing*
    - Added ability to follow loops during emulation by enabling the `follow_loops` flag.
        (See [documenation](docs/CPUEmulation.md#emulating-loops) for more information.)
    - Full subroutines can be emulated using `create_emulated()` or `emulate_call()`
        (See [documenation](docs/CPUEmulation.md#emulating-subroutines) for more information.)
    - Added ability to modify the function arguments using the `FunctionArg` objects returned by the `get_function_arg_objects()` function in the CPU context.
        (See [documentation](docs/CPUEmulation.md#retrieving-function-arguments) for more information.)
    - Added `passed_in_args` property in the CPU context which returns a list of `Functionarg` objects for the arguments of the function the context is currently in.
    - Added `function_args` property in the CPU context which is a shortcut for `get_function_arg_objects()` for the current call instruction.
    - Added `disable()` function in `Emulator` which allows disabling unnecessary opcodes or function hooks.
    - Added WinAPI function hooks
    - Added ability to set variable values retrieved from `ProcessorContext.variables`
    - Added support for instruction hooks.
        (See [documentation](docs/CPUEmulation.md#hooking-instructions) for more information.)
    - Added support for more x86/64 opcodes: STD, SCAS*
    - Created `kordesii.utils.iter_dynamic_functions()` which iterates dynamically resolved function signatures.
    - Added recording of interesting actions and high level objects: Files and Registry Keys
        (See [documentation](docs/CPUEmulation.md#objects) for more information.)

### Changed
- Input file paths in test cases now support environment variable expansion. 
- Input file paths in test cases can include `{MALWARE_REPO}` which will be replaced
by the currently set malware repository path.
- *IDA Proxy*
    - The stack trace in IDA is now locally printed to stderr when an exception occurs in a 
`run_in_ida` decorated function.
    - `run_in_ida` decorated functions can now execute other `run_in_ida` decorated functions within the same module.
- *function_tracing*
    - Getting and retrieving registers from `ProcessorContext.registers` is no longer case insensitive. Register names must be all lower case. This was done in order to improve emulation speed. 
        - However, `reg_read()` and `reg_write()` are not affected by this. 
    - Renamed `CustomBasicBlocks` to `BasicBlocks` to be more consistent with other objects.
    - Passed in arguments that come from memory or the stack are now added to the `ProcessorContext.variables`
        attribute after the first instruction of the function is emulated.
    - Updated `kordesii.utils.iter_functions()` to include dynamically resolved function signatures.
    - Allow call operand type to be taken into account when pulling a function signature. This provides better support for dynamically resolved function calls. (@ddash-ct)
- Moved functions and classes:
    - `kordesii.utils.decoderutils.SuperFunc_t` -> `kordesii.utils.Function`
    - `kordesii.utils.decoderutils.EncodedString` -> `kordesii.utils.EncodedString`
    - `kordesii.utils.decoderutils.EncodedStackString` -> `kordesii.utils.EncodedStackString`
    - `kordesii.utils.decoderutils.find_destination` -> `kordesii.utils.find_destination`
    - `kordesii.utils.decoderutils.re_find_functions` -> `kordesii.utils.ida_re.find_functions`
    - `kordesii.utils.decoderutils.yara_find_decode_functions` -> `kordesii.utils.yara.find_functions`
    - `kordesii.utils.utils.*` -> `kordesii.utils.*`
    - `kordesii.utils.function_tracing.flowchart.FlowChart` -> `kordesii.utils.Flowchart`

### Fixed
- Remote logs using IDA proxy are now displayed.
- If a log level is passed into `kordesii.setup_logging()` it will now be used set to the root logger for you.
- *function_tracing*
    - Fixed issue sometimes causing an incorrect stack cleanup when emulating the `call` opcode. 

### Deprecated
- Old locations for moved functions and classes mentioned above are deprecated and will be removed in a 
future version.
- Deprecated `FunctionTracer` and `get_tracer()` in exchange for creating a global instance of an `Emulator` object. This object just needs to be instantiated once on the top of your modules and is used in the same way as a function tracer but for any function.  It is also used to apply call hooks.
  - See [documentation](docs/CPUEmulation.md) for more information.
- `kordesii.utils.decoderutils.make_superfunc_t_from_matches()`
- The `identifier` property in `kordesii.utils.Function` (renamed from `SuperFunc_t`) is deprecated and should not be used.

### Removed
- *function_tracing*
    - Removed broken and unused `path_to_ea()` function in `Flowchart`


## [2.0.1] - 2020-05-01

### Changed
- Setup fixes for PyPi deployment


## [2.0.0] - 2020-02-20

### Changed
- Dropped support for Python 2 and IDA versions <= 7.3
- Added support for Python 3 and IDA version 7.4 (in Python 3 mode)

### Removed
- Removed `requirements.txt` file.
- Removed previously deprecated components:
    - `iter_functions()` in `kordesii.utils.decoderutils`
    - `ProcessorContext.get_variable_name()`
    - `kordesii.utils.utils.IterApis()`
    - `decoderutils.INVALID` and `decoderutils.UNUSED` enums
    - `decoderutils.output_strings()`
    - `as_bytes`, `byte_length`, `calc_size()`, `size`, `get_bytes()`, and `decoded_string` in `EncodedString` class
    - `bfs_iter_heads()`, `bfs_iter_blocks()`, `dfs_iter_heads()`, and `dfs_iter_blocks()` in `function_tracing.Flowchart`
    - `decoderdir`, `disabledebug`, `list_decoders()`, and `get_decoder_path()` in `Reporter` class
    - `get_errors()`, `get_debug()`, `error()`, and `debug()` in `Reporter` class
    - `kordesii-tool`, `kordesii-client`, `kordesii-server`, and `kordesii-test` command line tools
    - `kordesii.tools.tool`, `kordesii.tools.test`, and `kordesii.tools.client` modules
    - `decoderutils.generic_run_yara()`
    - `kordesii.utils.idayara` module
    - `patch_decoded()` and `define_string()` in `decoderutils`
    - `get_segment_bytes()`, `get_segment_start()`, `IDA_MatchObject`, and `IDA_re` in `kordesii.utils.utils`


## [1.7.0] - 2020-01-15

**NOTE: This is the last version to support Python 2 and IDA 7.0-7.3. 
The next release will only support Python 3 and IDA >= 7.4.**

### Added
- Added `--force` flag to `Tester` for adding or updating testcases to ignore errors if set. (@ddash-ct)
- *function_tracing:*
    - Added support for more x86/64 opcodes: AAA, AAD, AAM, AAS, CMC, CQO, CWD, POPF, POPFD, POPFQ, PUSHF, PUSHFD, PUSHFQ
    - Added support for builtin functions: memchr, strpbrk, strchr, strstr
- Added experimental feature which allows you to run IDA code remotely. 
    (See [documentation](README.md#ida-proxy) for more information.)

### Changed
- Changed `iter_functions()` and `iter_imports()` functions to include matching functions with underscores or integer suffixes.
    - e.g. `iter_functions("memcpy")` would match on `memcpy`, `_memcpy`, and `_memcpy_0`
- *function_tracing:*
    - If IDA fails to guess a function type, a function signature will now be forced using cdecl calling convention if the `num_args` parameter is set for `get_function_args()` or the `force` parameter for `get_function_signature()`.
    This is useful for functions that were dynamically declared.
    - Segment data is now retrieved on-demand. This helps to greatly speed up emulation for samples containing large data segments.
- Renamed and moved component:
    - `kordesii.utils.utils.IDA_re()` -> `kordesii.utils.ida_re.Pattern()`
    - `kordesii.utils.utils.get_segment_bytes()` -> `kordesii.utils.segments.get_bytes()`
    - `kordesii.utils.utils.get_segment_start()` -> `kordesii.utils.segments.get_start()`
- `setuptools` is now required for decoder package discovery. (This is no longer optional.)

### Fixed
- `ida_re.search()` will now properly search all segments if a segment is not provided.
- *function_tracing:*
    - Fixed stack delta calculation in CALL opcode by using `get_sp_delta()` when function data cannot be obtained.
    - Fixed bug in displacement operands to interpret `base` and `index` properties as signed integers. (@ddash-ct)
    - Fixed logic error in rotate and shift opcodes due to incorrectly placed parenthesis.
    - Added a check to ensure stack variables have a non-zero base before being added to the context's variable set.
    - `Memory.realloc()` now appropriately copies the data from the previous address if a relocation occurs.

### Deprecated
- `iter_functions()` in `kordesii.utils.decoderutils` is deprecated in favor of using the one in `kordesii.utils.utils`


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


[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/2.2.0...HEAD
[2.2.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/2.1.0...2.2.0
[2.1.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/2.0.1...2.1.0
[2.0.1]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.7.0...2.0.0
[1.7.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.6.1...1.7.0
[1.6.1]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.6.0...1.6.1
[1.6.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.5.0...1.6.0
[1.5.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.4.1...1.5.0
[1.4.1]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.4.0...1.4.1
[1.4.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/Defense-Cyber-Crime-Center/kordesii/compare/1.0.0...1.1.0
