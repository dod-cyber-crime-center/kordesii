# CPU Emulation

DC3-Kordesii includes an experimental tracing utility called `function_tracing` that can be used to statically emulate
and trace instructions within a function.

- [Creating a FunctionTracer](#creating-a-functiontracer)
- [Creating a ProcessorContext](#creating-a-processorcontext)
- [Iterating Multiple Paths](#iterating-multiple-paths)
- [Emulating Call Stack](#emulating-call-stack)
- [Modifying Function Signature](#modifying-function-signature)
- [Hooking Functions](#hooking-functions)
- [Pointer History](#pointer-history)
- [Variables](#variables)

### Guides
- [CPU Emulation](CPUEmulation.md)
- [Decoder Development](DecoderDevelopment.md)
- [Decoder Installation](DecoderInstallation.md)
- [Decoder Testing](DecoderTesting.md)


## Creating a FunctionTracer

To start, we first need to create a `FunctionTracer` object for the function
that we would like to emulate/trace. This object holds a cache of all
the possible code paths and emulated contexts as they are generated.
While you can initialize your own using the `FunctionTracer` object, it
is recommended to use the `get_tracer()` function to use a previously created
one if it is available.

The address passed in can be any address within the function you would like to emulate.

```python
from kordesii.utils import function_tracing

# First create a tracer for the function at addr.
addr = 0x401839
tracer = function_tracing.get_tracer(addr)
```

## Creating a ProcessorContext

We can emulate the function up to a particular instruction address (but not including) by requesting the context. 
For a simple function, we most likely will only care about the first possible
code path to get to that instruction. In which case we can use the `context_at()` function.

If emulation is successful, a `ProcessorContext` object will be returned.
This object can be used to extract information about its registers, operands, and memory at that point in time.
If the given instruction is a `call` operation, the passed in arguments can also be retrieved.

- Operands are a special `Operand` object that can be used to query information about the operand (`type`, `text`, `has_register()`, etc) and holds the dereferenced `value` and the source `addr` if it's a memory reference.
- Memory can be retrieved with the `read_data()` function.

```python
context = tracer.context_at(addr)

# extract the first operand at addr
operand = context.operands[0]  # equivalent to context.get_operands(addr)[0]
# pull referenced address if memory reference or value otherwise
ptr = operand.addr or operand.value  
# extract data from pointer 
data = context.read_data(ptr) # as null terminated string
data = context.read_data(ptr, data_type=function_tracing.WIDE_STRING)  # as null terminated wide string
data = context.read_data(ptr, 12)  # as 12 bytes
data = context.read_data(ptr, data_type=function_tracing.DWORD)  # as dword
# etc.

# Extract operand from a different instruction.
operand = context.get_operands(addr - 8)[0]

# Extract pointer from register and read contents from memory.
rbp = context.registers.rbp
stack = context.read_data(rbp, size=0x14)

# Extract the arguments (if a call instruction)
for args in context.get_function_args():
    for i, arg in enumerate(args):
        print("Arg {} -> 0x{:X}".format(i, arg))
        # If arg is a pointer, you can use the context to dereference it.
        value = context.read_data(arg, size=100)
```

*WARNING: `function_tracing` uses the Hex-Rays Decompiler to help get more accurate function signatures for the `get_function_args()`.
You are more likely to get an incorrect number of arguments if it's not available.*


As a shortcut, extracting the operand value or function arguments can be done directly
from the `FunctionTracer` object with a single call.
Both the extracted value and the context are returned.

```python
# (automatically pulls operand.addr or operand.value as appropriate)
context, value = tracer.get_operand_value(addr, 0)

# Get function arguments for a call instruction.
for context, args in tracer.get_function_args(addr):
    for i, arg in enumerate(args):
        print("Arg {} -> 0x{:X}".format(i, arg))
        # If arg is a pointer, you can use the context to dereference it.
        value = context.mem_read(arg, size=100)
```

## Iterating Multiple Paths

If you would like to retrieve the context, operands, or function arguments for all possible code paths we can
use the `iter_context_at()`, `iter_operand_value()` or `iter_function_args()` functions within the
`FunctionTracer` object.

*WARNING: It is possible to retrieve an unmanageable amount of possible code paths. It is recommended to break
out of the for loop as soon as you extracted the data you need.*

```python
# Get context for each possible path.
for context in tracer.iter_context_at(addr):
    # ...
    
# Get operand for each possible path.
for context, value in tracer.iter_operand_value(addr):
    # ...
    
# Get function args for each possible path.
for context, args in tracer.iter_function_args(addr):
    # ...    
```

## Emulating Call Stack

By default, when you request a context, operand, or function argument, the emulation will
start at the top of the function for that tracer. If you would like to have the callers of that
function to also be emulated beforehand you can specify the depth of the call stack using the `depth` parameter.

When used with an `iter*` function, this will cause a context to be created for all possible call stacks
of the specified depth and all possible code paths for each of the call levels.
To use only the first possible code path for each call level, you can set the `exhaustive` parameter
to be `False`.

```python
# Get context for each possible path allowing a call stack of 2 previous callers.
for context in tracer.iter_context_at(addr, depth=2, exhaustive=False):
    # ...
```

This can be useful if you are trying to pull all possible values for a passed in argument or to automatically handle possible wrapper functions.

```python
# Extract all possible null terminated strings passed in as the first argument.
strings = []
for context in tracer.iter_context_at(addr, depth=1):
    # mov     eax, [ebp+arg_0]
    strings.append(context.read_data(context.operands[1].value))
    
# Extract the function arguments for a call, but add depth of 1 to account for a possible wrapper.
context, args = tracer.context_at(addr, depth=1)
```


## Modifying Function Signature

When extracting function arguments, if the disassembler did not correctly determine the number of arguments, we
can adjust the function signature beforehand through a variety of methods:

```python
import idc
from kordesii.utils import function_tracing

call_ea = 0x401049
tracer = function_tracing.get_tracer(call_ea)

# Disassember incorrectly determines the number of arguments, we need to modify the function signature.
context = tracer.context_at(call_ea)
args = context.get_function_args()  # len(args) == 1
```

1. Adjust the function type before tracing by calling `idc.SetType()`
    - This forces the function in the IDB file to permanently contain this new signature if not changed back.
    
    ```python
    idc.SetType(context.operands[0].value, '_BYTE *__cdecl sub_401000(_BYTE *a1, char a2)')
    args = context.get_function_args()  # len(args) == 2
    ```
    
2. Force a specific number of arguments using the `num_args` parameter on `*_function_args()` type functions.
    - This forces any extra arguments that the disassembler doesn't detect as an "int" type.
    - This does not affect the function type within the IDB file.
    
    ```python
    args = context.get_function_args(num_args=2)  # len(args) == 2
    ```
    
3. Use `get_function_signature()` on the context to retreive a `FunctionSignature` object that allows for modifying
    the function signature before argument extraction.
    - Modifications to this signature does not affect the function type within the IDB file.
    - The `FunctionSignature` object also allows for querying each function type, getting their size, and modifying in-place.
    
    ```python
    func_sig = context.get_function_signature()
    func_sig.arg_types = ('_BYTE *', 'char')
    # OR
    func_sig.declaration = '_BYTE *__cdecl sub_401000(_BYTE *a1, char a2)'

    for arg in func_sig.args:
       print('Name: ', arg.name)   
       print('Type: ', arg.type)
       print('Size: ', arg.width)
       print('Value: ', arg.value)
              
       # We can also modify types before extraction to adjust the value that gets returned.
       if arg.idx == 1:
           arg.type = 'DWORD'
                     
    args = [arg.value for arg in func_sig.args]  # len(args) == 2
    ```
   

## Hooking Functions

`function_tracing` emulates the calls to a few common C/C++ library functions (`memmove`, `memcpy`, `strcpy`, etc) to help ensure data moves get emulated correctly. These can be found in [builtin_funcs.py](../kordesii/utils/function_tracing/builtin_funcs.py).

You can also provide your own hooked functions to emulate results and/or report information
for calls to a specific function. To hook a function, either use the `hook()` function directly
on your `FunctionTracer` object or with `function_tracing.hook_tracers()` to hook all
current and future tracers pulled from `get_tracer()`.

The hook function accepts 2 parameters:

1. The name or starting address of the function to hook.
2. A Python function to be called to emulate the function. This function must accept 3 parameters: the current cpu context, the function name, and the passed in function arguments. This function should then return an appropriate return value that will be then set to the `eax` register or `None` if the register should not be changed.
    
    
```python
import base64

# Using function hooking to emulate a base64 algorithm and collect results for reporting.
decoded_strings = []
def func_hook(context, func_name, func_args):
    global decoded_strings
    logger.info('{} was called with: {!r}'.format(func_name, func_args))
    # Base64 decode passed in string and then set it to destination pointer.
    src_ptr, src_size, dst_ptr = func_args
    
    src = context.mem_read(src_ptr, src_size)
    try:
        dst = base64.b64decode(src)
    except TypeError:
        return -1  # emulate error result
    context.mem_write(dst_ptr, dst)
        
    # report string for our own purposes
    decoded_strings.append(dst)
        
    # emulate returned results
    return len(dst)

function_tracing.hook_tracers('Base64Decode', func_hook)  # function start_ea can also be used instead of a name
```

## Pointer History

You can retrieve the history of a pointer across multiple memory copy routines using the `get_pointer_history()`
function on the `ProcessorContext` object. This function returns a list of all previous
pointer locations sorted from earliest to latest.

```python
history = context.get_pointer_history(addr)
for ip, ea in reversed(history):
    print('0x{:x} :: 0x{:x} -> 0x{:x}'.format(ea, addr))
    addr = ea
```


## Variables

As emulation occurs, stack and global variables are recorded in the cpu context which
can then be extracted by the user.

You can view variables that have been encountered during emulation using the `variables` attribute on the context.

```python
# show all encountered variables
print(context.variables.names)
print(context.variables.addrs)

# iterate all the variables encountered during emulation
for var in context.variables:
    print('name = {}'.format(var.name))    # name of variable
    print('address = {}'.format(var.addr))     # address of variable as found in context memory.
    print('location = {}'.format('stack' if var.is_stack else 'global'))  # stack vs global variable
    print('size = {}'.format(var.size))    # size of data variable is pointing to.
    print('data = {}'.format(var.data))    # dereferenced raw data
    print('value = {}'.format(var.value))  # dereferenced variable unpacked based on data type
    print('references = {}'.format(sorted(var.references)))   # instruction addresses that reference this variable

# variables can also be queried just like a dictionary by either name or address
if 'arg_0' in context.variables:
    print(context.variables['arg_0'])

var = context.variables.get(context.sp + 8, None)
if var:
    print(var)
```
