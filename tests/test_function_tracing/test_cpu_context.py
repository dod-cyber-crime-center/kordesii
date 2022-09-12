"""
Tests the ProcessorContext object
"""

import pytest


ENC_DATA = [
    b"Idmmn!Vnsme ",
    b'Vgqv"qvpkle"ukvj"ig{"2z20',
    b"Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-",
    b"Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*",
    b"Dfla%gpwkv%mji`v%lk%rjji%fijqm+",
    b"Egru&ghb&biau&cgen&ngrc&rnc&irnct(",
    b"\\cv}3g{v3pargv3qfg3w|}4g3qavrx3g{v3t\x7fr``=",
    b"C\x7frer7c\x7fr7q{xxs7zve|7~d7cry7~yt\x7frd9",
    b'+()./,-"#*',
    b"`QFBWFsQL@FPPb",
    b"tSUdFS",
    b"\x01\x13\x10n\x0e\x05\x14",
    b'-",5 , v,tr4v,trv4t,v\x7f,ttt',
    b"@AKJDGBA@KJGDBJKAGDC",
    (
        b"!\x1d\x10U\x05\x14\x06\x01U\x02\x1c\x19\x19U\x19\x1a\x1a\x1eU\x17\x07\x1c"
        b"\x12\x1d\x01\x10\x07U\x01\x1a\x18\x1a\x07\x07\x1a\x02["
    ),
    (
        b"4\x16\x05\x04W\x16\x19\x13W\x15\x02\x04\x04\x12\x04W\x04\x03\x16\x1b\x1b"
        b"\x12\x13W\x1e\x19W\x04\x16\x19\x13W\x13\x05\x1e\x11\x03\x04Y"
    ),
    (
        b".\x12\x1fZ\x10\x1b\x19\x11\x1f\x0eZ\x12\x0f\x14\x1dZ\x15\x14Z\x0e\x12\x1f"
        b"Z\x18\x1b\x19\x11Z\x15\x1cZ\x0e\x12\x1fZ\r\x13\x1e\x1fZ\x19\x12\x1b\x13\x08T"
    ),
    b"LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM",
]

DEC_DATA = [
    # address, data, key
    (0x40C000, b'Hello World!', 0x01),
    (0x40C010, b'Test string with key 0x02', 0x02),
    (0x40C02C, b'The quick brown fox jumps over the lazy dog.', 0x03),
    (0x40C05C, b'Oak is strong and also gives shade.', 0x04),
    (0x40C080, b'Acid burns holes in wool cloth.', 0x05),
    (0x40C0A0, b'Cats and dogs each hate the other.', 0x06),
    (0x40C0C4, b"Open the crate but don't break the glass.", 0x13),
    (0x40C0F0, b'There the flood mark is ten inches.', 0x17),
    (0x40C114, b'1234567890', 0x1a),
    (0x40C120, b'CreateProcessA', 0x23),
    (0x40C130, b'StrCat', 0x27),
    (0x40C138, b'ASP.NET', 0x40),
    (0x40C140, b'kdjsfjf0j24r0j240r2j09j222', 0x46),
    (0x40C15C, b'32897412389471982470', 0x73),
    (0x40C174, b'The past will look brighter tomorrow.', 0x75),
    (0x40C19C, b'Cars and busses stalled in sand drifts.', 0x77),
    (0x40C1C4, b'The jacket hung on the back of the wide chair.', 0x7a),
    (0x40C1F8, b'32908741328907498134712304814879837483274809123748913251236598123056231895712', 0x7f),
]


@pytest.mark.in_ida_x86
def test_cpu_context_x86():
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Test on encryption function.
    context = emulator.context_at(0x00401024)

    operands = context.operands
    assert len(operands) == 2

    assert operands[0].text == "[ebp+a1]"
    assert operands[0].value == 0
    # arg_0 should be 8 bytes from stack pointer.
    assert operands[0].addr == context.registers.esp + 8 == context.registers.ebp + 8 == 0x117F804

    assert operands[1].text == "eax"
    assert operands[1].value == context.registers.eax == 1

    # Test variables
    data_ptr = operands[0].addr
    assert sorted(context.variables.names) == ["a1", "a2", "loc_401029"]
    assert data_ptr in context.variables
    var = context.variables[data_ptr]
    assert var.name == "a1"
    assert not var.history
    assert var.size == 4
    assert var.data_type == "dword"
    assert var.data_type_size == 4
    assert var.count == 1
    # test changing the variable
    assert var.data == b"\x00\x00\x00\x00"
    assert var.value == context.operands[0].value == 0
    var.value = 21
    assert var.value == context.operands[0].value == 21
    assert var.data == b"\x15\x00\x00\x00"
    assert context.mem_read(var.addr, 4) == b"\x15\x00\x00\x00"

    # Now execute this instruction and see if a1 has be set with the 1 from eax.
    context.execute(context.ip)
    assert operands[0].value == 1

    # Test getting all possible values passed into arg_0 using depth.
    strings = []
    for context in emulator.iter_context_at(0x00401003, depth=1):
        assert context.ip == 0x00401003
        # mov     eax, [ebp+arg_0]
        strings.append(context.read_data(context.operands[1].value))
    assert strings == ENC_DATA

    # Test pulling arguments from a call.
    context = emulator.context_at(0x0040103A)
    operands = context.operands
    assert len(operands) == 1
    assert operands[0].is_func_ptr
    assert operands[0].value == 0x00401000
    # First, attempt to pull the arguments from the stack without get_function_args()
    first_arg_ptr = context.read_data(context.registers.esp, data_type=function_tracing.DWORD)
    second_arg = context.read_data(context.registers.esp + 4, data_type=function_tracing.BYTE)
    assert context.read_data(first_arg_ptr) == b"Idmmn!Vnsme "
    assert second_arg == 1
    # Now try with get_function_args()
    args = context.get_function_args()
    assert len(args) == 2
    assert context.read_data(args[0]) == b"Idmmn!Vnsme "
    assert args[1] == 1

    assert sorted(context.variables.names) == ["aIdmmnVnsme", "sub_401000"]

    # Test getting context with follow_loops by pulling context at end of xor algorithm.

    # first without follow_loops off to show we get non-decrypted data
    context = emulator.context_at(0x00401029, follow_loops=False, depth=1)
    assert context.passed_in_args[1].value == 0x1  # key
    assert context.read_data(context.passed_in_args[0].value) == b"Idmmn!Vnsme "  # data

    # now with follow_loops on to show we get decrypted data
    context = emulator.context_at(0x00401029, follow_loops=True, depth=1)
    assert context.passed_in_args[1].value == 0x1
    # The way the xor function works is that it takes and MODIFIES the
    # pointer argument passed in, unhelpfully returning a pointer to the end of the
    # decrypted data, not the start, with no way knowing the size...
    # This is obviously a typo when creating strings.exe, but let's just say
    # this is good practice for dealing with some gnarly malware sample :)
    # Therefore, we are going to iteratively decrease the pointer until we find a
    # valid address in the variable map. This variable was the variable used by the caller.
    result = context.registers.eax
    result -= 1
    while result not in context.variables:
        result -= 1
    assert context.read_data(result) == b"Hello World!"

    # Alright, one more time, but with ALL strings.
    # Testing we can successfully decrypt the strings and get the key used.
    strings = []
    for context in emulator.iter_context_at(0x00401029, follow_loops=True, depth=1):
        result = context.registers.eax
        result -= 1
        while result not in context.variables:
            result -= 1
        strings.append((context.read_data(result), context.passed_in_args[1].value))
    assert strings == [(data, key) for _, data, key in DEC_DATA]


@pytest.mark.in_ida_arm
def test_cpu_context_arm():
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Test on encryption function.
    context = emulator.context_at(0x00010420)

    # TODO: Move to test_operands_arm()?
    operands = context.operands
    assert len(operands) == 2

    assert operands[0].text == "R2"
    assert operands[0].value == context.registers.r2 == 1

    assert operands[1].text == "[R11,#var_8]"
    assert operands[1].value == 0
    # var_8 should be 8 bytes from r11 and 4 bytes off sp
    assert operands[1].addr == context.registers.r11 - 8 == context.registers.sp + 4 == 0x117F7F4

    # Test variables
    var_operand = operands[1]
    data_ptr = var_operand.addr
    assert sorted(context.variables.names) == ["loc_10438", "var_8", "var_9"]
    assert data_ptr in context.variables
    var = context.variables[data_ptr]
    assert var.name == "var_8"
    assert not var.history
    assert var.size == 4
    assert var.data_type == "dword"
    assert var.data_type_size == 4
    assert var.count == 1
    # test changing the variable
    assert var.data == b"\x00\x00\x00\x00"
    assert var.value == var_operand.value == 0
    var.value = 21
    assert var.value == var_operand.value == 21
    assert var.data == b"\x15\x00\x00\x00"
    assert context.mem_read(var.addr, 4) == b"\x15\x00\x00\x00"

    # Now execute this instruction and see if a1 has be set with the 1 from R2.
    context.execute(context.ip)
    assert var_operand.value == 1

    # Test getting all possible values passed into arg_0 using depth.
    strings = []
    for context in emulator.iter_context_at(0x10408, depth=1):
        assert context.ip == 0x10408
        # STR     R0, [R11,#var_8]
        strings.append(context.read_data(context.operands[0].value))
    assert strings == ENC_DATA

    # Test pulling arguments from a call.
    context = emulator.context_at(0x1046C)
    operands = context.operands
    assert len(operands) == 1
    assert operands[0].is_func_ptr
    assert operands[0].value == 0x103FC
    # First, attempt to pull the arguments from the registers without get_function_args()
    first_arg_ptr = context.registers.r0
    second_arg = context.registers.r1
    assert context.read_data(first_arg_ptr) == b"Idmmn!Vnsme "
    assert second_arg == 1
    # Now try with get_function_args()
    args = context.get_function_args()
    assert len(args) == 2
    assert context.read_data(args[0]) == b"Idmmn!Vnsme "
    assert args[1] == 1

    # TODO: off_10544 is a pointer to the strings01 address
    assert sorted(context.variables.names) == ["encrypt", "off_10544"]

    # Test getting context with follow_loops by pulling context at end of xor algorithm.

    # first without follow_loops off to show we get non-decrypted data
    context = emulator.context_at(0x10454, follow_loops=False, depth=1)
    assert context.passed_in_args[1].value == 0x1  # key
    assert context.read_data(context.passed_in_args[0].value) == b"Idmmn!Vnsme "  # data

    # now with follow_loops on to show we get decrypted data
    context = emulator.context_at(0x10454, follow_loops=True, depth=1)
    # The compiler reuses register r0, but then saves the register in the stack (var_9).
    # Therefore, attempting to use context.passed_in_args will produce garbage, because it is not aware of the reuse.
    # So lets pull from "var_9" where it saved it instead.
    assert context.passed_in_args[1].value != 0x1
    assert context.variables["var_9"].value == b"\x01"
    # Luckily, the compiler does not mess with the original first argument.
    assert context.read_data(context.passed_in_args[0].value) == b"Hello World!"

    # Alright, one more time, but with ALL strings.
    # Testing we can successfully decrypt the strings and get the key used.
    strings = []
    for context in emulator.iter_context_at(0x10454, follow_loops=True, depth=1):
        key = ord(context.variables["var_9"].value)
        result = context.read_data(context.passed_in_args[0].value)
        strings.append((result, key))
    assert strings == [(data, key) for _, data, key in DEC_DATA]


@pytest.mark.in_ida_x86
@pytest.mark.in_ida_arm
def test_builtin_funcs():
    """Tests the emulated builtin_funcs."""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing.call_hooks import stdlib

    emulator = function_tracing.Emulator()
    assert emulator.arch in ["metapc", "ARM"]

    src = 0x123000
    dst = 0x124000

    # test strcat
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello")
    assert stdlib.builtin_funcs.strcat(context, "strcat", [dst, src]) == dst
    assert context.read_data(dst) == b"helloworld"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello".encode(encoding))
        assert stdlib.builtin_funcs.strcat(context, "wcscat", [dst, src]) == dst
        assert context.read_data(dst, data_type=function_tracing.WIDE_STRING) == u"helloworld".encode(encoding)

    # test strncat
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello")
    assert stdlib.builtin_funcs.strncat(context, "strncat", [dst, src, 10]) == dst
    assert context.read_data(dst) == b"helloworld"
    assert stdlib.builtin_funcs.strncat(context, "strncat", [dst, src, 2]) == dst
    assert context.read_data(dst) == b"helloworldwo"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello".encode(encoding))
        assert stdlib.builtin_funcs.strncat(context, "wcsncat", [dst, src, 10]) == dst
        assert context.read_data(dst, data_type=function_tracing.WIDE_STRING) == u"helloworld".encode(encoding)
        assert stdlib.builtin_funcs.strncat(context, "wcsncat", [dst, src, 2]) == dst
        assert context.read_data(dst, data_type=function_tracing.WIDE_STRING) == u"helloworldwo".encode(encoding)

    # test strcpy
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello!!!")
    assert stdlib.builtin_funcs.strcpy(context, "strcpy", [dst, src]) == dst
    assert context.read_data(dst) == b"world"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello!!!".encode(encoding))
        assert stdlib.builtin_funcs.strcpy(context, "wcscpy", [dst, src]) == dst
        assert context.read_data(dst, data_type=function_tracing.WIDE_STRING) == u"world".encode(encoding)

    # test strncpy
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello!!!")
    assert stdlib.builtin_funcs.strncpy(context, "strncpy", [dst, src, 2]) == dst
    # Since we are only copying 2 characters over, the null doesn't get sent over and therefore get
    # some of the original string in the copy.
    assert context.read_data(dst) == b"wollo!!!"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello!!!".encode(encoding))
        assert stdlib.builtin_funcs.strncpy(context, "wcsncpy", [dst, src, 2]) == dst
        assert context.read_data(dst, data_type=function_tracing.WIDE_STRING) == u"wollo!!!".encode(encoding)

    # test strdup/strndup
    heap_ptr = context.memory.HEAP_BASE
    context = emulator.new_context()
    context.memory.write(src, b"hello")
    # should return a newly allocated string
    assert stdlib.builtin_funcs.strdup(context, "strdup", [src]) == heap_ptr
    assert context.read_data(heap_ptr) == b"hello"
    context = emulator.new_context()
    context.memory.write(src, b"hello")
    assert stdlib.builtin_funcs.strndup(context, "strndup", [src, 2]) == heap_ptr
    assert context.read_data(heap_ptr) == b"he"

    # test strlen
    context = emulator.new_context()
    context.memory.write(src, b"hello")
    assert stdlib.builtin_funcs.strlen(context, "strlen", [src]) == 5
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"hello".encode(encoding))
        assert stdlib.builtin_funcs.strlen(context, "wcslen", [src]) == 5


@pytest.mark.in_ida
def test_function_signature():
    """Tests FunctionSignature object."""
    import idc
    from kordesii import utils
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    xor_func_ea = 0x00401000

    # Basic tests.
    context = emulator.context_at(xor_func_ea)
    func_sig = context.get_function_signature(func_ea=xor_func_ea)
    assert func_sig.declaration == "_BYTE *__cdecl sub_401000(_BYTE *a1, char a2);"
    assert func_sig.arg_types == ("_BYTE * a1", "char a2")
    args = func_sig.args
    assert len(args) == 2
    assert args[0].name == "a1"
    assert args[0].type == "_BYTE *"
    assert args[0].value == 0
    assert args[1].name == "a2"
    assert args[1].type == "char"
    assert args[1].value == 0

    # Test that we can manipulate signature.
    func_sig.arg_types += ("int new_arg",)
    assert func_sig.declaration == "_BYTE *__cdecl sub_401000(_BYTE *a1, char a2, int new_arg);"
    args = func_sig.args
    assert len(args) == 3
    assert args[2].name == "new_arg"
    assert args[2].type == "int"
    assert args[2].value == 0

    # Now test using iter_function_args

    # First force an incorrect number of arguments.
    idc.SetType(xor_func_ea, " _BYTE *__cdecl sub_401000(_BYTE *a1)")
    func = utils.Function(xor_func_ea)

    # Then test we can force 2 arguments anyway.
    results = []
    for ea in func.calls_to:
        for context in emulator.iter_context_at(ea):
            # The function signature only gives 1 argument now.
            func_sig = context.get_function_signature()
            assert len(func_sig.args) == 1
            # But we force 2.
            args = context.get_function_args(num_args=2)
            assert len(args) == 2
            results.append(args)
    assert results == [
        [4243456, 1],
        [4243472, 2],
        [4243500, 3],
        [4243548, 4],
        [4243584, 5],
        [4243616, 6],
        [4243652, 19],
        [4243696, 23],
        [4243732, 26],
        [4243744, 35],
        [4243760, 39],
        [4243768, 64],
        [4243776, 70],
        [4243804, 115],
        [4243828, 117],
        [4243868, 119],
        [4243908, 122],
        [4243960, 127],
    ]

    # Test that we can force function signatures.
    with pytest.raises(RuntimeError):
        context.get_function_args(0xFFF)
    with pytest.raises(RuntimeError):
        context.get_function_signature(0xFFF)
    assert len(context.get_function_args(0xFFF, num_args=3)) == 3
    func_sig = context.get_function_signature(0xFFF, force=True)
    assert func_sig.declaration == 'int __cdecl no_name();'


@pytest.mark.in_ida_x86
def test_function_arg():
    """Tests FunctionArg object."""
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    xor_func_ea = 0x00401000
    xor_func_call = 0x0040103A

    # Basic tests.
    context = emulator.context_at(xor_func_call)
    args = context.get_function_arg_objects()
    assert len(args) == 2
    assert args[0].name == "a1"
    assert args[0].type == "_BYTE *"
    assert args[0].value == 0x0040C000  # pointer to b'Idmmn!Vnsme '
    assert args[0].addr == context.sp + 0
    assert args[1].name == "a2"
    assert args[1].type == "char"
    assert args[1].value == 1  # key
    assert args[1].addr == context.sp + 4
    # Test that we can change the values.
    args[0].value = 0xffff
    assert args[0].value == 0xffff
    assert args[0].addr == context.sp + 0
    assert context.read_data(args[0].addr, 4) == b'\xff\xff\x00\x00'

    # Test pulling in passed in arguments.
    context = emulator.context_at(0x00401011)  # somewhere randomly in the xor function
    args = context.passed_in_args
    assert args[0].name == "a1"
    assert args[0].type == "_BYTE *"
    assert args[0].value == 0
    assert args[0].addr == context.sp + 0x08  # +8 to account for pushed in return address and ebp
    assert args[1].name == "a2"
    assert args[1].type == "char"
    assert args[1].value == 0
    assert args[1].addr == context.sp + 0x0C


@pytest.mark.in_ida_arm
def test_function_arg_arm():
    """Tests FunctionArg object."""
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    xor_func_ea = 0x104FC
    xor_func_call = 0x1046C

    # Basic tests.
    context = emulator.context_at(xor_func_call)
    args = context.get_function_arg_objects()
    assert len(args) == 2
    assert args[0].name == "result"
    assert args[0].type == "_BYTE *"
    assert args[0].value == context.registers.r0 == 0x21028  # pointer to b'Idmmn!Vnsme '
    assert args[0].addr is None  # register arguments don't have an address.
    assert args[1].name == "a2"
    assert args[1].type == "char"
    assert args[1].value == context.registers.r1 == 1  # key
    assert args[1].addr is None
    # Test that we can change the values.
    args[0].value = 0xffff
    assert args[0].value == context.registers.r0 == 0xffff
    assert args[0].addr is None

    # Test pulling in passed in arguments.
    context = emulator.context_at(0x1042C)  # somewhere randomly in the xor function
    args = context.passed_in_args
    assert args[0].name == "result"
    assert args[0].type == "_BYTE *"
    assert args[0].value == context.registers.r0 == 0
    assert args[0].addr is None
    assert args[1].name == "a2"
    assert args[1].type == "char"
    assert args[1].value == context.registers.r1 == 0
    assert args[1].addr is None


@pytest.mark.in_ida_x86
@pytest.mark.in_ida_arm
def test_func_emulate():
    """Tests full function emulation in Emulator.create_emulated."""
    from kordesii.utils import function_tracing, is_x86_64

    emulator = function_tracing.Emulator()

    if is_x86_64():
        xor_func_ea = 0x00401000
        enc_data_ptr = 0x0040C000  # pointer to b'Idmmn!Vnsme '
    else:
        xor_func_ea = 0x000103FC
        enc_data_ptr = 0x00021028
    xor_decrypt = emulator.create_emulated(xor_func_ea)

    # Test decrypting a string in memory.
    context = emulator.new_context()
    ret = xor_decrypt(enc_data_ptr, 1, context=context)
    # TODO: The encrypt() function we are emulating doesn't actually return anything.
    #   This originally worked because the x86 sample would use eax to store the length anyway.
    #   This is not the case for ARM.
    #   Update strings.c and compiled samples to have the encrypt() function return the length?
    #   (or create another sample entirely)
    # assert ret == enc_data_ptr + len(b'Idmmn!Vnsme ')  # function returns pointer after decryption.
    assert context.read_data(enc_data_ptr) == b'Hello World!'

    # Test decrypting a string that was never in the sample.
    enc_data = b"!; '0607!)"
    context = emulator.new_context()
    ptr = context.mem_alloc(len(enc_data))
    context.mem_write(ptr, enc_data)
    xor_decrypt(ptr, 0x42, context=context)
    assert context.read_data(ptr) == b'cybertruck'


@pytest.mark.in_ida_x86
@pytest.mark.in_ida_arm
def test_function_hooking():
    """Tests function hooking mechanism."""
    from kordesii.utils import function_tracing, is_x86_64

    emulator = function_tracing.Emulator()

    if is_x86_64():
        xor_func_ea = 0x00401000
        end_ea = 0x00401141  # address in caller after all xor functions have been called.
        expected_args = [
            [0x40c000, 0x1],
            [0x40c010, 0x2],
            [0x40c02c, 0x3],
            [0x40c05c, 0x4],
            [0x40c080, 0x5],
            [0x40c0a0, 0x6],
            [0x40c0c4, 0x13],
            [0x40c0f0, 0x17],
            [0x40c114, 0x1a],
            [0x40c120, 0x23],
            [0x40c130, 0x27],
            [0x40c138, 0x40],
            [0x40c140, 0x46],
            [0x40c15c, 0x73],
            [0x40c174, 0x75],
            [0x40c19c, 0x77],
            [0x40c1c4, 0x7a],
            [0x40c1f8, 0x7f],
        ]
    else:
        xor_func_ea = 0x000103FC
        end_ea = 0x00010540
        expected_args = [
            [0x21028, 0x1],
            [0x21038, 0x2],
            [0x21054, 0x3],
            [0x21084, 0x4],
            [0x210A8, 0x5],
            [0x210C8, 0x6],
            [0x210EC, 0x13],
            [0x21118, 0x17],
            [0x2113C, 0x1a],
            [0x21148, 0x23],
            [0x21158, 0x27],
            [0x21160, 0x40],
            [0x21168, 0x46],
            [0x21184, 0x73],
            [0x2119C, 0x75],
            [0x211C4, 0x77],
            [0x211EC, 0x7a],
            [0x2121C, 0x7f],
        ]

    args = []
    # First test hooking with standard function.
    def xor_hook(context, func_name, func_args):
        args.append(func_args)
    emulator.hook_call(xor_func_ea, xor_hook)
    context = emulator.context_at(end_ea)
    assert args == expected_args
    assert [_args for _, _args in context.get_call_history(xor_func_ea)] == expected_args

    # Now test with the function emulated to see our data getting decrypted.
    emulator.reset_hooks()
    emulator.emulate_call(xor_func_ea)
    context = emulator.context_at(end_ea)
    assert [_args for _, _args in context.get_call_history(xor_func_ea)] == expected_args
    strings = [(context.read_data(args[0]), args[1]) for _, args in context.get_call_history(xor_func_ea)]
    assert strings == [(data, key) for _, data, key in DEC_DATA]


@pytest.mark.in_ida_x86
def test_instruction_hooking_x86():
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Test hooking all "push" instructions, which will be the parameters to the xor decryption.
    pushes = []
    def push_hook(context, instruction):
        pushes.append(instruction.operands[0].value)
    emulator.hook_instruction("push", push_hook)
    context = emulator.context_at(0x00401142)
    # fmt: off
    assert pushes == [
        0x117fc00,  # ebp pushed
        # key, enc_data_ptr
        0x1, 0x40c000,
        0x2, 0x40c010,
        0x3, 0x40c02c,
        0x4, 0x40c05c,
        0x5, 0x40c080,
        0x6, 0x40c0a0,
        0x13, 0x40c0c4,
        0x17, 0x40c0f0,
        0x1a, 0x40c114,
        0x23, 0x40c120,
        0x27, 0x40c130,
        0x40, 0x40c138,
        0x46, 0x40c140,
        0x73, 0x40c15c,
        0x75, 0x40c174,
        0x77, 0x40c19c,
        0x7a, 0x40c1c4,
        0x7f, 0x40c1f8,
    ]
    # fmt: on


@pytest.mark.in_ida_x86
def test_opcode_hooking():
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing import utils

    emulator = function_tracing.Emulator()

    # Test hooking all "push" instructions.
    pushes = []
    def push(context, instruction):
        operand = instruction.operands[0]
        value_bytes = utils.struct_pack(operand.value, width=operand.width)
        context.sp -= context.byteness
        context.memory.write(context.sp, value_bytes)
        pushes.append(operand.value)  # record for testing

    emulator.hook_opcode("push", push)

    context = emulator.context_at(0x00401142)
    # fmt: off
    assert pushes == [
        0x117fc00,  # ebp pushed
        # key, enc_data_ptr
        0x1, 0x40c000,
        0x2, 0x40c010,
        0x3, 0x40c02c,
        0x4, 0x40c05c,
        0x5, 0x40c080,
        0x6, 0x40c0a0,
        0x13, 0x40c0c4,
        0x17, 0x40c0f0,
        0x1a, 0x40c114,
        0x23, 0x40c120,
        0x27, 0x40c130,
        0x40, 0x40c138,
        0x46, 0x40c140,
        0x73, 0x40c15c,
        0x75, 0x40c174,
        0x77, 0x40c19c,
        0x7a, 0x40c1c4,
        0x7f, 0x40c1f8,
    ]
    # fmt: on


@pytest.mark.in_ida_arm
def test_instruction_hooking_arm():
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Test hooking all LDR instructions, which will be the encrypted string pointers.
    ldrs = []
    def ldr_hook(context, instruction):
        ldrs.append(instruction.operands[1].value)
    emulator.hook_instruction("ldr", ldr_hook)
    emulator.context_at(0x10540)
    # fmt: off
    assert ldrs == [
        0x21028,
        0x21038,
        0x21054,
        0x21084,
        0x210A8,
        0x210C8,
        0x210EC,
        0x21118,
        0x2113C,
        0x21148,
        0x21158,
        0x21160,
        0x21168,
        0x21184,
        0x2119C,
        0x211C4,
        0x211EC,
        0x2121C,
    ]
    # fmt: on


@pytest.mark.in_ida
def test_context_depth():
    """Tests depth feature in iter_context_at()"""
    from kordesii import utils
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    ea = 0x00405901  # Address in function that contains multiple paths.
    num_paths_first_depth = 3
    num_paths_second_depth = 25

    # First ensure paths are calculated correctly.
    flowchart = utils.Flowchart(ea)
    block = flowchart.find_block(ea)
    assert len(list(block.paths())) == num_paths_first_depth

    func = utils.Function(ea)
    call_eas = list(func.calls_to)
    assert len(call_eas) == 1
    call_ea = call_eas[0]
    flowchart = utils.Flowchart(call_ea)
    block = flowchart.find_block(call_ea)
    assert len(list(block.paths())) == num_paths_second_depth

    # Now show that we get the correct number of contexts based on depth and other parameters.

    # Test getting contexts for only the first depth.
    ctxs = list(emulator.iter_context_at(ea))
    assert len(ctxs) == num_paths_first_depth
    # (exhaustive has no affect on final call level)
    ctxs = list(emulator.iter_context_at(ea, exhaustive=False))
    assert len(ctxs) == num_paths_first_depth

    # Test getting contexts with 2 depths.
    ctxs = list(emulator.iter_context_at(ea, depth=1))
    assert len(ctxs) == num_paths_first_depth * num_paths_second_depth
    ctxs = list(emulator.iter_context_at(ea, depth=1, exhaustive=False))
    assert len(ctxs) == num_paths_first_depth


@pytest.mark.in_ida
def test_objects_and_actions():
    """Test the objects and actions feature."""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing import actions, objects

    emulator = function_tracing.Emulator()

    # NOTE: We are just going to fake adding actions since our strings.exe example
    # doesn't perform any actions.
    offset = 0x1234
    ctx = emulator.new_context()
    ctx.ip = offset
    assert not ctx.actions
    handle = ctx.objects.alloc()
    assert handle == 0x80
    ctx.actions.add(actions.FileOpened(ip=offset-3, handle=handle, path=r"C:\dummy\path", mode="w"))
    ctx.actions.add(actions.FileWritten(ip=offset-2, handle=handle, data=b"first bytes\n"))
    # Throw in some other random actions for good measure.
    ctx.actions.add(actions.CommandExecuted(ip=offset-6, command="hello"))
    ctx.actions.add(actions.FileWritten(ip=offset-1, handle=handle, data=b"second bytes"))
    assert ctx.objects
    assert len(ctx.objects) == 1
    assert ctx.objects.handles == [handle]
    file_obj = ctx.objects[handle]
    assert file_obj
    assert file_obj.handle == handle
    assert isinstance(file_obj, objects.File)
    assert file_obj.path == r"C:\dummy\path"
    assert file_obj.mode == "w"
    assert file_obj.data == b"first bytes\nsecond bytes"
    assert file_obj.closed is False
    assert file_obj.references == [offset-3, offset-2, offset-1]

    # Now test if we can detect when the right file is closed.
    # NOTE: We have to regrab the object for changes to take affect.
    sec_handle = ctx.objects.alloc()
    ctx.actions.add(actions.FileClosed(ip=offset, handle=sec_handle))
    assert len(ctx.objects) == 2
    assert ctx.objects[handle].closed is False
    ctx.actions.add(actions.FileClosed(ip=offset, handle=handle))
    assert ctx.objects[handle].closed is True
    assert ctx.objects.handles == [handle, sec_handle]


@pytest.mark.in_ida
def test_call_depth_basic_x86():
    """
    Low level test for ProcessorContext._execute_call()
    """
    import idc
    from kordesii.utils import function_tracing
    emulator = function_tracing.Emulator()

    # Emulate up to the sub_401000 call
    ctx = emulator.context_at(0x0040103A)
    ptr = ctx.function_args[0].value
    ctx._call_depth = 1

    # Push return address on the stack and set the ip to the function's start address.
    # (Doing this manually, because we aren't emulating the 'call' opcode in this method.)
    ctx.sp -= ctx.byteness
    ret_addr = idc.next_head(ctx.instruction.ip)
    ctx.memory.write(ctx.sp, ret_addr.to_bytes(ctx.byteness, "little"))

    # Execute the call to sub_401000 (the decrypt function)
    ctx._execute_call("sub_401000", 0x401000)
    assert ctx.read_data(ptr) == b"Hello World!"


@pytest.mark.in_ida
def test_call_depth_x86():
    """
    High level test for emulating function calls during emulation.
    """
    from kordesii.utils import function_tracing, Function
    emulator = function_tracing.Emulator()

    data_ptr = 0x40C000

    # Test with context_at()
    ctx = emulator.context_at(0x40103F, call_depth=1)
    assert ctx.read_data(data_ptr) == b"Hello World!"
    ctx = emulator.context_at(0x401142, call_depth=1)
    assert [ctx.read_data(ptr) for ptr, _, _ in DEC_DATA] == [data for _, data, _ in DEC_DATA]

    # Test with direct ctx.execute() call.
    ctx = emulator.new_context()
    func = Function(0x401030)
    ctx.execute(start=func.start_ea, end=func.end_ea, call_depth=1)
    assert [ctx.read_data(ptr) for ptr, _, _ in DEC_DATA] == [data for _, data, _ in DEC_DATA]


@pytest.mark.in_ida
def test_execute_function_x86():
    """
    Tests the Emulator.execute_function()
    """
    from kordesii.utils import function_tracing
    emulator = function_tracing.Emulator()
    # Test with emulating the full function.
    ctx = emulator.execute_function(0x401030, call_depth=1)
    assert ctx.read_data(0x40C000) == b"Hello World!"
    assert [ctx.read_data(ptr) for ptr, _, _ in DEC_DATA] == [data for _, data, _ in DEC_DATA]


@pytest.mark.in_ida
def test_execute_function_printf_x86():
    """
    Tests running the full main function which contains printf's so we can also test
    if stdout is written correctly.
    """
    from kordesii.utils import function_tracing
    emulator = function_tracing.Emulator()
    ctx = emulator.execute_function(0x401150, call_depth=3)  # main function
    assert ctx.stdout == """\
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
"""
