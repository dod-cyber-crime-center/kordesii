from textwrap import dedent

import pytest


@pytest.mark.in_ida
def test_flowchart():
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Test on simple 1 block function.
    flowchart = function_tracing.Flowchart(0x004011AA)
    blocks = list(flowchart.blocks())
    assert len(blocks) == 1
    block = blocks[0]
    assert block.start_ea == 0x00401150
    assert block.end_ea == 0x004012A0
    assert list(block.heads()) == (
        [0x00401150, 0x00401151, 0x00401153, 0x00401158, 0x0040115D, 0x00401162, 0x00401167]
        + [0x0040116A, 0x0040116F, 0x00401174, 0x00401179, 0x0040117C, 0x00401181, 0x00401186]
        + [0x0040118B, 0x0040118E, 0x00401193, 0x00401198, 0x0040119D, 0x004011A0, 0x004011A5]
        + [0x004011AA, 0x004011AF, 0x004011B2, 0x004011B7, 0x004011BC, 0x004011C1, 0x004011C4]
        + [0x004011C9, 0x004011CE, 0x004011D3, 0x004011D6, 0x004011DB, 0x004011E0, 0x004011E5]
        + [0x004011E8, 0x004011ED, 0x004011F2, 0x004011F7, 0x004011FA, 0x004011FF, 0x00401204]
        + [0x00401209, 0x0040120C, 0x00401211, 0x00401216, 0x0040121B, 0x0040121E, 0x00401223]
        + [0x00401228, 0x0040122D, 0x00401230, 0x00401235, 0x0040123A, 0x0040123F, 0x00401242]
        + [0x00401247, 0x0040124C, 0x00401251, 0x00401254, 0x00401259, 0x0040125E, 0x00401263]
        + [0x00401266, 0x0040126B, 0x00401270, 0x00401275, 0x00401278, 0x0040127D, 0x00401282]
        + [0x00401287, 0x0040128A, 0x0040128F, 0x00401294, 0x00401299, 0x0040129C, 0x0040129E]
        + [0x0040129F]
    )
    # Ensure we create a path of just the 1 block.
    path_blocks = list(flowchart.get_paths(0x004011AA))
    assert len(path_blocks) == 1
    path_block = path_blocks[0]
    assert path_block.path() == [path_block]
    # Ensure cpu context gets created correctly.
    cpu_context = path_block.cpu_context(init_context=emulator.new_context())
    assert cpu_context.ip == block.end_ea
    cpu_context = path_block.cpu_context(0x0040115D, init_context=emulator.new_context())
    assert cpu_context.ip == 0x0040115D

    # Test read_data()
    data_ptr = cpu_context.read_data(cpu_context.registers.esp, data_type=function_tracing.DWORD)
    assert cpu_context.read_data(data_ptr) == b"Idmmn!Vnsme "
    # Test write_data()
    cpu_context.write_data(cpu_context.registers.esp, data_ptr + 3, data_type=function_tracing.DWORD)
    data_ptr = cpu_context.read_data(cpu_context.registers.esp, data_type=function_tracing.DWORD)
    assert cpu_context.read_data(data_ptr) == b"mn!Vnsme "

    # Test on slightly more complex function with 5 blocks
    flowchart = function_tracing.Flowchart(0x004035BB)

    found_block = flowchart.find_block(0x004035AD)
    assert found_block
    assert found_block.start_ea == 0x004035AB

    blocks = list(flowchart.blocks(start=0x004035AB, reverse=True))
    assert len(blocks) == 2
    assert [(block.start_ea, block.end_ea) for block in blocks] == [(0x004035AB, 0x004035B1), (0x00403597, 0x004035AB)]

    blocks = list(flowchart.blocks(start=0x004035AB))
    assert len(blocks) == 4
    assert [(block.start_ea, block.end_ea) for block in blocks] == [
        (0x004035AB, 0x004035B1),
        (0x004035BA, 0x004035BD),
        (0x004035B1, 0x004035B3),
        (0x004035B3, 0x004035BA),
    ]

    blocks = list(flowchart.blocks())
    assert len(blocks) == 5
    assert [(block.start_ea, block.end_ea) for block in blocks] == [
        (0x00403597, 0x004035AB),
        (0x004035AB, 0x004035B1),
        (0x004035BA, 0x004035BD),
        (0x004035B1, 0x004035B3),
        (0x004035B3, 0x004035BA),
    ]
    blocks = list(flowchart.blocks(reverse=True))
    assert len(blocks) == 5
    assert [(block.start_ea, block.end_ea) for block in blocks] == [
        (0x004035BA, 0x004035BD),
        (0x004035B3, 0x004035BA),
        (0x00403597, 0x004035AB),
        (0x004035B1, 0x004035B3),
        (0x004035AB, 0x004035B1),
    ]
    blocks = list(flowchart.blocks(dfs=True))
    assert len(blocks) == 5
    assert [(block.start_ea, block.end_ea) for block in blocks] == [
        (0x00403597, 0x004035AB),
        (0x004035AB, 0x004035B1),
        (0x004035B1, 0x004035B3),
        (0x004035B3, 0x004035BA),
        (0x004035BA, 0x004035BD),
    ]
    blocks = list(flowchart.blocks(reverse=True, dfs=True))
    assert len(blocks) == 5
    assert [(block.start_ea, block.end_ea) for block in blocks] == [
        (0x004035BA, 0x004035BD),
        (0x004035B3, 0x004035BA),
        (0x004035B1, 0x004035B3),
        (0x004035AB, 0x004035B1),
        (0x00403597, 0x004035AB),
    ]

    path_blocks = list(flowchart.get_paths(0x004035B1))
    assert len(path_blocks) == 1
    assert [path_block.bb.start_ea for path_block in path_blocks[0].path()] == [0x00403597, 0x004035AB, 0x004035B1]

    path_blocks = list(flowchart.get_paths(0x004035BC))
    assert len(path_blocks) == 3
    assert sorted([_path_block.bb.start_ea for _path_block in path_block.path()] for path_block in path_blocks) == [
        [0x00403597, 0x004035AB, 0x004035B1, 0x004035B3, 0x004035BA],
        [0x00403597, 0x004035AB, 0x004035B3, 0x004035BA],
        [0x00403597, 0x004035BA],
    ]


@pytest.mark.in_ida
def test_basic_blocks():
    """Tests functionality of our custom BasicBlock"""
    from kordesii.utils import function_tracing

    flowchart = function_tracing.Flowchart(0x004035BB)

    # region Test getting ancestors

    # test first block
    block = flowchart.find_block(0x403597)
    ancestors = block.ancestors()
    assert sorted(b.start_ea for b in ancestors) == []

    # test block in the middle with a loop
    block = flowchart.find_block(0x004035B1)
    ancestors = block.ancestors()
    assert sorted(b.start_ea for b in ancestors) == [
        0x403597,
        0x4035ab,
        0x4035b3,  # loop back
    ]

    # test very last block
    block = flowchart.find_block(0x004035BB)
    ancestors = block.ancestors()
    assert sorted(b.start_ea for b in ancestors) == [
        0x403597,
        0x4035ab,
        0x4035b1,
        0x4035b3,
    ]

    # endregion


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
    assert strings == [
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
    assert strings == [
        (b'Hello World!', 0x01),
        (b'Test string with key 0x02', 0x02),
        (b'The quick brown fox jumps over the lazy dog.', 0x03),
        (b'Oak is strong and also gives shade.', 0x04),
        (b'Acid burns holes in wool cloth.', 0x05),
        (b'Cats and dogs each hate the other.', 0x06),
        (b"Open the crate but don't break the glass.", 0x13),
        (b'There the flood mark is ten inches.', 0x17),
        (b'1234567890', 0x1a),
        (b'CreateProcessA', 0x23),
        (b'StrCat', 0x27),
        (b'ASP.NET', 0x40),
        (b'kdjsfjf0j24r0j240r2j09j222', 0x46),
        (b'32897412389471982470', 0x73),
        (b'The past will look brighter tomorrow.', 0x75),
        (b'Cars and busses stalled in sand drifts.', 0x77),
        (b'The jacket hung on the back of the wide chair.', 0x7a),
        (b'32908741328907498134712304814879837483274809123748913251236598123056231895712', 0x7f),
    ]


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
    assert strings == [
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
    assert strings == [
        (b'Hello World!', 0x01),
        (b'Test string with key 0x02', 0x02),
        (b'The quick brown fox jumps over the lazy dog.', 0x03),
        (b'Oak is strong and also gives shade.', 0x04),
        (b'Acid burns holes in wool cloth.', 0x05),
        (b'Cats and dogs each hate the other.', 0x06),
        (b"Open the crate but don't break the glass.", 0x13),
        (b'There the flood mark is ten inches.', 0x17),
        (b'1234567890', 0x1a),
        (b'CreateProcessA', 0x23),
        (b'StrCat', 0x27),
        (b'ASP.NET', 0x40),
        (b'kdjsfjf0j24r0j240r2j09j222', 0x46),
        (b'32897412389471982470', 0x73),
        (b'The past will look brighter tomorrow.', 0x75),
        (b'Cars and busses stalled in sand drifts.', 0x77),
        (b'The jacket hung on the back of the wide chair.', 0x7a),
        (b'32908741328907498134712304814879837483274809123748913251236598123056231895712', 0x7f),
    ]


@pytest.mark.in_ida
def test_memory():
    """Tests the memory controller."""
    from kordesii.utils.function_tracing.memory import Memory

    m = Memory()

    # basic test
    assert m.read(0x00121000, 10) == b"\x00" * 10

    # test reading across pages
    m.write(0x00121FFB, b"helloworld")
    assert m.read(0x00121FFB, 10) == b"helloworld"
    assert m.read(0x00121FFB + 10, 10) == b"\x00" * 10
    assert m.read(0x00121FFB + 5, 10) == b"world" + b"\x00" * 5

    # test reading segment data
    assert m.read(0x0040C000, 11) == b"Idmmn!Vnsme"
    assert m.read(0x00401150, 3) == b"\x55\x8B\xEC"

    # test str print
    assert str(m) == dedent(
        """\
        Base Address             Address Range            Size
        0x00121000               0x00121000 - 0x00123000  8192
        0x00401000               0x00401000 - 0x0040F000  57344
    """
    )

    # test searching
    assert m.find(b"helloworld", start=0x0011050) == 0x00121FFB
    assert m.find(b"helloworld") == 0x00121FFB
    assert m.find(b"helloworld", start=0x00121FFC) == -1
    assert m.find(b"helloworld", end=0x10) == -1
    assert m.find(b"helloworld", start=0x0011050, end=0x00121FFB) == -1
    assert m.find(b"helloworld", start=0x0011050, end=0x00122000) == -1
    assert m.find(b"helloworld", start=0x0011050, end=0x00122100) == 0x00121FFB
    assert m.find(b"`QFBWF") == 0x0040C120
    assert m.find(b"Idmmn!Vnsme") == 0x0040C000
    assert m.find_in_segment(b"Idmmn!Vnsme", ".data") == 0x0040C000
    assert m.find_in_segment(b"Idmmn!Vnsme", ".text") == -1
    assert m.find(b"\x5F\x5E\xC3", start=0x004035BD) == 0x004035E0

    # test bugfix when searching single length characters
    assert m.find(b"h", start=0x0011050) == 0x00121FFB
    assert m.find(b"h", start=0x0011050, end=0x00121FFB) == -1
    assert m.find(b"h", start=0x0011050, end=0x00121FFB + 1) == 0x00121FFB
    assert m.find(b"o", start=0x0011050) == 0x00121FFB + 4

    # tests allocations
    first_alloc_ea = m.alloc(10)
    assert first_alloc_ea == m.HEAP_BASE
    second_alloc_ea = m.alloc(20)
    assert second_alloc_ea == m.HEAP_BASE + 10 + m.HEAP_SLACK
    m.write(second_alloc_ea, b"im in the heap!")
    assert m.read(second_alloc_ea, 15) == b"im in the heap!"
    assert m.find_in_heap(b"the heap!") == second_alloc_ea + 6
    m.write(second_alloc_ea, b"helloworld")
    assert m.find_in_heap(b"helloworld") == second_alloc_ea

    # tests reallocations
    assert m.realloc(first_alloc_ea, 40) == first_alloc_ea  # no relocation
    assert m.realloc(first_alloc_ea, m.PAGE_SIZE * 5) == second_alloc_ea + 20 + m.HEAP_SLACK  # relocation
    assert m.realloc(second_alloc_ea, 40) == second_alloc_ea  # no relocation
    second_alloc_realloced_ea = m.realloc(second_alloc_ea, m.PAGE_SIZE * 6)
    assert second_alloc_realloced_ea != second_alloc_ea
    assert m.read(second_alloc_realloced_ea, 10) == b"helloworld"  # data should be copied over.


@pytest.mark.in_ida
def test_registers():
    """Tests registers"""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing.cpu_context import ProcessorContext
    from kordesii.utils.function_tracing.registers import Register

    # Basic register tests.
    reg = Register(8, rax=0xFFFFFFFFFFFFFFFF, eax=0xFFFFFFFF, ax=0xFFFF, al=0xFF, ah=0xFF00)
    assert sorted(reg.names) == ["ah", "al", "ax", "eax", "rax"]
    assert reg.rax == 0
    assert reg.ax == 0
    assert reg["rax"] == 0
    assert reg["ax"] == 0
    reg.ah = 0x23
    assert reg.ah == 0x23
    assert reg.al == 0x00
    assert reg.ax == 0x2300
    assert reg.eax == 0x00002300
    reg.eax = 0x123
    assert reg.ah == 0x01
    assert reg.al == 0x23
    assert reg.rax == 0x0000000000000123

    emulator = function_tracing.Emulator()
    context = emulator.new_context()
    registers = context.registers

    # fmt: off
    # Test getting all register names.
    assert sorted(registers.names) == [
        'ac', 'af', 'ah', 'al', 'ax', 'b', 'bh', 'bl', 'bp', 'bpl', 'bx',
        'c0', 'c1', 'c2', 'c3', 'cf', 'ch', 'cl', 'cs', 'cx', 'd', 'df',
        'dh', 'di', 'dil', 'dl', 'dm', 'ds', 'dx', 'eax', 'ebp', 'ebx',
        'ecx', 'edi', 'edx', 'eflags', 'es', 'esi', 'esp', 'flags', 'fs', 'gs', 'i', 'ic',
        'id', 'iem', 'if', 'im', 'iopl', 'ir', 'nt', 'o', 'of', 'om', 'p',
        'pc', 'pf', 'pm', 'r10', 'r10b', 'r10d', 'r10w', 'r11', 'r11b',
        'r11d', 'r11w', 'r12', 'r12b', 'r12d', 'r12w', 'r13', 'r13b', 'r13d',
        'r13w', 'r14', 'r14b', 'r14d', 'r14w', 'r15', 'r15b', 'r15d', 'r15w',
        'r8', 'r8b', 'r8d', 'r8w', 'r9', 'r9b', 'r9d', 'r9w', 'rax', 'rbp',
        'rbx', 'rc', 'rcx', 'rdi', 'rdx', 'rf', 'rip', 'rsi', 'rsp', 'sf',
        'sf', 'si', 'sil', 'sp', 'spl', 'ss',
        'st', 'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7',
        'tag0', 'tag1', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6', 'tag7',
        'tf', 'top', 'u', 'um', 'vif', 'vip', 'vm',
        'xmm0', 'xmm1', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
        'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9',
        'z', 'zf', 'zm',
    ]
    # Test getting register names for FPU.
    assert sorted(registers.fpu.names) == [
        "b", "c0", "c1", "c2", "c3", "d", "dm", "i", "ic", "iem", "im", "ir",
        "o", "om", "p", "pc", "pm", "rc", "sf",
        "st", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
        "tag0", "tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7",
        "top", "u", "um", "z", "zm",
    ]
    # fmt: on

    # Test FPU registers.
    # TODO: Add tests for flags
    EMPTY = registers.fpu.EMPTY
    assert registers.st0 == EMPTY
    assert registers["st0"] == EMPTY
    assert registers.fpu.st0 == EMPTY
    assert registers.fpu["st0"] == EMPTY
    registers.fpu.push(-12.3)
    assert registers.st0 == -12.3
    assert registers.st1 == EMPTY
    registers.fpu.push(34)
    assert registers.st0 == 34
    assert registers.st1 == -12.3
    registers.fpu.pop()
    assert registers.st0 == -12.3
    assert registers.st1 == EMPTY
    registers.fpu.push(registers.fpu.INFINITY)
    assert registers.st0 == registers.fpu.INFINITY
    assert registers.st1 == -12.3


@pytest.mark.in_ida_arm
def test_barrel_shifted_operands():
    """Tests ARM's barrel shifted operand types"""
    from kordesii.utils import function_tracing
    from kordesii.utils.function_tracing import FunctionTracingError

    emulator = function_tracing.Emulator()

    # MOV     R1, R3,LSR#31
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103A4)
    ctx.ip = insn.ip
    assert insn.operands[1].text == "R3,LSR#31"
    ctx.registers.r3 = 0xffffffff
    ctx.registers.c = 0
    assert ctx.registers.r3 == 0xffffffff
    assert ctx.registers.c == 0
    assert insn.operands[1].value == 0x1
    assert ctx.registers.c == 0  # carry flag should have not been updated, (not MOVS)

    # ADD     R1, R1, R3,ASR#2
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103A8)
    ctx.ip = insn.ip
    assert insn.operands[2].text == "R3,ASR#2"
    ctx.registers.r3 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[2].value == 0x1013 >> 2
    assert ctx.registers.c == 0  # carry flag should have not been updated, (not ADDS)
    # Test again with a negative number to ensure ASR sign extends appropriately.
    ctx.registers.r3 = -0x1013
    assert ctx.registers.r3 == 0xffffefed   # sanity check
    assert insn.operands[2].value == 0xfffffbfb  # sign extended shift right 2
    assert ctx.registers.c == 0

    # MOVS    R1, R1,ASR#1
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103AC)
    ctx.ip = insn.ip
    assert insn.operands[1].text == "R1,ASR#1"
    ctx.registers.r1 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[1].value == 0x1013 >> 1
    assert ctx.registers.c == 1  # carry flag should be affected (MOVS)
    # reset instruction pointer to ensure carry flag is only affected if ip is the same.
    ctx.ip = 0
    assert ctx.ip != insn.ip
    ctx.registers.r1 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[1].value == 0x1013 >> 1
    assert ctx.registers.c == 0  # carry flag should not be affected, (ctx.ip != insn.ip)

    # Ensure proper error is thrown if we attempt to set the operand value.
    with pytest.raises(FunctionTracingError):
        insn.operands[1].value = 10


@pytest.mark.in_ida_arm
def test_register_list_operands():
    """Tests ARM operands that are register lists."""
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # POPEQ   {R4-R10,PC}
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x106A8)
    assert insn.operands[0].text == "{R4-R10,PC}"
    assert insn.operands[0].is_register_list is True
    assert insn.operands[0].register_list == ["R4", "R5", "R6", "R7", "R8", "R9", "R10", "PC"]
    ctx.registers.r4 = 4
    ctx.registers.r5 = 5
    ctx.registers.r6 = 6
    ctx.registers.r7 = 7
    ctx.registers.r8 = 8
    ctx.registers.r9 = 9
    ctx.registers.r10 = 10
    ctx.registers.pc = 1024
    assert insn.operands[0].value == [4, 5, 6, 7, 8, 9, 10, 1024]
    insn.operands[0].value = [10, 20, 30, 40, 50, 60, 70, 80]
    assert insn.operands[0].value == [10, 20, 30, 40, 50, 60, 70, 80]
    assert ctx.registers.r4 == 10
    assert ctx.registers.r5 == 20
    assert ctx.registers.r6 == 30
    assert ctx.registers.r7 == 40
    assert ctx.registers.r8 == 50
    assert ctx.registers.r9 == 60
    assert ctx.registers.r10 == 70
    assert ctx.registers.pc == 80

    # ValueError should be thrown if we set the wrong amount of values.
    with pytest.raises(ValueError):
        insn.operands[0].value = [1, 2, 3]


@pytest.mark.in_ida_arm
def test_memory_addressing_modes():
    """Tests pre/post indexed memory address operands."""
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Post-index
    # LDR     R3, [R5],#4
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x106BC)
    assert insn.operands[1].text == "[R5],#4"
    ctx.registers.r5 = 5
    # operand initially points to address 0x5
    assert insn.operands[1].addr == 5
    assert insn.operands[1].value == 0x8070605
    insn.execute()
    # operand should now point to address 0x5 + 4
    assert ctx.registers.r5 == 5 + 4
    assert insn.operands[1].addr == 5 + 4
    assert insn.operands[1].value == 0xc0b0a09

    # Pre-index (no update)
    # LDR     R2, [R3,R2]
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x10354)
    assert insn.operands[1].text == "[R3,R2]"
    ctx.registers.r2 = 2
    ctx.registers.r3 = 3
    # operand initially points to address 3 + 2
    assert insn.operands[1].addr == 3 + 2
    assert insn.operands[1].value == 0x8070605
    insn.execute()
    # operands should still point to address 3 + 2
    assert ctx.registers.r3 == 3
    ctx.registers.r2 = 2  # undo the modification to R2 the instruction does :)
    assert insn.operands[1].addr == 3 + 2
    assert insn.operands[1].value == 0x8070605

    # Pre-index with update
    # LDR     PC, [LR,#8]!
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x102D4)
    assert insn.operands[1].text == "[LR,#8]!"
    ctx.registers.lr = 2
    # operand initially points to address 0x2 + 8
    assert insn.operands[1].addr == 2 + 8
    assert insn.operands[1].value == 0xd0c0b0a
    insn.execute()
    # operand should now point to address 0x2 + 8 + 8
    assert ctx.registers.lr == 2 + 8
    assert insn.operands[1].addr == 2 + 8 + 8
    assert insn.operands[1].value == 0x15141312


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
    assert strings == [
        (b'Hello World!', 0x01),
        (b'Test string with key 0x02', 0x02),
        (b'The quick brown fox jumps over the lazy dog.', 0x03),
        (b'Oak is strong and also gives shade.', 0x04),
        (b'Acid burns holes in wool cloth.', 0x05),
        (b'Cats and dogs each hate the other.', 0x06),
        (b"Open the crate but don't break the glass.", 0x13),
        (b'There the flood mark is ten inches.', 0x17),
        (b'1234567890', 0x1a),
        (b'CreateProcessA', 0x23),
        (b'StrCat', 0x27),
        (b'ASP.NET', 0x40),
        (b'kdjsfjf0j24r0j240r2j09j222', 0x46),
        (b'32897412389471982470', 0x73),
        (b'The past will look brighter tomorrow.', 0x75),
        (b'Cars and busses stalled in sand drifts.', 0x77),
        (b'The jacket hung on the back of the wide chair.', 0x7a),
        (b'32908741328907498134712304814879837483274809123748913251236598123056231895712', 0x7f),
    ]


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
