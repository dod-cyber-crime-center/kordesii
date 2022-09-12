"""
Tests flowchart mechanics.
"""

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
