"""
Tests the IDA proxy functionality.
"""

import pytest

import kordesii


def test_basic(strings_exe):
    """Tests some basic functionality and stability."""
    strings_exe = str(strings_exe)

    with kordesii.IDA(strings_exe):
        import idc
        from kordesii.utils import utils
        from kordesii.utils import ida_re

        assert idc.get_input_file_path() == strings_exe
        assert idc.print_insn_mnem(0x00401525) == 'mov'
        assert utils.get_function_addr('GetProcAddress') == 0x40a028
        assert utils.get_string(0x0040C000) == b'Idmmn!Vnsme '

        regex = ida_re.Pattern(b'Idmmn!Vnsme')
        match = regex.search()
        assert match
        assert match.start() == 0x0040C000
        assert match.group() == b'Idmmn!Vnsme'

        # Ensure we can only start one at a time.
        with pytest.raises(ValueError):
            kordesii.IDA(r'C:\dummy.exe').start()
        pass

        # Test that we can also use submodules (the utils in utils)
        from kordesii import utils
        assert utils.get_function_addr('GetProcAddress') == 0x40a028
        assert utils.get_string(0x0040C000) == b'Idmmn!Vnsme '

        # Test that importing a class doesn't cause things to explode.
        try:
            from ida_gdl import BasicBlock
        except ImportError as e:
            # FIXME
            pytest.xfail(f"Known bug of IDA proxy: {e}")

        with pytest.raises(NotImplementedError) as exec_info:
            BasicBlock(1, 2, 3)
        assert str(exec_info.value) == "Initializing the class ida_gdl.BasicBlock is not supported."

    # Ensure we can't use modules after closing.
    with pytest.raises(AttributeError):
        idc.print_insn_mnem(0x00401525)

    # Now test that we can spin it up again.
    with kordesii.IDA(strings_exe):
        # import idc  # reimporting is not required.
        assert idc.get_input_file_path() == strings_exe

    # Now test manually starting and stopping.
    ida = kordesii.IDA(strings_exe)
    ida.start()
    import idc
    assert idc.get_input_file_path() == strings_exe
    ida.stop()

    # can't access imports outside
    with pytest.raises(AttributeError):
        idc.get_input_file_path()

    # now try starting the same instance again.
    ida.start()
    assert idc.get_input_file_path() == strings_exe
    ida.stop()

    # Try opening a file that is not actually an exe.
    # It should still work, just not be very helpful.
    with kordesii.IDA(__file__):
        assert idc.get_input_file_path() == __file__
        assert idc.print_insn_mnem(0x00401525) == ''


def ida_assert(value, expected):
    """
    Workaround to test values inside run_in_ida decorated functions.
    This is necessary because pytest's assert rewriting is messing with our ability
    to use assert in these functions.
    """
    if value != expected:
        raise AssertionError(f'{value} != {expected}')


@kordesii.run_in_ida
def trace_arguments(ea):
    """
    This is a function that would be almost impossible to do proxied due to
    the complexities of function_tracing.
    """
    from kordesii.utils import function_tracing

    emulator = function_tracing.Emulator()

    # Test that we can call other decorated functions.
    ida_assert(get_mnem(ea), 'mov')

    strings = []
    for context in emulator.iter_context_at(ea, depth=1):
        ida_assert(context.ip, ea)
        # mov     eax, [ebp+arg_0]
        strings.append(context.read_data(context.operands[1].value))

    return strings


@kordesii.run_in_ida
def get_mnem(ea):
    import idc
    return idc.print_insn_mnem(ea)


def test_run_in_ida(strings_exe):
    """Tests the run_in_ida decorator."""
    strings_exe = str(strings_exe)

    with kordesii.IDA(strings_exe):
        assert trace_arguments(0x00401003) == [
            b'Idmmn!Vnsme ',
            b'Vgqv"qvpkle"ukvj"ig{"2z20',
            b'Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-',
            b'Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*',
            b'Dfla%gpwkv%mji`v%lk%rjji%fijqm+',
            b'Egru&ghb&biau&cgen&ngrc&rnc&irnct(',
            b'\\cv}3g{v3pargv3qfg3w|}4g3qavrx3g{v3t\x7fr``=',
            b'C\x7frer7c\x7fr7q{xxs7zve|7~d7cry7~yt\x7frd9',
            b'+()./,-"#*',
            b'`QFBWFsQL@FPPb',
            b'tSUdFS',
            b'\x01\x13\x10n\x0e\x05\x14',
            b'-",5 , v,tr4v,trv4t,v\x7f,ttt',
            b'@AKJDGBA@KJGDBJKAGDC',
            b'!\x1d\x10U\x05\x14\x06\x01U\x02\x1c\x19\x19U\x19\x1a\x1a\x1eU\x17\x07\x1c\x12\x1d\x01\x10\x07U\x01\x1a\x18\x1a\x07\x07\x1a\x02[',
            b'4\x16\x05\x04W\x16\x19\x13W\x15\x02\x04\x04\x12\x04W\x04\x03\x16\x1b\x1b\x12\x13W\x1e\x19W\x04\x16\x19\x13W\x13\x05\x1e\x11\x03\x04Y',
            b'.\x12\x1fZ\x10\x1b\x19\x11\x1f\x0eZ\x12\x0f\x14\x1dZ\x15\x14Z\x0e\x12\x1fZ\x18\x1b\x19\x11Z\x15\x1cZ\x0e\x12\x1fZ\r\x13\x1e\x1fZ\x19\x12\x1b\x13\x08T',
            b'LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM'
        ]

        # Also test that we can catch exceptions.
        with pytest.raises(TypeError, match="argument 2 of type 'ea_t'"):
            get_mnem('not an address')

    # Ensure we get an error, if we attempt to run the function outside of proxy instance.
    with pytest.raises(RuntimeError):
        trace_arguments(0x00401003)
