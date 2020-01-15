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

        assert idc.get_input_file_path() == strings_exe
        assert idc.print_insn_mnem(0x00401525) == 'mov'
        assert utils.get_function_addr('GetProcAddress') == 0x40a028
        assert utils.get_string(0x0040C000) == 'Idmmn!Vnsme '

        # Ensure we can only start one at a time.
        with pytest.raises(ValueError):
            kordesii.IDA(r'C:\dummy.exe').start()
        pass

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


@kordesii.run_in_ida
def trace_arguments(ea):
    """
    This is a function that would be almost impossible to do proxied due to
    the complexities of function_tracing.
    """
    from kordesii.utils import function_tracing

    tracer = function_tracing.get_tracer(ea)

    strings = []
    for context in tracer.iter_context_at(ea, depth=1):
        assert context.ip == ea
        # mov     eax, [ebp+arg_0]
        strings.append(context.read_data(context.operands[1].value))

    return strings


def test_run_in_ida(strings_exe):
    """Tests the run_in_ida decorator."""
    strings_exe = str(strings_exe)

    with kordesii.IDA(strings_exe):
        assert trace_arguments(0x00401003) == [
            'Idmmn!Vnsme ',
            'Vgqv"qvpkle"ukvj"ig{"2z20',
            'Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-',
            'Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*',
            'Dfla%gpwkv%mji`v%lk%rjji%fijqm+',
            'Egru&ghb&biau&cgen&ngrc&rnc&irnct(',
            '\\cv}3g{v3pargv3qfg3w|}4g3qavrx3g{v3t\x7fr``=',
            'C\x7frer7c\x7fr7q{xxs7zve|7~d7cry7~yt\x7frd9',
            '+()./,-"#*',
            '`QFBWFsQL@FPPb',
            'tSUdFS',
            '\x01\x13\x10n\x0e\x05\x14',
            '-",5 , v,tr4v,trv4t,v\x7f,ttt',
            '@AKJDGBA@KJGDBJKAGDC',
            '!\x1d\x10U\x05\x14\x06\x01U\x02\x1c\x19\x19U\x19\x1a\x1a\x1eU\x17\x07\x1c\x12\x1d\x01\x10\x07U\x01\x1a\x18\x1a\x07\x07\x1a\x02[',
            '4\x16\x05\x04W\x16\x19\x13W\x15\x02\x04\x04\x12\x04W\x04\x03\x16\x1b\x1b\x12\x13W\x1e\x19W\x04\x16\x19\x13W\x13\x05\x1e\x11\x03\x04Y',
            '.\x12\x1fZ\x10\x1b\x19\x11\x1f\x0eZ\x12\x0f\x14\x1dZ\x15\x14Z\x0e\x12\x1fZ\x18\x1b\x19\x11Z\x15\x1cZ\x0e\x12\x1fZ\r\x13\x1e\x1fZ\x19\x12\x1b\x13\x08T',
            'LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM'
        ]

    # Ensure we get an error, if we attempt to run the function outside of proxy instance.
    with pytest.raises(RuntimeError):
        trace_arguments(0x00401003)
