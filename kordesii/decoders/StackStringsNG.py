"""
Experimental new stack string decoder using function_tracing
"""

import io

import idc


import kordesii
from kordesii.utils import decoderutils
from kordesii.utils import function_tracing
from kordesii.utils import utils


logger = kordesii.get_logger()


ENCODINGS = [('utf-8', 1), ('utf-16-le', 2)]


def num_raw_bytes(string):
    """
    Returns the number of raw bytes found in the given unicode string
    """
    count = 0
    for char in string:
        char = char.encode('unicode-escape')
        count += char.startswith(b'\\x') + char.startswith(b'\\u') * 2
    return count


def read_string(data):
    """
    Read data until we find a something that is not a printable ascii character.

    :return: String and encoding if we find a string of at least 1 character.
        Returns Nones otherwise.
    """
    stream = io.BytesIO(data)
    strings = []
    for encoding, width in ENCODINGS:
        stream.seek(0)
        string = u''
        while True:
            char = stream.read(width)
            if not char:
                # Ran out of bytes
                break
            try:
                char = char.decode(encoding)
            except UnicodeDecodeError:
                break
            if char == u'\0' or num_raw_bytes(char):
                break
            string += char
        if string:
            strings.append((string, encoding))

    if not strings:
        return None, None

    # Return whichever encoding uses the most data.
    return max(strings, key=lambda s: len(s[0]))


class StackStringExtractor(object):

    def __init__(self):
        self.encoded_strings = []

    def process_string(self, context, var, ip):
        # Read in data from stack and see if it's a valid string.
        stack_data = context.read_data(var.addr, 1024)
        string, encoding = read_string(stack_data)
        if string:
            data = string.encode(encoding)
            encoded_string = decoderutils.EncodedStackString(
                data,
                frame_id=var.frame_id,
                stack_offset=var.stack_offset,
                string_reference=ip,
                code_page=encoding,
            )
            encoded_string.decoded_data = data
            self.encoded_strings.append((var.addr, encoded_string))

    def parse_stack_strings(self, func):

        logger.debug('Processing function: 0x{:X}'.format(func.start_ea))
        tracer = function_tracing.get_tracer(func.start_ea)

        waiting_for_call = []

        context = None
        for ea in func.heads():
            context = tracer.context_at(ea)
            if not context:
                continue
            context.execute()  # also include instruction we are looking at.

            # If we encounter a call, process pushed in variables.
            if idc.print_insn_mnem(ea) == 'call':
                for ip, var in waiting_for_call:
                    self.process_string(context, var, ip)
                waiting_for_call = []
                continue

            # Look for instructions where a stack variable is being used for something other than
            # a move.
            # We can do this by only considering variables that are the last operand.
            operands = context.get_operands(ea)
            if not operands:
                continue
            addr = operands[-1].addr or operands[-1].value
            if not addr:
                continue
            var = context.variables.get(addr)
            if var and var.is_stack:
                # Ignore string if it comes from memory with no concatinations.
                if var.history and idc.is_loaded(var.history[0].addr):
                    continue

                # If instruction is a push, it is possible that the string will be populated
                # after this instruction. Therefore, wait for the function call be before processing.
                if idc.print_insn_mnem(ea) == 'push':
                    waiting_for_call.append((ea, var))
                else:
                    self.process_string(context, var, ea)

        # Process any strings still waiting for a call.
        if context:
            for ip, var in waiting_for_call:
                self.process_string(context, var, ip)

        # Remove any substrings or strings that are too small.
        for addr, encoded_string in sorted(self.encoded_strings):
            if len(encoded_string.encoded_data) < 3:
                self.encoded_strings.remove((addr, encoded_string))
                continue
            for _addr, _encoded_string in self.encoded_strings[:]:
                # Remove dups
                if (_addr == addr
                        and _encoded_string is not encoded_string
                        and _encoded_string.encoded_data == encoded_string.encoded_data):
                    self.encoded_strings.remove((addr, encoded_string))
                    break
                # Remove substrings
                elif _addr < addr:
                    index = addr - _addr
                    substring = _encoded_string.encoded_data[index:index + len(encoded_string.encoded_data)]
                    if substring == encoded_string.encoded_data:
                        self.encoded_strings.remove((addr, encoded_string))
                        break

        # Report found strings
        for _, encoded_string in sorted(self.encoded_strings):
            # Don't want to rename because the buffers could be reused for multiple strings.
            encoded_string.publish(rename=False, patch=False)
            # TODO: EncodedString should allow commenting without renaming.
            idc.set_cmt(
                encoded_string.string_reference,
                'Stack String: "{}"'.format(encoded_string.display_name), 0)


@kordesii.decoder_entry
def main():

    # NOP memset, its emulation is not needed and it's slowing things down.
    def memset(context, func_name, func_args):
        return
    function_tracing.hook_tracers('memset', memset)

    for ea, name in utils.iter_functions():
        try:
            func = decoderutils.SuperFunc_t(ea)
        except AttributeError:
            continue
        if not func.is_library:
            StackStringExtractor().parse_stack_strings(func)
