"""
Description: Sample decoder
Author: DC3
"""
import re

import kordesii
from kordesii.utils import decoderutils
from kordesii.utils import function_tracing


logger = kordesii.get_logger()
tracers = function_tracing.TracerCache()


def find_strings():
    """
    Extracts and creates EncodedString objects for the parameters following xor encryption function:

        void encrypt(char *s, char key)
        {
	        while (*s)
		        *s++ ^= key;
        }

    :returns: list of EncodedString objects.
    """
    encoded_strings = []
    for encrypt_func in decoderutils.re_find_functions(re.compile(r'\x8b\x45\x08\x0f\xbe\x08')):
        logger.info('Found XOR encrypt function at: 0x{:0x}'.format(encrypt_func.start_ea))
        for call_ea in encrypt_func.xrefs_to:
            logger.debug('Tracing {:0x}'.format(call_ea))
            # Extract arguments for call to xor function.
            tracer = tracers.get(call_ea)
            context, args = tracer.get_function_args(call_ea)
            enc_str_ptr, key = args
            encoded_string = decoderutils.EncodedString(enc_str_ptr, string_reference=call_ea, key=key)
            encoded_string.calc_size()  # Calculate size for given encoded string.
            encoded_strings.append(encoded_string)
    return encoded_strings


def sample_decode(encoded_string):
    """
    Given an encoded_string instance, decode the data using xor with key that was found.
    """
    return ''.join(chr(ord(x) ^ encoded_string.key) for x in encoded_string.encoded_data)


@kordesii.decoder_entry
def main():
    """
    Finds xor encrypted strings then decrypts and outputs them.
    """
    encoded_strings = find_strings()

    strings = decoderutils.decode_strings(encoded_strings, sample_decode)
    decoderutils.output_strings(strings)
