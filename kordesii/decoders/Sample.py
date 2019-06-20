"""
Description: Sample decoder
Author: DC3
"""
import re

import kordesii
from kordesii.utils import decoderutils
from kordesii.utils import function_tracing


logger = kordesii.get_logger()


def xor_decrypt(key, enc_data):
    return ''.join(chr(ord(x) ^ key) for x in enc_data)


def find_strings():
    """
    Extracts and publishes EncodedString objects for the parameters following xor encryption function:

        void encrypt(char *s, char key)
        {
	        while (*s)
		        *s++ ^= key;
        }
    """
    for encrypt_func in decoderutils.re_find_functions(re.compile(r'\x8b\x45\x08\x0f\xbe\x08')):
        logger.info('Found XOR encrypt function at: 0x{:0x}'.format(encrypt_func.start_ea))
        for call_ea in encrypt_func.xrefs_to:
            logger.debug('Tracing {:0x}'.format(call_ea))
            # Extract arguments for call to xor function.
            tracer = function_tracing.get_tracer(call_ea)
            context, args = tracer.get_function_args(call_ea)
            enc_str_ptr, key = args
            encoded_string = decoderutils.EncodedString(enc_str_ptr, string_reference=call_ea, key=key)
            encoded_string.decoded_data = xor_decrypt(key, encoded_string.encoded_data)
            encoded_string.publish(rename=True, patch=False)


@kordesii.decoder_entry
def main():
    """
    Finds xor encrypted strings then decrypts and outputs them.
    """
    find_strings()
