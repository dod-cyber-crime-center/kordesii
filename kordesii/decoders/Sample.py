"""
Description: Sample decoder
Author: DC3
"""

import kordesii
from kordesii.utils import EncodedString
from kordesii.utils import ida_re
from kordesii.utils import function_tracing

logger = kordesii.get_logger()
emulator = function_tracing.Emulator()


def xor_decrypt(key, enc_data):
    return bytes((x ^ key) for x in enc_data)


def find_strings():
    """
    Extracts and publishes EncodedString objects for the parameters following xor encryption function:

        void encrypt(char *s, char key)
        {
            while (*s)
                *s++ ^= key;
        }
    """
    for encrypt_func in ida_re.find_functions(br"\x8b\x45\x08\x0f\xbe\x08"):
        logger.info("Found XOR encrypt function at: 0x%x", encrypt_func.start_ea)
        for call_ea in encrypt_func.calls_to:
            logger.debug("Tracing 0x%08x", call_ea)
            # Extract arguments for call to xor function.
            context, args = emulator.get_function_args(call_ea)
            enc_str_ptr, key = args
            encoded_string = EncodedString(enc_str_ptr, string_reference=call_ea, key=key)
            encoded_string.decoded_data = xor_decrypt(key, encoded_string.encoded_data)
            encoded_string.publish(rename=True, patch=False)


@kordesii.decoder_entry
def main():
    """
    Finds xor encrypted strings then decrypts and outputs them.
    """
    find_strings()
