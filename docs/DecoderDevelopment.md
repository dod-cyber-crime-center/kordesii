# Decoder Development Guide

This guide seeks to explain how to develop decoders for DC3-Kordesii.

### Guides
- [CPU Emulation](CPUEmulation.md)
- [Decoder Development](DecoderDevelopment.md)
- [Decoder Installation](DecoderInstallation.md)
- [Decoder Testing](DecoderTesting.md)


## Steps

To create a simple decoder the high level steps are:

1. [Install DC3-Kordesii](../README.md#install)
    - If you plan to contribute your decoder back to DC3-Kordesii, you can install in "development"
    mode and place your decoder directly into DC3-Kordesii's "decoders" directory.
2. If this is not an upstream contribution, create a directory or python package to store your parsers. 
    - It is recommended you create your decoder in your own Python project. (See [Formal Packaging](DecoderInstallation.md#formal-packaging))
3. Create a new python file in your decoder directory.
    - The name of this file is usually the name of the malware family or method of extraction (e.g. "StackStrings")
    - Add a docstring containing "Description:" and "Author:" entries. These will be used by the framework
    when `kordesii list` is called.
    
```python
"""
Description: Sample decoder
Author: DC3
"""
```
    
4. Import `kordesii`, `kordesii.utils.decoderutils` and possibly `kordesii.utils.function_tracing`

5. Create a logger with `kordesii.get_logger()`
    - Use this logger to log any messages you would like to present back the user. Messages are passed back in semi-realtime through the use of sockets.
    - It is a good idea to use logging to help inform the user on the progress of the decoder and if the decoder may need to be updated due to a new variant of the sample.

6. Decorate your entry point with `kordesii.decoder_entry`. This is the function that the framework will call on startup. (The framework will call idc.Wait() and other necessary IDA functions for you.)
    - **WARNING:** It is important that the function you wrap with `decoder_entry` is the last thing in the module. 
    Anything declared after it will not be available when the decoder runs.
    
```python
import kordesii

# DECODER CODE

@kordesii.decoder_entry
def main():
   # ...
   
# DON'T ADD ANY CODE HERE!
```

7. Find and extract encrypted strings (and their keys).
    - Identify points of interest using the regex or yara helpers found in `kordesii.utils.decoderutils`
    - Then trace to extract keys and decrypted strings
        - If you can, use `kordesii.utils.function_tracing` to emulate your sample to help simplify code and make your decoder more flexible with new samples.
    - Use the logger to report success and failure messages as well as debug message to help a future developer looking at your code.
    
8. Create `EncodedString` or `EncodedStackString` objects from found strings and set the decrypted data into the `decoded_data` attribute.

9. Call `publish()` on your generated `EncodedString`/`EncodedStackString` objects to output the string and optionally patch or rename the string within the IDB.
    

```python
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

```
