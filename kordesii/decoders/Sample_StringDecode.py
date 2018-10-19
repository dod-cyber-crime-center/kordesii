
import idc

from kordesii import kordesiiidahelper
from kordesii.utils import decoderutils


YARA_RULE = """rule sample_decode
{
    strings:
        $sample_xor_decode = { 8B 45 08 0F BE 08 }
    condition:
        $sample_xor_decode
}"""


class Sample_Tracer(decoderutils.StringTracer):
    def __init__(self, initial_offset, identifier):
        super(Sample_Tracer, self).__init__(initial_offset, identifier)

    def search(self):
        """
        Function Description:
            Attempts to identify the string location and key based upon the values which are
            passed to the string decode function.  In this simple example, we know the values
            will be in the pushes immediately preceding the call.
            The encoded string location is the first argument for the string decode function and
            the xor key is the second argument
            Populates the encoded_strings list

        Return Value:
            Boolean value, True if the encoded string location and key are identified, False if
            the encoded string information is not identified
        """
        function_call_loc = self.initial_offset
        offset_loc = idc.PrevHead(function_call_loc)
        key_loc = idc.PrevHead(offset_loc)

        # some basic validation checks to make sure we have the correct locations
        # ie, ensure that we are pushing values onto the stack for the call
        if idc.GetMnem(offset_loc) != 'push':
            return False
        if idc.GetMnem(key_loc) != 'push':
            return False

        # args for EncodedString object init
        string_reference = offset_loc
        string_location = idc.GetOperandValue(offset_loc, 0)
        key = idc.GetOperandValue(key_loc, 0)

        # create EncodedString and check if valid
        encoded_string = decoderutils.EncodedString(string_location,
                                                    string_reference,
                                                    key=key)
        if encoded_string.calc_size() == idc.BADADDR:
            return False  # if we can't determine a size, fail the search

        # decoderutils extends its list of encoded strings from this class, so add
        # this encoded string to our list
        self.encoded_strings.append(encoded_string)

        return True


def sample_decode(encoded_string):
    """
    Function Description:
        Given an encoded_string instance, decode the data using xor with key that was found.
    """
    return ''.join(chr(ord(x) ^ encoded_string.key) for x in encoded_string.encoded_data)


def main():
    """
    Function Description:
        Calls decoderutils string_decoder_main, which conducts all decryption operations
        Passes the YARA rule, the Sample_Tracer class, and the sample_decode decryption function
    """
    decoderutils.string_decoder_main(YARA_RULE, Sample_Tracer, sample_decode)


if __name__ == '__main__':
    idc.Wait()
    main()
    if 'exit' in idc.ARGV:
        idc.Exit(0)
