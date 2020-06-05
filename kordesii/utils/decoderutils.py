import abc
import copy
import hashlib
import logging
import os
import warnings

import idaapi
import idautils
import idc

logger = logging.getLogger(__name__)

# region ======== Deprecated Components ========

import kordesii.utils.strings as strings
import kordesii.utils.functions as functions
import kordesii.utils.utils as utils
import kordesii.utils.ida_re as ida_re
import kordesii.utils.yara as yara


class EncodedString(strings.EncodedString):
    def __init__(self, *args, **kwargs):
        warnings.warn("EncodedString has been moved to kordesii.utils.EncodedString", DeprecationWarning)
        super(EncodedString, self).__init__(*args, **kwargs)


class EncodedStackString(strings.EncodedStackString):
    def __init__(self, *args, **kwargs):
        warnings.warn("EncodedStackString has been moved to kordesii.utils.EncodedStackString", DeprecationWarning)
        super(EncodedStackString, self).__init__(*args, **kwargs)


class SuperFunc_t(functions.Function):
    def __init__(self, *args, **kwargs):
        warnings.warn("SuperFunc_t has been moved and renamed to kordesii.utils.Function", DeprecationWarning)
        super(SuperFunc_t, self).__init__(*args, **kwargs)


def find_destination(*args, **kwargs):
    warnings.warn("find_destination has moved to kordesii.utils.find_destination", DeprecationWarning)
    utils.find_destination(*args, **kwargs)


def re_find_functions(regex, flags=0, section=None, func_name=None):
    warnings.warn(
        "re_find_functions has been moved to kordesii.utils.ida_re.find_functions",
        DeprecationWarning
    )
    funcs = list(ida_re.find_functions(regex, flags=flags, segname=section))
    if func_name is not None:
        for func in funcs:
            func.rename(func_name)
    return funcs


def yara_find_decode_functions(rule_text, func_name=None):
    warnings.warn(
        "yara_find_decode_functions has been moved to kordesii.utils.yara.find_functions",
        DeprecationWarning
    )
    funcs = list(yara.find_functions(rule_text))
    if func_name is not None:
        for func in funcs:
            func.rename(func_name)
    return funcs


def make_superfunc_t_from_matches(matches, func_name=None):
    warnings.warn("make_superfunc_t_from_matches() is deprecated.", DeprecationWarning)
    decode_funcs = set()
    for ea, identifier in matches:
        if ea == idc.BADADDR:
            continue
        func = functions.Function(ea, identifier)
        if func_name is not None:
            func.rename(func_name)
        decode_funcs.add(func)
    return list(decode_funcs)

# endregion =====================================


class StringTracer(object, metaclass=abc.ABCMeta):
    """
    Description:
        An object to hold tracing info for one offset at a time.

        This abstract class doesn't do anything, but attempts to define fields that are
        almost always used. If a field is not used, it is recommended to set it to UNUSED.

    Fields:
        initial_offset - The EA the searching starts at. This is usually a yara match EA or a
                         func_t.start_ea. (<initial_offset> must be within a function.)
        func_ea - The start_ea of the function containing the initial_offset.
        string_location - The EA the encoded string starts at. Defaults to idc.BADADDR.
        string_reference - The EA from which the encoded string is referenced. Defaults to
                           idc.BADADDR.
        encoded_strings - Storage for the encoded string(s) found by search. Defaults to [].
        size - The size of the string. Defaults to None.

    Input:
        initial_offset - Required. We have to start somewhere.
        identifier - The id of the YARA rule that this Tracer is based off of

    Throws:
        AttributeError - There was no function at initial_offset.
    """

    def __init__(self, initial_offset=None, identifier=None):
        super(StringTracer, self).__init__()
        self.initial_offset = initial_offset
        self.identifier = identifier
        if self.initial_offset is not None:
            if not idaapi.get_func(initial_offset):
                raise AttributeError("No function at 0x%X" % initial_offset)
            self.func_ea = idaapi.get_func(initial_offset).start_ea
        else:
            self.func_ea = None
        # TODO: remove use of idc.BADADDR
        self.string_location = idc.BADADDR
        self.string_reference = idc.BADADDR
        self.encoded_strings = []
        self.size = None

    @abc.abstractmethod
    def search(self):
        """
        Description:
            Attempts to identify the string location based on the address passed in the constructor.

            A reminder: abc doesn't care about your parameters matching this prototype, just the name,
            so using **kwargs on search is fine. However, because find_encoded_strings is calling
            this function, there may be no *args as it wouldn't know what to pass. Assuming you don't
            edit this file's code, it may be useful to simply wrap your actual search function with this
            search function in some cases.

        Output:
            True if the encoded string offset is identified, False if the encoded string offset
            is not identified.
        """
        pass


# Put these here for increased robustness. Please don't depend on these very often.
ENCODED_STRINGS = []
DECODED_STRINGS = []


def get_encoded_strings():
    """ Use responsibly """
    return ENCODED_STRINGS


def get_decoded_strings():
    """ Use responsibly """
    return DECODED_STRINGS


def is_valid_ea(ea):
    """
    Description:
        Returns true for valid EAs, False for invalid ones.

    Input:
        ea - The EA to check

    Output:
        True if the EA is valid, False if it is not
    """
    return ea not in (None, idc.BADADDR) and idc.get_inf_attr(
        idc.INF_MIN_EA
    ) <= ea <= idc.get_inf_attr(idc.INF_MAX_EA)


# TODO: Integrate this into EncodedString class
def split_decoded_string(decoded_string, identify=False):
    """
    Description:
        Given a single EncodedString, split it into multiple.
        By default, it is split on \x00.
        The original EncodedString is not modified.

    Input:
        decoded_string - The EncodedString to split
        identify - When True, define the resultant strings in the IDB

    Output:
        A list of EncodedStrings.
    """
    """
    Normally, we have either a block of either all one byte characters OR all two byte characters,
    however with some families, the blocks have utf-8 and utf-16 mixed together. When the block is all one
    byte characters, we just split the block on \x00 and are done with it. Likewise, when the block is all
    two byte characters, we just split the block on \x00\x00 and are done with it. For mixed blocks,
    we can't just split on one or the other. If we were to split on \x00 to find the single byte character strings,
    we would of course completely destroy the two byte character strings. Therefore, we effectively tokenize
    the block on \x00\x00 and process each sub-block separately.

    To process a block, we start from its end (which is guaranteed to be either \x00\x00 or the end of
    the buffer, which might as well be \x00) and work our way forward. We initially start by finding
    the rightmost \x00, which is either the end of the previous single byte character string or the
    first byte in a two byte character. To determine if the \x00 is part of two byte character string,
    we step back two characters. We keep stepping back as long as we keep landing
    on \x00. Once we hit a character that's not \x00, we undo our last step (and because we don't want
    to grab a leading \x00, step one more character, for a total of 3 characters not the 2 we have
    been stepping).

    Wherever we are now is the beginning of the string, which continues up until the index from which
    we searched for the rightmost \x00 earlier. We continue like this until we run into the front of
    the current block and then process the next block, repeating until we hit the end of the buffer.
    """
    results = []
    section_start = 0
    section_end = decoded_string.decoded_data.find(b"\x00\x00")
    if section_end == -1:
        section_end = len(decoded_string.encoded_data)
    string_end = section_end

    while True:
        while True:
            # Determine where the next individual string starts
            string_start = decoded_string.decoded_data[section_start:string_end].rfind(
                b"\x00"
            )
            if string_start != -1:
                string_start += section_start
                while (
                    string_start >= section_start
                    and decoded_string.decoded_data[string_start] == 0
                ):
                    string_start -= 2
                if string_start > section_start:
                    string_start += 3  # last step +1 to skip \x00
                elif string_start < section_start:
                    # The leftmost string in the section, so don't step past section_start
                    string_start = section_start
            else:
                string_start = section_start  # The leftmost string in the block

            # Now that we have a string_start and string_end, we can carve the string
            new_decoded_string = decoded_string.decoded_data[string_start:string_end]
            if new_decoded_string:
                # Since we're using \x00 as the delimiter, we need to add \x00 to the end
                new_decoded_string += b"\x00"
                new_string = copy.copy(decoded_string)
                new_string.encoded_data = new_decoded_string
                new_string.decoded_data = new_decoded_string
                new_string.offset = string_start
                results.append(new_string)

            if string_start == section_start:
                break
            else:
                # -1 to skip \x00 for searching (which necessitates adding it back above)
                string_end = string_start - 1

        # We've processed a full section, advance to the next section
        if section_end == len(decoded_string.decoded_data):
            break
        else:
            section_start = section_end + 2
            # Skip blocks of \x00
            while (
                section_start < len(decoded_string.encoded_data)
                and decoded_string.decoded_data[section_start] == 0
            ):
                section_start += 1
            section_end = decoded_string.decoded_data[section_start:].find(b"\x00\x00")
            if section_end == -1:  # The rightmost section in the block
                section_end = len(decoded_string.encoded_data)
            else:
                section_end += section_start
            string_end = section_end

    results.sort(key=lambda decoded_string: decoded_string.start_ea)

    if identify:
        for new_string in results:
            new_string.define()

    return results


def find_encoded_strings_inline(matches, Tracer, **kwargs):
    """
    For each yara match, attempt to find encoded strings.

    Input:
        matches - A list of yara matches (ea, identifier)
        Tracer - A pointer to an implementation of StringTracer.
        **kwargs - kwargs to be passed to Tracer's constructor.

    Output:
        A list of EncodedStrings.
    """
    encoded_strings = []
    for ea, identifier in matches:
        try:
            tracer = Tracer(ea, identifier, **kwargs)
            if tracer.search():
                encoded_strings.extend(tracer.encoded_strings)
            else:
                logger.warning("Failed to find strings at 0x%X" % ea)
        except AttributeError:
            logger.warning("Error tracing at 0x%X" % ea)
    return encoded_strings


def find_encoded_strings(funcs, Tracer, **kwargs):
    """
    Description:
        For each ref for each function, attempt to find encoded strings.

    Input:
        funcs - A list of functions. Must have an xrefs_to field.
        Tracer - A pointer to an implementation of StringTracer.
        **kwargs - kwargs to be passed to Tracer's constructor.

    Output:
        A list of EncodedStrings.
    """
    encoded_strings = []
    for func in funcs:
        for ref in func.xrefs_to:
            if idc.get_segm_name(ref) == ".pdata":
                logger.info(
                    "Segment .pdata for ref 0x%08x is not a relevant code segment and will be skipped"
                    % ref
                )
            else:
                # NOTE: Setting errors to info because it is common and will spam our console.
                try:
                    tracer = Tracer(ref, func.identifier, **kwargs)
                    if tracer.search():
                        encoded_strings.extend(tracer.encoded_strings)
                    else:
                        logger.info("Failed to find strings at 0x%X" % ref)
                except AttributeError as e:
                    # Only catch AttributeErrors resulting from a function not existing. All other AttributeErrors
                    # are actual errors and should go uncaught.
                    #
                    # TODO: Create a separate exception class for a function not existing, so that we don't have to do
                    #  this kind of error message checking.
                    if str(e).startswith("No function at 0x"):  #
                        logger.info(
                            "No function exists at 0x%X. Create a function at this location to obtain strings."
                            % ref
                        )
                    else:
                        raise e
    return encoded_strings


def decode_strings(encoded_strings, decode):
    """
    Description:
        For each encoded_string entry in encoded_strings, decode the data using the provided
        decode function.

    Input:
        encoded_strings - A list of EncodedStrings.
        decode - A pointer to a function that handles decoding.

    Output:
        A list of successfully decoded EncodedStrings.
    """
    # NOTE: Setting errors to info because it is common and will spam our console.
    decoded_strings = []
    for encoded_string in encoded_strings:
        if not encoded_string.encoded_data:
            logger.info("Unable to find string {!r}".format(encoded_string))
            continue
        encoded_string.decoded_data = decode(encoded_string)
        if isinstance(encoded_string.decoded_data, bytearray):
            encoded_string.decoded_data = bytes(encoded_string.decoded_data)
        if encoded_string.decoded_data:  # Allow decoders to abort/fail quietly
            decoded_strings.append(encoded_string)
        else:
            logger.info("Failed to decode string: {!r}".format(encoded_string))
    return decoded_strings


INPUT_FILE_PATH = idc.get_input_file_path()


def find_input_file():
    """
    Description:
        Check whether or not IDA knows where the original file used to create the IDB is.
        If IDA doesn't know, check the IDA's directory for the file.

    Output:
        Returns True if the input file was located, False if it was not.
    """
    global INPUT_FILE_PATH
    ida_path = INPUT_FILE_PATH
    if not os.path.exists(ida_path):
        # If IDA does not know, check if the (correct) file is sitting next to the IDB.
        local_path = os.path.join(idautils.GetIdbDir(), idc.get_root_filename())
        if (
            os.path.exists(local_path)
            and hashlib.md5(open(local_path, "rb").read()).hexdigest().upper()
            == idc.retrieve_input_file_md5()
        ):
            INPUT_FILE_PATH = local_path
            logger.debug("Guessed the input file path: " + INPUT_FILE_PATH)
            logger.debug("IDA thought it was:          " + ida_path)
            return True
        else:
            return False
    else:
        return True


def string_decoder_main(
    yara_rule,
    Tracer,
    decode,
    patch=True,
    func_name="string_decode_function",
    inline=False,
):
    """
    Description:
        If you are going to use this file's workflow as is, this is the entry point. This supports the majority
        of decode function xref based decoding algorithms (the 'older' way) and inline decoding algorithms
        (the 'newer' way).

    Input:
        First, you'll need to provide a YARA rule. The rule can either be passed as a string or in a file.
        If it is in a file, be sure to set is_yara_file = True. Also note that when YARA finds the decoder
        function, it will attempt to rename it:
            func_name = '' will reset the name to the default name it had when IDA built the IDB
            func_name = None will prevent this script from renaming it

        Second, you need to implement the StringTracer class above to handle your malware's particular
        way of loading the encrypted string. Pass a pointer to this class as the second parameter.

        Third, you need to implement the decoding algorithm and pass a pointer to the entry function
        as the third parameter.

        It is also important to have the original file in the correct location for YARA rule application.
        The IDB contains the path of original file from when the IDB was created, but if the file isn't there,
        this script will check the IDB's current directory for a file with the same name and same md5.

        This script will also patch the encoded string with the decoded one unless patch = False.

    Throws:
        AttributeError - see StringTracer, SuperFunc_t
        OSError - The provided YARA file could not be opened.
        RuntimeError - see _yara_find_decode_functions
        TypeError - The provided Tracer does not extend StringTracer.
        ValueError - Could not find the file used to create the IDB.
                   - see EncodedString.get_bytes
    """
    global ENCODED_STRINGS
    global DECODED_STRINGS

    # We could just check if there is a 'search' method, but handle it this way to enforce conventions.
    if not issubclass(Tracer, StringTracer):
        logger.error("Tracer does not extend StringTracer!")
        return

    # Check that IDA actually knows where the original input file is.
    if not find_input_file():
        logger.error(
            "Unable to locate the file used to create the IDB: " + INPUT_FILE_PATH
        )
        return

    # Do the decoding.
    try:
        if inline:
            matches = yara.match_strings(yara_rule)
            ENCODED_STRINGS = find_encoded_strings_inline(matches, Tracer)
        else:
            decode_functions = yara_find_decode_functions(yara_rule, func_name)
            ENCODED_STRINGS = find_encoded_strings(decode_functions, Tracer)
        ENCODED_STRINGS = decode_strings(ENCODED_STRINGS, decode)
        ENCODED_STRINGS = sorted(set(ENCODED_STRINGS))
        for string in ENCODED_STRINGS:
            string.publish(patch=patch)
        return ENCODED_STRINGS
    except RuntimeError as e:
        logger.error(
            "The provided YARA rule failed to match. No strings can be decrypted for this YARA rule."
        )
        return


idc.auto_wait()  # Force wait on import just to be sure
