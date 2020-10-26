"""
Utilities for working with encoded strings.
"""
import functools
import logging
import re
import sys

import ida_name
import idaapi
import idc
import idautils

import kordesii
from kordesii.serialization import serializable_class
from kordesii.utils import function_tracing

logger = logging.getLogger(__name__)

# fmt: off
# Codecs used to detect encoding of strings.
CODE_PAGES = [
    "ascii",
    "utf-32-be", "utf-32-le", "utf-16-be", "utf-16-le", "utf-8",  # General (utf-7 omitted)
    "gb18030", "gbk",  # Unified Chinese
    "gb2312", "hz",  # Simplified Chinese
    "big5hkscs", "big5",  # Traditional Chinese (cp950 omitted)
    "koi8-r", "iso8859-5", "cp1251", "mac-cyrillic",  # Cyrillic (cp866, cp855 omitted)
    "cp949",  # Korean (johab, iso2022-kr omitted)
    "iso8859-6", "cp1256",  # Arabic (cp864, cp720 omitted)
    "latin1",  # If all else fails, latin1 is always is successful.
]
# fmt: on

# CODEC to use for displaying strings in IDA, etc.
DISPLAY_CODE = "cp437" if sys.platform == "win32" else "ascii"


@serializable_class
@functools.total_ordering
class EncodedString(object):
    """
    Object to hold data about an encoded/encrypted string.
    """

    _MAX_COMMENT_LENGTH = 130
    _MAX_NAME_LENGTH = 30

    # TODO: Since we must have either a string_location or encoded_data should we change
    #   the first parameter to be something like "encoded_data_or_location" and then
    #   check which it is by type?
    def __init__(
        self,
        string_location,
        string_reference=None,
        size=None,
        offset=None,
        key=None,
        encoded_data=None,
        code_page=None,
        dest=None,
    ):
        """
        Instantiate an EncodedString.

        :param string_location:
            Data segment pointer for static strings or stack pointer for stack strings.
        :param string_reference:
            The location the string is referenced from.
            This is required to pull the stack frame when string_location is a stack pointer.
        :param size: Size of the encoded data.
            When set encoded_data is populated using this and string_location.
        :param offset: Used when there is an offset based accessing scheme.
        :param key: Used when there is a key that can vary by string.
        :param encoded_data: encoded/encrypted data, if not provided data will be retrieved from IDA.
        :param code_page: known encoding page used to decode data to unicode (after data is decrypted)
            (code page is dynamically determined if not provided)
        :param dest: Location of decrypted data (if different from string_location)

        :raises ValueError: If both encoded_data and string_location is not provided.
        """
        self.string_location = string_location
        self.string_reference = string_reference
        self.offset = offset
        self.key = key
        self.decoded_data = None
        self.code_page = None
        self.dest = dest
        self._xrefs_to = None

        # Pull encoded_data from IDA if not provided.
        if encoded_data is None:
            if string_location is None:
                raise ValueError(
                    "encoded_data must be provided if string_location is None"
                )
            encoded_data = (
                self._get_bytes(string_location, size=size, code_page=code_page) or b""
            )

        if not isinstance(encoded_data, (bytes, list)):
            raise TypeError(
                "encoded_data must be type 'bytes', not '{!r}'".format(
                    type(encoded_data)
                )
            )

        self.encoded_data = encoded_data

    @classmethod
    def factory(
        cls,
        string_location,
        string_reference,
        size=None,
        offset=None,
        key=None,
        encoded_data=None,
        code_page=None,
        dest=None,
    ):
        """
        Factory function to generate an EncodedString or EncodedStackString based on type.

        :param string_location:
            Data segment pointer for static strings or stack pointer for stack strings.
        :param string_reference:
            The location the string is referenced from.
            This is required to pull the stack frame when string_location is a stack pointer.
        :param size: Size of the encoded data.
            When set encoded_data is populated using this and string_location.
        :param offset: Used when there is an offset based accessing scheme.
        :param key: Used when there is a key that can vary by string.
        :param encoded_data: encoded/encrypted data, if not provided data will be retrieved from IDA.
        :param code_page: known encoding page used to decode data to unicode (after data is decrypted)
            (code page is dynamically determined if not provided)
        :param dest: Location of decrypted data (if different from string_location)
        """
        if idc.is_loaded(string_location):
            return EncodedString(
                string_location,
                string_reference,
                size=size,
                offset=offset,
                key=key,
                encoded_data=encoded_data,
                code_page=code_page,
                dest=dest,
            )

        # otherwise assume string_location is a pointer within the stack
        # (using function_tracing's CPU emulator) and create an EncodedStackString object.
        stack = idc.get_func_attr(string_reference, idc.FUNCATTR_FRAME)
        # FIXME: This method isn't always super accurate because... IDA
        stack_offset = (
            string_location
            + function_tracing.RSP_OFFSET
            + idc.get_func_attr(string_reference, idc.FUNCATTR_FRSIZE)
            - function_tracing.STACK_BASE
        )
        if stack_offset < 0:
            logger.warning(
                "Ignoring negative stack offset {:#x} pulled from 0x{:X}".format(
                    stack_offset, string_location
                )
            )
            stack_offset = None

        return EncodedStackString(
            encoded_data,
            frame_id=stack,
            stack_offset=stack_offset,
            string_reference=string_reference,
            offset=offset,
            key=key,
            code_page=code_page,
            dest=dest,
        )

    def _compare_key(self):
        # Sort by where it was found then where it is referenced
        return (
            self.string_location or -1,
            self.string_reference or -1,
            self.decoded_data or b"",
        )

    def __hash__(self):
        return hash(self._compare_key())

    def __eq__(self, other):
        return self._compare_key() == other._compare_key()

    def __lt__(self, other):
        return self._compare_key() < other._compare_key()

    def report(self):
        """
        Generates a text report of the EncodedString object.

        :return str: Unicode string containing text report.
        """
        # We have to return repr as a unicode because of the decoded string.
        text = u""
        if self.string_location is not None:
            text += u"EA:  0x{:08X}\n".format(self.string_location)
        if self.string_reference is not None:
            text += u"Ref: 0x{:08X}\n".format(self.string_reference)
        if self.dest is not None:
            text += u"Dest: 0x{:08X}\n".format(self.dest)
        if self.offset is not None:
            text += u"Offset: 0x{:08X}\n".format(self.offset)
        if self.encoded_data:
            text += u"Raw Enc: {!r}\n".format(self.encoded_data)
        if self.decoded_data:
            text += u"Raw Dec: {!r}\n".format(self.decoded_data)
            dec_string = str(self)
            if self.code_page:
                text += u"Detected Code Page: {}\n".format(self.code_page)
            text += u"Dec: {}".format(dec_string)
        return text

    def __bytes__(self):
        return self.decoded_data

    def __str__(self):
        return self._decode_unknown_charset()

    def __unicode__(self):
        return self._decode_unknown_charset()

    def __repr__(self):
        encoded_data = self.encoded_data or b""
        if len(encoded_data) > 30:
            encoded_data = encoded_data[:30] + b" ..."
        return "<{!r} at 0x{:08x}>".format(
            encoded_data, self.string_location or self.string_reference
        )

    def __len__(self):
        return len(self.encoded_data)

    @property
    def xrefs_to(self):
        if self._xrefs_to is None:
            self._xrefs_to = [ref.frm for ref in idautils.XrefsTo(self.string_location)]
        return self._xrefs_to

    @property
    def display_name(self):
        """Returns an IDA friendly, printable name for the decoded string."""
        return str(self).encode(DISPLAY_CODE, "replace").decode(DISPLAY_CODE)

    def rename(self, name=None):
        """
        Renames (and comments) the string variable in IDA.

        :param str name: New name to given encoded string. (defaults to decoded_string)
        """
        name = name or self.display_name
        if not name:
            logger.warning(
                "Unable to rename encoded string due to no decoded string: {!r}".format(
                    self
                )
            )
            return

        # Add comment
        comment = '"{}"'.format(name[: self._MAX_COMMENT_LENGTH])
        if len(name) > self._MAX_COMMENT_LENGTH:
            comment += " (truncated)"
        if self.string_location is not None:
            idc.set_cmt(self.string_location, comment, 1)
        if self.string_reference is not None:
            idc.set_cmt(self.string_reference, comment, 1)
        if self.dest is not None:
            idc.set_cmt(self.dest, comment, 1)

        # Set variable name
        # To follow IDA conventions, the decoded string itself will be prefixed with 'a'
        # If a destination was provided, don't include any prefix, because this
        # is usually for resolved API functions.
        name = name[: self._MAX_NAME_LENGTH]
        if self.string_location is not None:
            ida_name.force_name(self.string_location, "a" + name)
        if self.dest is not None:
            # IDA will sometimes type API function pointers based on code analysis, and it's generic.  Unsetting the
            # type before the rename will cause IDA to properly type API functions if the type is known from the
            # loaded type libraries.
            idc.SetType(self.dest, '')
            ida_name.force_name(self.dest, name)

    def patch(self, fill_char=b'\x00', define=True):
        """
        Patches the original encoded string with the decoded string.

        :param str fill_char:
            Character to use to fill left over space if decoded data
            is shorter than its encoded data.
            Set to None leaving the original data.
        :param bool define: Whether to define the string after patching.
        """
        if not self.decoded_data or self.string_location is None:
            return
        decoded_data = self.decoded_data
        if fill_char:
            decoded_data += fill_char * (len(self.encoded_data) - len(decoded_data))
        try:
            idaapi.patch_bytes(self.start_ea, decoded_data)
            if define:
                self.define()
        except TypeError:
            logger.debug(
                "String type for decoded string from location 0x{:08x}.".format(
                    self.start_ea
                )
            )
        finally:
            return self

    # TODO: Can this just be embedded in patch()?
    def define(self):
        """
        Defines the string in the IDB.
        """
        try:
            idc.del_items(self.start_ea, idc.DELIT_SIMPLE, len(self.decoded_data))
            idaapi.create_strlit(
                self.start_ea, len(self.decoded_data), self.string_type
            )
        except Exception as e:
            logger.warning(
                "Unable to define string at 0x{:0X}: {}".format(self.start_ea, e)
            )

    def publish(self, rename=True, patch=True, fill_char=b'\x00', define=True):
        """
        - Saves encoded string to external kordesii Reporter
        - Prints a report about the string to the console
        - renames and patches the IDB with decoded data

        :param rename: Whether to rename the string in the IDB.
        :param patch: Whether to patch the string with the decoded variant in the IDB.
        :param str fill_char:
            Character to use to fill left over space if decoded data
            is shorter than its encoded data.
            Set to None leaving the original data.
        :param bool define: Whether to define the string after patching.
        """
        if not self.decoded_data:
            logger.warning(
                "Unable to publish string {!r}. Missing decoded_data.".format(self)
            )
            return

        # FIXME: Even though we strip nulls in __unicode__(), there still seems to be some strings
        # with null characters seeping through.
        kordesii.append_string(str(self).rstrip(u"\x00"))

        print("\n")
        display = self.report()
        print(display)

        if rename:
            self.rename()
        if patch:
            self.patch(fill_char=fill_char, define=define)

    @property
    def start_ea(self):
        if self.string_location in (None, idc.BADADDR):
            return -1
        else:
            return self.string_location + (self.offset or 0)

    @property
    def end_ea(self):
        start_ea = self.start_ea
        if start_ea is None:
            return -1
        else:
            return start_ea + len(self.decoded_data)

    @property
    def string_type(self):
        if not self.decoded_data:
            return None
        else:
            return (
                idc.STRTYPE_C_16
                if isinstance(self.decoded_data, str)
                else idc.STRTYPE_C
            )

    def _get_bytes(self, location, size=None, code_page=None):
        """
        Extracts bytes from given location.

        :param location: Location to pull bytes
        :param size: Number of bytes to pull (determines size by looking for terminator if not provided)
        :param code_page: Known code_page used to determine terminator.
        :return: bytes or None
        """
        # Determine size by looking for terminator.
        # (Use provided encoding to determine terminator width.)
        if size is None:
            width = 1
            if code_page:
                if "16" in code_page:
                    width = 2
                elif "32" in code_page:
                    width = 4
            end_location = idc.find_binary(location, idc.SEARCH_DOWN, "00 " * width)
            if end_location == idc.BADADDR:
                logger.warning("Failed to extract bytes from 0x{:08X}".format(location))
                return None

            size = end_location - location
            while size % width:  # ensure unicode strings are a valid length
                size += 1

        # Pull size amount of bytes from IDA.
        data = idc.get_bytes(location, size)
        if data is None:
            logger.warning(
                "Failed to extract {} bytes from 0x{:08X}".format(size, location)
            )
        return data

    def _num_raw_bytes(self, string):
        """
        Returns the number of raw bytes found in the given unicode string
        """
        count = 0
        for char in string:
            char = char.encode("unicode-escape")
            count += char.startswith(b"\\x") + char.startswith(b"\\u") * 2
        return count

    def _decode_unknown_charset(self):
        """
        Returns a decoded string using the best guess codec.
        """
        if not self.decoded_data:
            return u""

        # First see if the decoder already gave us unicode.
        if isinstance(self.decoded_data, str):
            return self.decoded_data

        # If a code page was set (either by us or the decoder) use that.
        # If the code page doesn't work... move on.
        if self.code_page:
            try:
                return self.decoded_data.decode(self.code_page)
            except UnicodeDecodeError:
                pass

        # TODO: Use chardet if they ever support utf16 without BOM.
        best_score = len(self.decoded_data)
        best_code_page = None
        best_output = None
        for code_page in CODE_PAGES:
            try:
                output = self.decoded_data.decode(code_page).rstrip(u"\x00")
            except UnicodeDecodeError:
                # If it's UTF we may need to strip away some null characters before decoding.
                if code_page in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
                    decoded_data = self.decoded_data
                    while decoded_data and decoded_data[-1] == 0:
                        try:
                            decoded_data = decoded_data[:-1]
                            output = decoded_data.decode(code_page).rstrip(u"\x00")
                        except UnicodeDecodeError:
                            continue
                        break  # successfully decoded
                    else:
                        continue
                # otherwise the code page isn't correct.
                else:
                    continue

            score = self._num_raw_bytes(output)
            if not best_output or score < best_score:
                best_score = score
                best_output = output
                best_code_page = code_page

        if best_output:
            self.code_page = best_code_page
            return best_output

        return u""


@serializable_class(skip_attrs=["xrefs_to"])
class EncodedStackString(EncodedString):
    """
    Variant of EncodedString that represents a string built from the stack.
    """

    def __init__(
        self,
        encoded_data,
        frame_id=None,
        stack_offset=None,
        memory_ptr=None,
        string_reference=None,
        offset=None,
        key=None,
        code_page=None,
        dest=None,
    ):
        """
        Instantiate an EncodedStackString object.

        :param encoded_data:
            encoded/encrypted data of string
            (This must be provided because stack strings don't have a string_location attribute.)
        :param frame_id: The id of the IDA frame containing the stack this string comes from.
        :param stack_offset: The offset within the IDA frame containing this string.
        :param memory_ptr: Optional extra argument to keep track of pointer to string in memory
            when using function_tracing.
        :param string_reference:
            The location the string is referenced from.
            This is required to pull the stack frame when string_location is a stack pointer.
        :param offset: Used when there is an offset based accessing scheme.
        :param key: Used when there is a key that can vary by string.
        :param code_page: known encoding page used to decode data to unicode (after data is decrypted)
            (code page is dynamically determined if not provided)
        :param dest: Location of decrypted data
        """
        super(EncodedStackString, self).__init__(
            None,
            string_reference=string_reference,
            offset=offset,
            key=key,
            encoded_data=encoded_data,
            code_page=code_page,
            dest=dest,
        )
        # Frame ID and Stack Offset are optional because it's not always easy to calculate this.
        self.frame_id = frame_id
        self.stack_offset = stack_offset
        # TODO: Remove memory_ptr, it should be manually added by the decoder after initialization
        # if they want to use it.
        # Optional extra argument to keep track of pointer to string in memory when using function_tracing.
        self.memory_ptr = memory_ptr

    def _compare_key(self):
        # Sort by where it was found and then by offset within stack.
        return (
            self.string_reference,
            self.frame_id,
            self.stack_offset,
            self.decoded_data,
        )

    def report(self):
        """
        General display format.

        :return unicode:
            A unicode string with the string's frame ID and stack offset,
            reference EA (where applicable), and the decoded value (where applicable).
        """
        text = u""
        if self.frame_id:
            text += u"Frame ID: 0x%X\n" % self.frame_id
        if self.stack_offset:
            text += u"Stack Offset: 0x%X\n" % self.stack_offset
        text += super(EncodedStackString, self).report()
        return text

    @property
    def xrefs_to(self):
        """
        Retrieves the xrefs to the stack variable.

        NOTE: This code is very SWIGGY because IDA did not properly expose this functionality.

        :raises ValueError: if frame_id, stack_offset, or string_reference was not provided.
            This is needed to determine what function to use.
        """
        if self._xrefs_to is None:
            if not self.string_reference:
                raise ValueError("Unable to get xrefs without string_reference.")
            if not (self.frame_id and self.stack_offset):
                raise ValueError(
                    "Unable to get xrefs without frame_id and stack_offset"
                )
            xrefs = idaapi.xreflist_t()
            frame = idaapi.get_frame(self.frame_id)
            func = idaapi.get_func(self.string_reference)
            member = idaapi.get_member(frame, self.stack_offset)
            idaapi.build_stkvar_xrefs(xrefs, func, member)
            self._xrefs_to = [ref.ea for ref in xrefs]
        return self._xrefs_to

    def rename(self, name=None):
        """
        Renames (and comments) the string variable in IDA.

        :param str name: New name to given encoded string. (defaults to decoded_string)
        """
        name = name or self.display_name
        if not name:
            logger.warning(
                "Unable to rename encoded string due to no decoded string: {!r}".format(
                    self
                )
            )

        # Set name and comment in stack variable.
        comment = '"{}"'.format(name[: self._MAX_COMMENT_LENGTH])
        if len(name) > self._MAX_COMMENT_LENGTH:
            comment += " (truncated)"
        if self.frame_id and self.stack_offset:
            idc.set_member_cmt(self.frame_id, self.stack_offset, comment, repeatable=1)
            var_name = re.sub(
                "[^_$?@0-9A-Za-z]", "_", name[: self._MAX_NAME_LENGTH]
            )  # Replace invalid characters
            if not var_name:
                raise ValueError("Unable to calculate var_name for : {!r}".format(self))
            var_name = "a" + var_name.capitalize()
            idc.set_member_name(self.frame_id, self.stack_offset, var_name)

        if self.dest is not None:
            ida_name.force_name(self.dest, name)

        # Add a comment where the string is being used.
        if self.string_reference:
            idc.set_cmt(self.string_reference, comment, 1)

    def patch(self, fill_char=None, define=True):
        """Does nothing, patching is not a thing for stack strings."""
        return self
