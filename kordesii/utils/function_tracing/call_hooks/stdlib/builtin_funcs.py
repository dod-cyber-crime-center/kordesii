"""
Common standard C library builtin functions.
"""

import logging
import re

from ... import utils
from ... import constants
from ...call_hooks import builtin_func

logger = logging.getLogger(__name__)


@builtin_func("_alloca")
@builtin_func("_malloca")
def _alloca(cpu_context, func_name, func_args):
    """
    Allocates stack space

    NOTE: Our memory controller will automatically allocate pages as it writes.
    Therefore, we don't actually need to allocate anything, just provide them with
    a pointer.
    """
    (size,) = func_args
    if size:
        size = utils.align_page_up(size)
        logger.debug("Allocating %d bytes of stack space.", size)
        # Returns a pointer to our allocated stack space.
        return cpu_context.sp - size


@builtin_func("malloc")
@builtin_func("calloc")
def malloc(cpu_context, func_name, func_args):
    """
    Allocates memory block
    """
    if func_name == "calloc":
        num, size = func_args
        size = num * size
    else:
        (size,) = func_args
    if size:
        logger.debug("Allocating %d bytes of memory.", size)
        return cpu_context.mem_alloc(size)


@builtin_func
def new(cpu_context, func_name, func_args):
    """
    Allocates memory block
    """
    size = func_args[0]
    # If we have a second argument it's either a nothrow_value or a ptr to where they
    # want us to allocate the space.
    # Just assume its a ptr if it's not 0 since the emulator should not produce a nothrow_value correctly
    # and therefore be 0.
    # TODO: Perhaps provide more context to make a more informed decision.
    try:
        ptr = func_args[1]
    except IndexError:
        ptr = 0
    if size:
        if ptr:
            logger.debug("Mapping %d bytes into 0x%X", size, ptr)
            # If a pointer was provided, just give it back to them without doing anything.
            # Our memory controller will automatically allocate pages as they are being written.
            return ptr

        logger.debug("Allocating %d bytes of memory.", size)
        return cpu_context.mem_alloc(size)


@builtin_func
def realloc(cpu_context, func_name, func_args):
    """
    Reallocates memory block
    """
    ptr, size = func_args
    if ptr and size:
        logger.debug("Reallocating 0x%X with %d bytes.", ptr, size)
        return cpu_context.mem_realloc(ptr, size)


@builtin_func
def memchr(cpu_context, func_name, func_args):
    """
    Locate character in block of memory.

    Searches within the first num bytes of the block of memory pointed by data_ptr
    for the first occurrence of value (interpreted as an unsigned char) and returns a pointer
    to it.
    """
    data_ptr, value, num = func_args

    ptr = cpu_context.memory.find(value, start=data_ptr, end=data_ptr + num)
    if ptr == -1:
        return 0

    return ptr


@builtin_func("memmove")
@builtin_func("memmove_s")
@builtin_func("wmemmove")
@builtin_func("wmemmove_s")
@builtin_func("memcpy")
@builtin_func("memcpy_s")
@builtin_func("wmemcpy")
@builtin_func("wmemcpy_s")
def memcpy(cpu_context, func_name, func_args):
    """
    Copies count characters from src to dst.
    """
    secure = func_name.endswith("_s")
    wide = func_name.startswith("w")
    if secure:
        dst, dst_size, src, count = func_args
        count = min(dst_size, count)
    else:
        dst, src, count = func_args

    if wide:
        count *= 2

    if dst and src:
        logger.debug("Copying %d bytes from 0x%X to 0x%X", count, src, dst)
        cpu_context.mem_copy(src, dst, count)
        return 0 if secure else dst


@builtin_func
def memset(cpu_context, func_name, func_args):
    """
    Writes count number of ch characters to dst.
    """
    dst, ch, count = func_args
    if dst:
        logger.debug("Writing %r * %d to 0x%X", chr(ch), count, dst)
        cpu_context.mem_write(dst, bytes([ch]) * count)
    return dst


@builtin_func
def memcmp(cpu_context, func_name, func_args):
    lhs, rhs, count = func_args
    if lhs and rhs:
        logger.debug("Comparing the first %d bytes in 0x%X with 0x%X", count, lhs, rhs)
        left = cpu_context.mem_read(lhs, count)
        right = cpu_context.mem_read(rhs, count)
        if left < right:
            return -1

        if left > right:
            return 1

        return 0


@builtin_func("strcat")
@builtin_func("strcat_s")
@builtin_func("wcscat")
@builtin_func("wcscat_s")
@builtin_func("lstrcatA")
@builtin_func("lstrcatW")
def strcat(cpu_context, func_name, func_args):
    """
    Concatenates at most count characters from src, stopping if the null character
    is found, to the end of the null-terminated byte string pointed to by dst.
    The src[0] replaces the null terminator at the end of dst.
    """
    secure = func_name.endswith("_s")
    wide = func_name.startswith("w") or func_name.endswith("W")
    if secure:
        dst, dst_size, src = func_args
        if wide:
            dst_size *= 2
    else:
        dst, src = func_args
        dst_size = None

    if dst and src:
        logger.debug("Concatenating c string in 0x%X to c string in 0x%X", src, dst)
        append_str = cpu_context.read_data(src, data_type=constants.WIDE_STRING if wide else constants.STRING)
        dest_str = cpu_context.read_data(dst, data_type=constants.WIDE_STRING if wide else constants.STRING)
        null_offset = dst + len(dest_str)
        if dst_size is not None:
            dst_size -= null_offset - dst
            append_str = append_str[:dst_size]
        terminator = b"\0\0" if wide else b"\0"
        cpu_context.mem_write(null_offset, append_str + terminator)
        return 0 if secure else dst


@builtin_func("strncat")
@builtin_func("strncat_s")
@builtin_func("wcsncat")
@builtin_func("wcsncat_s")
def strncat(cpu_context, func_name, func_args):
    """
    Concatenates at most count characters from src, stopping if the null character
    is found, to the end of the null-terminated byte string pointed to by dst.
    The src[0] replaces the null terminator at the end of dst.
    """
    secure = func_name.endswith("_s")
    wide = func_name.startswith("w")
    if secure:
        dst, dst_size, src, count = func_args
        if wide:
            dst_size *= 2
    else:
        dst, src, count = func_args
        dst_size = None
    if wide:
        count *= 2

    if dst and src:
        logger.debug("Concatenating c string in 0x%X to c string in 0x%X", src, dst)
        append_str = cpu_context.read_data(src, data_type=constants.WIDE_STRING if wide else constants.STRING)[:count]
        dest_str = cpu_context.read_data(dst, data_type=constants.WIDE_STRING if wide else constants.STRING)
        null_offset = dst + len(dest_str)
        if dst_size is not None:
            dst_size -= null_offset - dst
            append_str = append_str[:dst_size]
        terminator = b"\0\0" if wide else b"\0"
        cpu_context.mem_write(null_offset, append_str + terminator)
        return 0 if secure else dst


@builtin_func
def strpbrk(cpu_context, func_name, func_args):
    """
    Locate characters in string.

    Returns a pointer to the first occurrence of str1 of any of the characters
    that are part of str2, or a null pointer if there are no matches.
    """
    str1_ptr, str2_ptr = func_args
    str1 = cpu_context.read_data(str1_ptr)
    str2 = cpu_context.read_data(str2_ptr)

    for offset, ch in enumerate(str1):
        if ch in str2:
            return str1_ptr + offset
    return 0


@builtin_func("strchr")
@builtin_func("strrchr")
def strchr(cpu_context, func_name, func_args):
    """
    Locate first or last occurrence of character in string.
    """
    string_ptr, character = func_args
    string = cpu_context.read_data(string_ptr)

    if func_name == "strchr":
        offset = string.find(character)
    else:
        offset = string.rfind(character)

    if offset == -1:
        return 0

    return string_ptr + offset


@builtin_func("strcpy")
@builtin_func("strcpy_s")
@builtin_func("wcscpy")
@builtin_func("wcscpy_s")
@builtin_func("lstrcpyA")
@builtin_func("lstrcpyW")
def strcpy(cpu_context, func_name, func_args):
    """
    Copies the null-terminated byte string pointed to by src, including the null terminator, to dst.
    """
    secure = func_name.endswith("_s")
    wide = func_name.startswith("w") or func_name.endswith("W")
    if secure:
        dst, dst_size, src = func_args
        if wide:
            dst_size *= 2
    else:
        dst, src = func_args
        dst_size = None

    if dst and src:
        logger.debug("Copying c string in 0x%X to 0x%X", src, dst)
        terminator = b"\0\0" if wide else b"\0"
        src_str = cpu_context.read_data(src, data_type=constants.WIDE_STRING if wide else constants.STRING) + terminator
        size = len(src_str)
        if dst_size is not None:
            size = min(dst_size, size)  # limit to dst_size if secure.
        cpu_context.mem_copy(src, dst, size)
        return 0 if secure else dst


@builtin_func("strncpy")
@builtin_func("strncpy_s")
@builtin_func("wcsncpy")
@builtin_func("wcsncpy_s")
@builtin_func("lstrcpynA")
@builtin_func("lstrcpynW")
def strncpy(cpu_context, func_name, func_args):
    """
    Copies at most count characters of src (including the terminating null character) to dst
    but not any of the characters that follow the null character.
    For non-secure versions, if count is not reached, additional null characters are written to dst.
    """
    secure = func_name.endswith("_s")
    wide = func_name.startswith("w") or func_name.endswith("W")
    if secure:
        # Secure version has an extra dst_size argument used for validation, but we don't care to
        # throw errors if we don't have to!
        dst, _, src, count = func_args
    else:
        dst, src, count = func_args
    if wide:
        count *= 2

    if dst and src:
        logger.debug("Copying c string in 0x%X to 0x%X", src, dst)
        terminator = b"\0\0" if wide else b"\0"
        src_str = cpu_context.read_data(src, data_type=constants.WIDE_STRING if wide else constants.STRING) + terminator
        size = min(count, len(src_str))
        cpu_context.mem_copy(src, dst, size)
        # Non-secure version also pads the rest with null characters to reach count size
        if not secure and size < count:
            # As a safety check, we shouldn't be writing more than about 0x1000 of padding.
            delta = count - size
            if delta > 0x1000:
                logger.warning(
                    "Attempted to write %d bytes of padding. Ignoring request and using %d bytes "
                    "of padding instead.", delta, 0x1000)
                delta = 0x1000
            cpu_context.mem_write(src + size, b"\0" * delta)
        return 0 if secure else dst


@builtin_func
def strdup(cpu_context, func_name, func_args):
    """
    Returns a pointer to a null-terminated byte string, which is a duplicate of the string
    pointing to by str.
    """
    (str_ptr,) = func_args
    if str_ptr:
        logger.debug("Copying c string in 0x%X to new pointer.", str_ptr)
        null_offset = cpu_context.memory.find(b"\0", start=str_ptr)
        size = null_offset - str_ptr
        # create new pointer
        new_ptr = cpu_context.mem_alloc(size + 1)
        # Copy at most size bytes of data then add the null terminator.
        cpu_context.mem_copy(str_ptr, new_ptr, size)
        cpu_context.mem_write(new_ptr + size, b"\0")
        return new_ptr


@builtin_func
def strndup(cpu_context, func_name, func_args):
    """
    Returns a pointer to a null-terminated byte string, which contains copies
    of at most size bytes from the string pointed to by str.
    """
    str_ptr, size = func_args
    if str_ptr:
        logger.debug("Copying %d bytes of c string in 0x%X to new pointer.", size, str_ptr)
        null_offset = cpu_context.memory.find(b"\0", start=str_ptr)
        size = min(size, null_offset - str_ptr)
        # create new pointer
        new_ptr = cpu_context.mem_alloc(size + 1)
        # Copy at most size bytes of data then add the null terminator.
        cpu_context.mem_copy(str_ptr, new_ptr, size)
        cpu_context.mem_write(new_ptr + size, b"\0")
        return new_ptr


@builtin_func("strlen")
@builtin_func("strnlen_s")
@builtin_func("wcslen")
@builtin_func("wcsnlen_s")
@builtin_func("lstrlenA")
@builtin_func("lstrlenW")
def strlen(cpu_context, func_name, func_args):
    """
    Returns the length of the given null-terminated byte string.
    """
    secure = func_name.endswith("_s")
    wide = func_name.startswith("w") or func_name.endswith("W")
    if secure:
        str_ptr, strsz = func_args
    else:
        (str_ptr,) = func_args
        strsz = None

    if str_ptr:
        logger.debug("Getting length of c string in 0x%X", str_ptr)
        sstr = cpu_context.read_data(str_ptr, data_type=constants.WIDE_STRING if wide else constants.STRING)
        size = len(sstr)
        if wide:
            size /= 2
        # For secure version, strsz is returned if the terminator was not found
        # in the first strsz characters.
        if strsz is not None and size > strsz:
            return strsz
        return size


@builtin_func
def strstr(cpu_context, func_name, func_args):
    """
    Locate substring.

    Returns a pointer to the first occurrence of str2 in str1, or a null pointer if str2 is not part of str1.
    """
    str1_ptr, str2_ptr = func_args
    str1 = cpu_context.read_data(str1_ptr)
    str2 = cpu_context.read_data(str2_ptr)

    offset = str1.find(str2)
    if offset == -1:
        return 0

    return str1_ptr + offset


@builtin_func
def sprintf(ctx, func_name, func_args):
    """
    Format a string based on provided format string and parameters.

    For sprintf, there's no way to know up front how many args are needed, but there should always be at least
    2 (destination and format).  We can use the format string to determine how many arguments we need by
    counting the format specifiers.
    """
    # Almost guaranteed to get the incorrect number of args.  So obtain the format string and count the number of
    # format specifiers to determine how many args we need, not including the first 2
    if len(func_args) < 2:   # Ensure that there are at least 2 arguments, dest and format
        # Need to try to get at least 2 arguments...
        func_args = ctx.get_function_args(num_args=2)

    dest = func_args[0]
    fmt = ctx.read_data(func_args[1])
    logger.debug("Format string: %s", fmt)

    # Format using best attempt here.  Basically, locate all the format specifiers, and convert them to a python
    # supported format string.  For each format string, extract the appropriate data from the context, and append it to
    # the values list.
    fmt_val_re = re.compile(br"""
    %                           # start with percent character
    [-+ #0]{0,1}                # optional flag character
    (\*|[0-9]{1,}){0,}          # optional width specifier, though mutually exclusive (either a number or *, not both)
    ((\.[0-9]{1,})|\.\*){0,}    # optional precision specifier, mutually exclusive
    [diuoxXfFeEgGaAcspn]        # format type
    """, re.VERBOSE)

    # NOTE: findall() produces empty results so we need to use finditer()
    fmt_vals = [match.group() for match in fmt_val_re.finditer(fmt)]
    logger.debug("Format vals: %r", fmt_vals)

    # Re-pull function arguments with correct number of arguments.
    func_args = ctx.get_function_args(num_args=2 + len(fmt_vals))

    format_vals = []
    arg_pos = 2  # skip destination and format string
    for match in fmt_vals:
        if b'*' in match:
            # Indicates that one of the parameters is a width, which must be pulled and added to the list first
            format_vals.append(func_args[arg_pos])
            arg_pos += 1

        if match.endswith(b'c'):  # character (will this be the value or a read from the context???
            arg_val = func_args[arg_pos]
            if arg_val <= 0xFF:  # assume that the argument contains the character
                format_vals.append(arg_val)
            else:   # assume it's a pointer that must be dereferenced
                format_vals.append(ctx.read_data(arg_val, size=1))

        elif match.endswith(b's'):  # string value, should be a pointer
            _arg = ctx.read_data(func_args[arg_pos])
            if not len(_arg):   # If the argument isn't set during parsing, preserve the formatting
                logger.debug("Pulled 0 byte format string, reverting")
                _arg = b"%s"
            format_vals.append(_arg)

        else:   # all other numerical types???
            format_vals.append(func_args[arg_pos])

        arg_pos += 1

    result = fmt % tuple(format_vals)
    logger.debug("Writing formatted value %s to 0x%X", result, dest)
    ctx.mem_write(dest, result + b'\0')
    return len(result)
