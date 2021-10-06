"""
Utilty functions for the ARM architecture.
"""



# region Shift Operations


def lsl(value, count, width=32):
    """Logical Shift Left"""
    value <<= count
    carry = (value & (1 << width)) >> width
    value &= (1 << width) - 1
    return carry, value


def lsr(value, count, width=32):
    """Logical Shift Right"""
    count %= width
    value &= (1 << width) - 1
     # First shift 1 to the left to leave room for the carry.
    value <<= 1
    value >>= count
    carry = value & 1
    value >>= 1
    return carry, value


def asr(value, count, width=32):
    """Arithmetic Shift Right (assuming unsigned input)"""
    count %= width
    value &= (1 << width) - 1
    msb = value >> (width - 1)
    value -= (1 << width) * msb  # Convert to signed.
    # First shift 1 to the left to leave room for the carry.
    value <<= 1
    value >>= count
    carry = value & 1
    value >>= 1
    value &= (1 << width) - 1  # Convert back to unsigned.
    return carry, value


def ror(value, count, width=32):
    """
    Rotate Right

    >>> ror(0xff, 4) == (1, 0xf000000f)
    True
    >>> ror(0xff00, 8, width=16) == (1, 0xff)
    True
    >>> ror(0x1, 2) == (0, 0x40000000)
    True
    """
    count %= width
    value &= (1 << width) - 1
    if not count:
        return 0, value
    # First rotate value count - 1 times
    value = (value >> (count - 1)) | (value << (width - (count - 1)))
    # Then pull out the carry before rotating one more time.
    carry = value & 1
    value = (value >> 1) | (value << (width - 1))
    value &= (1 << width) - 1
    return carry, value


def rrx(carry, value, count, width=32):
    """
    Rotate Right Extended
    (original carry must also be passed in)

    >>> rrx(0, 0xff, 4) == (1, 0xe000000f)
    True
    >>> rrx(1, 0xff, 4) == (1, 0xf000000f)
    True
    """
    count %= width
    value &= (1 << width) - 1
    # First shift 1 to the left to leave room for the carry.
    value <<= 1
    # Stick in the original carry.
    value |= carry & 1
    value = (value >> count) | (value << ((width + 1) - count))
    carry = value & 1
    value >>= 1
    value &= (1 << width) - 1
    return carry, value


# endregion
