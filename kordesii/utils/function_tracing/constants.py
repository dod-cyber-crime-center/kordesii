"""Stores contants"""


# Define some datatypes that can be used for input to get the operand value
STRING = 0  # Represents a C-like string which is null terminated
WIDE_STRING = 1  # Represents a wide C-like string which is null terminated
BYTE_STRING = 2  # List a sequent of bytes of a specified size
BYTE = 3  # byte value
WORD = 4  # WORD value
DWORD = 5  # DWORD value
QWORD = 6  # QWORD value

STRING_TYPES = (STRING, WIDE_STRING, BYTE_STRING)
INT_TYPES = (BYTE, WORD, DWORD, QWORD)
DATA_TYPES = STRING_TYPES + INT_TYPES

SINGLE = 1  # Represents single precision for converting float to int or int to float
DOUBLE = 2  # Represents double precision for converting float to int or int to float
