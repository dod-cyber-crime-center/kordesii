"""
Implements the "hardware" for tracing a function.

Will perform the instructions and updates CPU registers, stack information, etc.
"""

# Python libraries
from copy import deepcopy
import logging
import itertools
import math

# IDAPython libraries
import idaapi
import idautils
import idc

# kordesii imports
import kordesii.kordesiiidahelper as kordesiiidahelper

from kordesii.utils.function_tracingutils import utils
from kordesii.utils.function_tracingutils.constants import *

# create logger
# HACKY work around for allowing for enabling/disabling of debug statements
import os
tracing_cpu_logger = logging.getLogger("tracing_cpu")
DEBUG = os.environ.get("ENABLE_DEBUG", "False")
if DEBUG == "True":
    tracing_cpu_logger.debug = kordesiiidahelper.append_debug


class MemController(object):
    """
    Class which implements the CPU memory controller.  Used to fetch data from memory
    when required by the current instruction.  This class contains it's own memory map
    in the form of a dictionary to track changes.  If the requested data is not found
    in the dictionary, it is accessed from the input file.
    """

    def __init__(self):
        self._memmap = {}

    def get_base_address(self, address):
        """
        Get the base address for a block in which address is contained.

        :param int address: address to locate

        :return: int
        """
        for addr in sorted(self._memmap):
            if addr <= address < addr + len(self._memmap[addr]):
                return addr

        return -1

    def is_base_address(self, address):
        """
        Determine if the address is a base address for a memory block.

        :param int address: address to check

        :return: boolean
        """
        return address in self._memmap

    def is_mapped(self, address):
        """
        Determine if the address is currently mapped into memory.

        :param int address: address to check for

        :return bool: boolean
        """
        return self.get_base_address(address) != -1

    def _append_block(self, base_address, size):
        """
        Simply extend the block at block_address by size bytes

        :param int base_address: address of block to be extend

        :param int size: size of bytes to extend by

        :return:
        """
        self._memmap[base_address] += bytearray(size)

    def _prepend_block(self, new_base, old_base, size):
        """
        Prepend size bytes to an already existing block and rebase the block and remove the original base from the map

        :param int new_base: the new base address for the extend block

        :param int old_base: base address for block being prepended

        :param int size: size of bytes to prepend

        :return:
        """
        # Create and prepend a new block to a currently existing block, and add it to the dictionary with a new key
        self._memmap[new_base] = bytearray(size) + self._memmap[old_base]
        # Remove the original block
        self._memmap.pop(old_base)

    def _join_blocks(self, min_base, max_base, size):
        """
        Join two previously disjoint blocks of memory and remove the original high addressed block from the map.

        :param int min_base: the low addressed block's base address

        :param int max_base: the high addressed block's base address

        :param int size: size of data required to join the blocks into a single block

        :return:
        """
        # First a new chunk of memory of size <size> and the max_base data will be concatenated to the block at 
        # min_base
        self._memmap[min_base] += bytearray(size) + self._memmap[max_base]
        # Remove the original block at max_base
        self._memmap.pop(max_base)

    def map(self, address, size):
        """
        Map memory into the memory controller.  This is a non-trivial task as several scenarios must be accounted for.
         - = Already allocated
         * = New request
         $ = Overlap of already allocated and new
         . = Not allocated

            1. Is the memory block already completely allocated?
                -------------$$$$$$$$$$$$$-----------
            
            2. Is the memory block partially allocated starting from its base address?
                -----------$$$$$$$$******************
            
            3. Is the memory block partially allocated from an arbitrary address within the block?
                ***********$$$$$$$$------------------
            
            4. Is none of the memory block allocated, but the base is immediately adjacent to the last address of
                already allocated memory?
                ------------------------*************
            
            5. Is none of the memory block allocated, but the end address is immediately adjacent to the base address
                of already allocated memory?
                *************------------------------
            
            6. Is a low chunk and a high chunk of memory already allocated?
                $$$$$$$$$$$****************$$$$$$$$$$
            
            7. Is the memory block disjointed from all other allocated memory?
                ----------------........*************

        :param int address: address where block begins

        :param int size: size of block to allocate
        """
        # Acquire some preliminary information about the requested block
        max_address = address + size - 1  # Max address in requested block
        is_min_mapped = self.is_mapped(address)  # If true, at least low addressed chunk is mapped
        is_max_mapped = self.is_mapped(max_address)  # If true, at least hi addressed chunk is mapped
        min_base = None  # Holds base address of already mapped memory containing requested base address.
        max_base = None  # Holds base address of already mapped memory containing requested max address.
        if is_min_mapped:
            min_base = self.get_base_address(address)

        if is_max_mapped:
            max_base = self.get_base_address(max_address)

        # If both address and max_address are mapped and are contained within the same block, then there's nothing to
        # be done as the entire block is already mapped.  This handles scenario 1 in the comments.
        if is_min_mapped and is_max_mapped and min_base == max_base:
            return

        # If only the requested address is mapped, then we need to extend an already existing block by the value:
        #   max_address - already_existing_block_max_address
        # This handles scenario 2 above.
        if is_min_mapped and not is_max_mapped:
            extend_size = max_address - (min_base + len(self._memmap[min_base]))
            self._append_block(min_base, extend_size)

        # If only the block's max address is mapped, then we need to prepend to an already existing block by the value:
        #   max_base - address
        # This handles scenario 3 above.
        elif not is_min_mapped and is_max_mapped:
            prepend_size = max_base - address
            self._prepend_block(address, max_base, prepend_size)

        # If both the min and max address are mapped, but min_base != max_base, then 2 disjoint blocks will be
        # combined.  The amount of data between the two disjoint blocks will be the difference between the min_base's
        # max address and max_base base address.
        # This handles scenrio 6 above
        elif is_min_mapped and is_max_mapped:
            join_size = max_base - (min_base + len(self._memmap[min_base]))
            self._join_blocks(min_base, max_base, join_size)

        else:
            # If (address - 1) is mapped, then the requested block is going to be immediately following an existing 
            # block, so this will just be an append.  This handles scenario 4 above.
            if self.is_mapped(address - 1):
                self._append_block(self.get_base_address(address - 1), size)

            # if (address + size) is mapped, then the requested block is immediately before an existing block,
            # so this will just be a prepend.  This handles scenario 5 above.
            elif self.is_mapped(address + size):
                self._prepend_block(address, address + size, size)

            # If this point is reached, then this is a disjoing memory block request and it can just be created.  This
            # handles scenario 7 above.
            else:
                self._memmap[address] = bytearray(size)

    def read(self, offset, size):
        """
        Read the data at the specified offset of the specified size.

        :param int offset: offset where data is located

        :param int size: size of data requested

        :return bytes: retrieved data
        """
        if offset in self._memmap:
            return str(self._memmap[offset][:size])

        for key_offset in sorted(self._memmap, reverse=True):
            if key_offset < offset:
                read_offset = offset - key_offset
                return str(self._memmap[key_offset][read_offset:read_offset + size])

    def write(self, offset, data):
        """
        Write the data to the specified address, which is actually just an entry in the
        memory map.

        :param int offset: offset of location to write data

        :param bytes data: data to be written, **must be a string***
        """
        if not isinstance(data, bytes):
            raise TypeError("Data written to 0x{:08X} must be bytes, not {}".format(offset, type(data)))
            
        if offset in self._memmap:
            self._memmap[offset][:len(data)] = data
        else:
            for key_offset in sorted(self._memmap, reverse=True):
                if key_offset < offset:
                    break
            else:
                raise AssertionError('Failed to find key_offset.')

            write_offset = offset - key_offset
            self._memmap[key_offset][write_offset:write_offset + len(data)] = data

    def search_block(self, offset, val):
        """
        Search a memory block containing the specified offset from that offset for the specified val.  Return the 
        offset of the location where val was located within the block.  This function will not span blocks.

        :param int offset: offset of location to search from
        :param str val: byte string to search for
        :return int: location where val was located, -1 if not found
        """
        block_base = self.get_base_address(offset)
        if block_base == -1:
            raise ValueError("Offset 0x{:X} is not mapped.".format(offset))

        loc = self._memmap[block_base].find(val, offset - block_base)
        return loc if loc == -1 else (loc + offset)

    def __repr__(self):
        """
        Print information about current memory map.
        """
        output = "Base Address\t\tAddress Range\t\t\t\tSize\n{}"
        temp = []
        for base_addr in sorted(self._memmap):
            addr_size = len(self._memmap[base_addr])
            temp.append("0x{:X}\t\t0x{:X} - 0x{:X}\t\t{}".format(base_addr, base_addr, base_addr + addr_size, addr_size))

        return output.format("\n".join(temp))

    def __str__(self):
        return self.__repr__()



class Register(object):
    """
    Provides access to a register family.

    :param size int: size of register in bytes
    :param **masks: maps member names to a mask of the register value it corresponds to.

    >>> reg = Register(8, rax=0xFFFFFFFFFFFFFFFF, eax=0xFFFFFFFF, ax=0xFFFF, al=0xFF, ah=0xFF00)
    >>> reg.rax
    0
    >>> reg.ax
    0
    >>> reg.ah = 0x23
    >>> reg.ah
    0x23
    >>> reg.ax
    0x2300
    >>> reg.eax
    0x00002300
    >>> reg.eax = 0x123
    >>> reg.al
    0x23
    >>> reg.ah
    0x01
    >>> reg.rax
    0x0000000000000123
    """

    def __init__(self, size, **masks):
        # TODO: Auto get size based on largest register (or leftmost 1)?
        self.__dict__['size'] = size
        self.__dict__['_size_mask'] = 2**(8 * size) - 1
        self.__dict__['_value'] = 0

        _masks = {}
        for name, mask in masks.items():
            # Get position of rightmost set bit in mask
            shift = int(math.log(mask & ~(mask - 1), 2))
            _masks[name.lower()] = (mask, shift)
        self.__dict__['_masks'] = _masks
        self.__dict__['names'] = _masks.keys()

    def __deepcopy__(self, memo):
        copy = Register(self.size)
        copy.__dict__['_masks'] = dict(self._masks)
        copy.__dict__['names'] = copy._masks.keys()
        copy.__dict__['_value'] = self._value
        return copy

    def __getattr__(self, reg_name):
        reg_name = reg_name.lower()
        try:
            mask, shift = self._masks[reg_name]
        except KeyError:
            raise AttributeError('Invalid register name: {}'.format(reg_name))
        return (self._value & mask) >> shift

    def __getitem__(self, reg_name):
        return self.__getattr__(reg_name)

    def __setattr__(self, reg_name, value):
        reg_name = reg_name.lower()
        try:
            mask, shift = self._masks[reg_name]
        except KeyError:
            raise AttributeError('Invalid register name: {}'.format(reg_name))
        assert isinstance(value, (int, long))
        self.__dict__['_value'] = (self._value & (mask ^ self._size_mask)) | ((value & (mask >> shift)) << shift)

    def __setitem__(self, reg_name, value):
        self.__setattr__(reg_name, value)

    def __contains__(self, reg_name):
        return reg_name.lower() in self._masks


class RegisterMap(object):
    """
    Holds register families and allows for direct access.

    This class contains all the CPU registers.  It is updated by both the CPU class, which
    updates the main CPU registers and the Processor class, which will update FLAGS.
    """

    def __init__(self, registers):
        """
        :param registers: list of Register instances
        """
        self.__dict__['_registers'] = registers

        # Build a hash table mapping member names to registers.
        # (This also validates that we have no collisions while we are at it.)
        reg_map = {}
        for register in registers:
            for name in register.names:
                if name in reg_map:
                    raise RuntimeError('Duplicate register name: {}'.format(name))
                reg_map[name] = register
        self.__dict__['_reg_map'] = reg_map

    def __deepcopy__(self, memo):
        return RegisterMap([deepcopy(reg) for reg in self._registers])

    def __getattr__(self, reg_name):
        reg_name = reg_name.lower()
        try:
            register = self._reg_map[reg_name]
        except KeyError:
            raise AttributeError('Invalid register: {}'.format(reg_name))
        return register[reg_name]

    def __getitem__(self, reg_name):
        return self.__getattr__(reg_name)

    def __setattr__(self, reg_name, value):
        reg_name = reg_name.lower()
        try:
            register = self._reg_map[reg_name]
        except KeyError:
            raise AttributeError('Invalid register: {}'.format(reg_name))
        register[reg_name] = value

    def __setitem__(self, reg_name, value):
        self.__setattr__(reg_name, value)


def x86_64_registers():
    """Initializes registers for x86/x64 architecture"""
    registers = [
        Register(8, rax=0xFFFFFFFFFFFFFFFF, eax=0xFFFFFFFF, ax=0xFFFF, al=0xFF, ah=0xFF00),
        Register(8, rbx=0xFFFFFFFFFFFFFFFF, ebx=0xFFFFFFFF, bx=0xFFFF, bl=0xFF, bh=0xFF00),
        Register(8, rcx=0xFFFFFFFFFFFFFFFF, ecx=0xFFFFFFFF, cx=0xFFFF, cl=0xFF, ch=0xFF00),
        Register(8, rdx=0xFFFFFFFFFFFFFFFF, edx=0xFFFFFFFF, dx=0xFFFF, dl=0xFF, dh=0xFF00),
        Register(8, rsi=0xFFFFFFFFFFFFFFFF, esi=0xFFFFFFFF, si=0xFFFF, sil=0xFF),
        Register(8, rdi=0xFFFFFFFFFFFFFFFF, edi=0xFFFFFFFF, di=0xFFFF, dil=0xFF),

        Register(8, rbp=0xFFFFFFFFFFFFFFFF, ebp=0xFFFFFFFF, bp=0xFFFF, bpl=0xFF),
        Register(8, rsp=0xFFFFFFFFFFFFFFFF, esp=0xFFFFFFFF, sp=0xFFFF, spl=0xFF),
        Register(8, rip=0xFFFFFFFFFFFFFFFF),

        Register(8, r8=0xFFFFFFFFFFFFFFFF, r8d=0xFFFFFFFF, r8w=0xFFFF, r8b=0xFF),
        Register(8, r9=0xFFFFFFFFFFFFFFFF, r9d=0xFFFFFFFF, r9w=0xFFFF, r9b=0xFF),
        Register(8, r10=0xFFFFFFFFFFFFFFFF, r10d=0xFFFFFFFF, r10w=0xFFFF, r10b=0xFF),
        Register(8, r11=0xFFFFFFFFFFFFFFFF, r11d=0xFFFFFFFF, r11w=0xFFFF, r11b=0xFF),
        Register(8, r12=0xFFFFFFFFFFFFFFFF, r12d=0xFFFFFFFF, r12w=0xFFFF, r12b=0xFF),
        Register(8, r13=0xFFFFFFFFFFFFFFFF, r13d=0xFFFFFFFF, r13w=0xFFFF, r13b=0xFF),
        Register(8, r14=0xFFFFFFFFFFFFFFFF, r14d=0xFFFFFFFF, r14w=0xFFFF, r14b=0xFF),
        Register(8, r15=0xFFFFFFFFFFFFFFFF, r15d=0xFFFFFFFF, r15w=0xFFFF, r15b=0xFF),

        Register(2, gs=0xFFFF),
        Register(2, fs=0xFFFF),
        Register(2, es=0xFFFF),
        Register(2, ds=0xFFFF),
        Register(2, cs=0xFFFF),
        Register(2, ss=0xFFFF),

        Register(16, xmm0=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm1=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm2=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm3=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm4=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm5=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm6=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm7=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm8=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm9=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm10=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm11=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm12=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm13=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm14=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        Register(16, xmm15=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),

        # FLAGS register
        Register(4, **{
            "cf": 0x1, "pf": 0x4, "af": 0x10, "zf": 0x40, "sf": 0x80,
            "tf": 0x100, "if": 0x200, "df": 0x400, "of": 0x800,
            "iopl": 0x2000, "nt": 0x4000,
            "rf": 0x10000, "vm": 0x20000, "ac": 0x40000,
            "vif": 0x80000, "vip": 0x100000, "id": 0x200000
        }),
    ]
    return RegisterMap(registers)


class ProcessorContext(object):
    """
    Stores the context of the processor during execution.
    """
    STACK_LIMIT = 0x117d000     # Minumum address stack can grow to
    STACK_BASE = 0x1180000      # Base address for stack

    RSP_OFFSET = 0x800
    RBP_OFFSET = 0x400

    def __init__(self):
        self.registers = x86_64_registers()
        self._memctrlr = MemController()
        self._bitness = utils.get_bits()
        self._byteness = self._bitness / 8
        self.init_context()

    def init_context(self):
        """
        Do some initialization of the CPU context
        """
        self.mem_map(self.STACK_LIMIT, self.STACK_BASE - self.STACK_LIMIT)
        self.reg_write("RSP", self.STACK_BASE - self.RSP_OFFSET)
        self.reg_write("RBP", self.STACK_BASE - self.RBP_OFFSET)

    def reg_read(self, reg):
        """
        Read a register value

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.reg_read("EIP")

        :param str reg: register name to be read

        :return int: value contained in specified register as int
        """
        assert isinstance(reg, str)
        return self.registers[reg.upper()]

    def reg_write(self, reg, val):
        """
        Write a register value

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.reg_write("EAX", 0xbaadf00d)

        :param str reg: register name to be written

        :param int val: value to be written to register as an int of width of the register (will be truncated as necessary)
        """
        assert isinstance(val, (int, long))
        assert isinstance(reg, str)
        self.registers[reg.upper()] = val

    def mem_map(self, address, size):
        """
        Map memory of size at the specified address.  Must be 4K page aligned.  Just a wrapper around memctrlr.map with
        the addition of page aligning.

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.mem_map(0xA0001000, 0x1000)

        :param int address: address to map memory at

        :param int size: size of memory to map (4K page aligned)
        """
        self._memctrlr.map(address, size)

    def map_segment(self, address):
        """
        Given an address, map the associated segment into memory so that it can be accesses correctly.

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.map_segment(0x1001A32C)

        :param int address: address within a segment to map
        """
        segStart = idc.SegStart(address)
        segEnd = idc.SegEnd(address)
        segSize = utils.align_page_up(segEnd - segStart)
        segRange = iter(itertools.count(segStart).next, (segStart + segSize))
        segBytes = str(bytearray(idc.Byte(i) if idc.isLoaded(i) else 0 for i in segRange))
        tracing_cpu_logger.debug(
            "[map_segment] :: Mapping memory for segment from 0x{:X}::0x{:X}".format(segStart, segStart + segSize))
        self.mem_write(segStart, segBytes, False)        

    def mem_read(self, address, size):
        """
        Read memory at the specified address of size size

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.mem_write(0xA0001000, "This is 16 bytes")
        >>> data = cpu_context.mem_read(0xA0001000, 16)
        >>> print "Data at 0xA0001000: {}".format(data)

        :param int address: address to read memory from

        :param int size: size of data to be read

        :return bytes: read data as bytes
        """
        if not self._memctrlr.is_mapped(address):
            # Check if the memory is loaded in IDA, if so, then map it
            try:
                # IDA 7 throws a AssertionError instead of BADADDR if segment doesn't exist.
                seg_start = idc.SegStart(address)
            except AssertionError:
                seg_start = None
            if seg_start is None or utils.signed(seg_start, utils.get_bits()) == -1:
                self.mem_map(address, utils.align_page_up(size))
            else:
                self.map_segment(address)
        
        if not self._memctrlr.is_mapped(address):
            raise ValueError(">>> 0x{:x} Requested memory address 0x{:x} was not properly mapped".format(
                self.reg_read("RIP"),
                address
                ))
                
        if not self._memctrlr.is_mapped(address + size):
            raise ValueError(">>> 0x{:x} Request to read past mapped memory region: 0x{:x}.".format(
                self.reg_read("RIP"),
                address + size))

        return self._memctrlr.read(address, size)

    def mem_write(self, address, data, align_page=True):
        """
        Write content contained in data to specified address

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.mem_write(0xA0001000, "This is 16 bytes")
        >>> data = cpu_context.mem_read(0xA0001000, 16)
        >>> print "Data at 0xA0001000: {}".format(data)

        :param int address: address to write data at

        :param bytes data: data to be written as bytes

        :param bool align_page: whether to align to 4K page or not
        """
        if not self._memctrlr.is_mapped(address) or not self._memctrlr.is_mapped(address + len(data)):
            tracing_cpu_logger.debug("[mem_write] :: Mapping memory block at 0x{:X} of size {}".format(address, len(data)))
            self.mem_map(address, utils.align_page_up(len(data)) if align_page else len(data))

        self._memctrlr.write(address, data)

    def mem_search_block(self, address, value):
        """
        Search memory block containing specified address for a specified value from the specified address.

        :param int address: address to search from
        :param str value: value to search for
        """
        return self._memctrlr.search_block(address, value)

    def get_value(self, addr, size=0, data_type=BYTE_STRING):
        """
        Reads a value for the specified address, of the specified size and will convert the resulting data into the
        specified type.

        :param int addr: address to read data from
        :param int size: size of data to read
        :param data_type: type of data to be extracted (default to byte string)
        """
        result = None
        if data_type == STRING:
            null_offset = self.mem_search_block(addr, '\0')
            result = self.mem_read(addr, null_offset - addr)
        elif data_type == WIDE_STRING:
            null_offset = self.mem_search_block(addr, "\0\0\0")
            result = self.mem_read(addr, null_offset - addr)
        elif data_type == BYTE_STRING:
            result = self.mem_read(addr, size)
        elif data_type == WORD:
            result = utils.struct_pack(self.mem_read(addr, 2))
        elif data_type == DWORD:
            result = utils.struct_pack(self.mem_read(addr, 4))
        elif data_type == QWORD:
            result = utils.struct_pack(self.mem_read(addr, 8))

        return result

    def get_operand_value(self, opnd, size=8, ip=None, data_type=BYTE_STRING):
        """
        Get the operand value requested from the current state and return it.

        >>> cpu_context = ProcessorContext()
        >>> value = cpu_context.get_operand_value(1, size=16)

        :param int opnd: the operand of interest (0 - first operand, 1 - second operand, ...)
        :param int size: size of data to be extracted (defaults to 8 bytes)
        :param int ip: location of instruction pointer to pull operand from (defaults to current eip in context)
        :param str data_type: data type to be extracted (defaults to byte string)

        :return: extracted data of specified type
        """
        if not ip:
            ip = self.reg_read("rip")

        optype = idc.GetOpType(ip, opnd)

        # Pull data based on operand type.
        if optype == idc.o_imm:
            # Just return an immediate value, ignoring the specified data type
            return idc.GetOperandValue(ip, opnd)

        elif optype == idc.o_reg:
            # If the operand is a register, do what we can to fulfill the user requested type.
            value = self.reg_read(idc.GetOpnd(ip, opnd).upper())
            # Make a byte string for consistency when return proper data type
            value = utils.struct_pack(value)

        elif optype in (idc.o_displ, idc.o_phrase):
            # Although these are different, they need to be handled similarly...
            try:
                offset = utils.get_stack_offset(self, ip, opnd)
            except ValueError:  # ValueError means it isn't a stack variable
                offset = utils.calc_displacement(self, ip, opnd)

            # Need to account for "lea" instructions here so we return the calculated value
            if idc.GetMnem(ip) == "lea":
                return offset
            value = self.mem_read(offset, size)

        elif optype == idc.o_mem:
            value = self.mem_read(idc.GetOperandValue(ip, opnd), size)

        else:
            raise AssertionError('Unexpected optype: {}'.format(optype))

        # Format data and return.
        if data_type == BYTE_STRING:
            # Return the appropriate length of the string based on the string type
            if data_type == BYTE_STRING:
                return value[:size]
            
        if data_type in (STRING, WIDE_STRING):
            null_term = value.find('\0') if data_type == STRING else value.find('\0\0\0')
            if 0 < null_term < size:
                return value[:null_term]
            else:
                return value[:size]

        if data_type == BYTE:
            return utils.struct_unpack(value[0])

        if data_type == WORD:
            return utils.struct_unpack(value[:2])

        if data_type == DWORD:
            return utils.struct_unpack(value[:4])

        if data_type == QWORD:
            return utils.struct_unpack(value[:8])

    def get_function_args(self, func_ea):
        """
        Returns the function argument values for this context based on the 
        given function.

        >>> cpu_context = ProcessorContext()
        >>> args = cpu_context.get_function_args(0x180011772)

        :param int func_ea: Ea of the function to pull a signature from.

        :returns: list of function arguments
        """
        # First get a func_type_data_t structure for the function
        funcdata = utils.get_function_data(func_ea)

        # Now use the data contained in funcdata to obtain the values for the arguments.
        args = []
        cur_esp = self.reg_read("RSP")  # Make it easier to read stack data...
        for i in xrange(funcdata.size()):
            loc_type = funcdata[i].argloc.atype()
            # Where was this parameter passed?
            if loc_type == 0:  # ALOC_NONE, not sure what this means...
                raise NotImplementedError("Argument {} location of type ALOC_NONE")
            elif loc_type == 1:  # ALOC_STACK
                # read the argument from the stack, since these are in order, just handle it with cur_esp
                arg = self.mem_read(cur_esp, self._byteness)
                args.append(utils.struct_unpack(arg))
                cur_esp += self._byteness
            elif loc_type == 2:  # ALOC_DIST, not sure what this means
                # funcdata[i].argloc.scattered()
                raise NotImplementedError("Argument {} location of type ALOC_DIST")
            elif loc_type == 3:  # ALOC_REG1, single register
                arg = self.reg_read(utils.REG_MAP.get(funcdata[i].argloc.reg1()))
                width = funcdata[i].type.get_size()
                args.append(arg & utils.get_mask(width))
            elif loc_type == 4:  # ALOC_REG2, register pair, not sure what this means
                # funcdata[i].argloc.reg2()
                raise NotImplementedError("Argument {} location of type ALOC_REG2")
            elif loc_type == 5:  # ALOC_RREL, register relative, not sure what this means
                # funcdata[i].argloc.get_rrel()
                raise NotImplementedError("Argument {} location of type ALOC_RREL")
            elif loc_type == 6:  # ALOC_STATIC, global address
                # funcdata[i].argloc.get_ea()
                raise NotImplementedError("Argument {} location of type ALOC_STATIC")
            elif loc_type >= 7:  # ALOC_CUSTOM, custom argloc
                # funcdata[i].argloc.get_custom()
                raise NotImplementedError("Argument {} location of type ALOC_CUSTOM")

        return args
