"""
Interface for memory management.
"""

import idc
import ida_segment

import collections
import logging

from kordesii.utils import utils
from kordesii.utils.function_tracing.utils import get_bits


logger = logging.getLogger(__name__)


class Memory(object):
    """
    Class which implements the CPU memory controller backed by the segment data in the input file.

    This class provides a read() and write() function for CPU emulation.
    If a memory address has not been written to, null bytes will be returned.
    """

    PAGE_SIZE = 0x1000

    HEAP_BASE = idc.get_inf_attr(idc.INF_MAX_EA)
    # Slack space between heap allocations.
    HEAP_SLACK = 0x3000

    # maximum amount of memory allowed to read/write
    # (if we are reading/writing more than ~ 268 MB we have bigger problems.)
    MAX_MEM_READ = 0x10000000
    MAX_MEM_WRITE = 0x10000000

    def __init__(self):
        self._pages = collections.defaultdict(lambda: bytearray(self.PAGE_SIZE))
        # A map of base addresses to size for heap allocations.
        self._heap_allocations = {}
        self._map_segments()

    def _map_segments(self):
        """Maps segments into memory."""
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            seg_bytes = utils.get_segment_bytes(seg.start_ea)
            self.write(seg.start_ea, seg_bytes)

    @property
    def blocks(self):
        """
        Returns a list of tuples containing the base address and size for
        contiguous blocks of memory.
        """
        # Collect ranges of continuous memory.
        memory_ranges = []
        base_address = None
        size = 0
        for page_index in sorted(self._pages):
            # First page of block?
            if base_address is None:
                base_address = page_index << 12

            size += self.PAGE_SIZE

            # Found end of continuous block of memory?
            if page_index + 1 not in self._pages:
                memory_ranges.append((base_address, size))
                base_address = None
                size = 0

        # Store last block
        if base_address is not None:
            memory_ranges.append((base_address, size))

        return memory_ranges

    def __str__(self):
        """
        Print information about current memory map.
        """
        # Create text output.
        _just = 25 if get_bits() == 32 else 50
        _hex_fmt = "0x{:08X}" if get_bits() == 32 else "0x{:016X}"
        title = "{}{}{}".format("Base Address".ljust(_just), "Address Range".ljust(_just), "Size")
        memory_ranges = []
        for base_address, size in self.blocks:
            memory_ranges.append("{}{}{}".format(
                _hex_fmt.format(base_address).ljust(_just),
                "{} - {}".format(_hex_fmt.format(base_address), _hex_fmt.format(base_address + size)).ljust(_just),
                size
            ))

        return "{}\n{}\n".format(title, "\n".join(memory_ranges))

    def is_mapped(self, address):
        return address >> 12 in self._pages

    def alloc(self, size):
        """
        Allocates heap region with size number of bytes.

        :param size: Number of bytes to allocate.
        :return: starting address of allocated memory.
        """
        # Allocate from HEAP_BASE if this is our first allocation.
        if not self._heap_allocations:
            address = self.HEAP_BASE
        # Otherwise, use the largest base address not used.
        # TODO: We may want to reuse previously freed space in the future.
        else:
            max_base_address, heap_size = sorted(self._heap_allocations.items())[-1]
            address = max_base_address + heap_size + self.HEAP_SLACK

        # NOTE: We are just going to record that the memory as been allocated
        # but not actually trigger any data from being written. (The calls to write() will do that)
        # This helps to prevent us from wasting (real) memory if someone allocates
        # a huge amount of memory but only uses a small amount.
        self._heap_allocations[address] = size
        logger.debug('[alloc] :: Allocated {} bytes at 0x{:X}'.format(size, address))
        return address

    def realloc(self, address, size):
        """
        Reallocates heap region with size number of bytes.

        :param address: base address to reallocate.
        :param size: Number of bytes to allocate.
        :return: address of the reallocated memory block.
        """
        # Passed in address should be the base address of a previously allocated memory region.
        if address not in self._heap_allocations:
            raise ValueError('0x{:X} address is not allocated.'.format(address))

        previous_size = self._heap_allocations[address]

        # See if we need to relocate the heap address.
        if size > previous_size:
            for base_address in sorted(self._heap_allocations):
                if address < base_address < address + size:
                    # We need to relocate the memory block.
                    new_address = self.alloc(size)
                    # Don't free the old, because the user may want to search it.
                    logger.debug('[realloc] :: Relocated 0x{:X} -> 0x{:X}'.format(address, new_address))
                    return new_address

        # Otherwise we just need to adjust the size.
        if previous_size != size:
            logger.debug('[realloc] :: Reallocating heap size at 0x{:X} from {} to {} bytes.'.format(
                address, previous_size, size))
            self._heap_allocations[address] = size
        return address

    def read(self, address, size):
        """
        Reads data from given address.

        :param address: Address to read data from.
        :param size: Number of bytes to read.

        :return: byte string of read data.
        """
        if address < 0:
            raise ValueError('Address must be a positive integer. Got 0x{:08X}'.format(address))
        if size < 0:
            raise ValueError('Size must be a positive integer.')
        if size > self.MAX_MEM_READ:
            logger.error(
                '[mem_read] :: Attempted to read {} bytes from 0x{:08X}. '
                'Ignoring request and reading {} bytes instead.'.format(
                    size, address, self.MAX_MEM_READ))
            size = self.MAX_MEM_READ

        logger.debug('[mem_read] :: Reading {} bytes from 0x{:08X}'.format(size, address))

        page_index = address >> 12
        page_offset = address & 0xfff

        # Read data from pages.
        out = bytearray()
        while size:
            # We don't want to trigger a page creation on read().. only write().
            page = self._pages.get(page_index, bytearray(self.PAGE_SIZE))
            read_bytes = page[page_offset:page_offset + size]
            out += read_bytes
            size -= len(read_bytes)
            page_offset = 0
            page_index += 1

        return bytes(out)

    def write(self, address, data):
        """
        Writes data to given address.

        :param address: Address to write data to.
        :param data: data to write
        """
        if address < 0:
            raise ValueError('Address must be a positive integer. Got 0x{:08X}'.format(address))
        size = len(data)
        if size > self.MAX_MEM_WRITE:
            logger.error(
                '[mem_read] :: Attempted to write {} bytes to 0x{:08X}. '
                'Ignoring request and using first {} bytes instead.'.format(
                    size, address, self.MAX_MEM_WRITE))
            data = data[:self.MAX_MEM_WRITE]

        logger.debug('[mem_write] :: Writing {} bytes to 0x{:08X}'.format(len(data), address))

        page_index = address >> 12
        page_offset = address & 0xfff

        # Write data into pages.
        while data:
            page = self._pages[page_index]
            split_index = self.PAGE_SIZE - page_offset
            to_write = data[:split_index]
            page[page_offset:page_offset + len(to_write)] = to_write
            data = data[split_index:]
            page_offset = 0
            page_index += 1

    def find(self, value, start=0, end=None):
        """
        Searches memory for given value.

        :param bytes value: byte string to search for
        :param int start: Starting address to start search (defaults to 0)
        :param int end: Optional ending address to end search

        :return int: address where value was located or -1 if not found

        :raises ValueError: If search value is larger than a page.
        """
        # We are not going to handle things that could expand beyond multiple pages
        if len(value) >= self.PAGE_SIZE:
            raise ValueError('Search value must be less than {} bytes, got {}'.format(
                self.PAGE_SIZE, len(value)))

        if end and end <= start:
            raise ValueError('Ending address must be greater than starting address.')

        page_index = start >> 12
        page_offset = start & 0xfff

        if end:
            end_page_index = end >> 12
            end_page_offset = end & 0xfff
        else:
            end_page_index = end_page_offset = None

        page = self._pages.get(page_index, bytearray(self.PAGE_SIZE))

        # First search for the entire value in the page.
        if end and end_page_index == page_index:
            # Since we end in this page, don't attempt to read overlap.
            offset = page.find(value, page_offset, end_page_offset)
            return page_index << 12 | offset

        offset = page.find(value, page_offset)
        if offset != -1:
            return page_index << 12 | offset

        # If we can't find it, try again with part of the next page attached
        # to account for data overlapping onto another page.
        _start = max(page_offset, self.PAGE_SIZE - len(value) + 1)
        _end = self.PAGE_SIZE + len(value) - 1
        if end and end_page_index == page_index + 1:
            _end = min(_end, self.PAGE_SIZE + end_page_offset)
        if _end == self.PAGE_SIZE + end_page_offset and _end <= _start:
            return -1

        next_page = self._pages.get(page_index + 1, bytearray(self.PAGE_SIZE))
        offset = (page + next_page).find(value, _start, _end)
        if offset != -1:
            return page_index << 12 | offset
        else:
            # Jump to the next mapped page to continue the search.
            # return -1 if there are no more pages beyond.
            for _page_index in sorted(self._pages):
                if _page_index > page_index:
                    # Stop searching pages if we surpass the end.
                    if end and end <= _page_index << 12:
                        return -1
                    return self.find(value, start=_page_index << 12, end=end)
            return -1

    def finditer(self, value, start=0, end=None):
        """
        Searches for all instances of value within memory.
        """
        while True:
            offset = self.find(value, start=start, end=end)
            if offset == -1:
                return
            yield offset
            start = offset + len(value)

    def find_in_segment(self, value, seg_name_or_ea):
        """
        Searches memory for given value within the range of a specific segment.

        :param bytes value: byte string to search for
        :param seg_name_or_ea: segment name or address within segment.

        :return int: address where value was located or -1 if not found
        """
        if isinstance(seg_name_or_ea, str):
            segment = ida_segment.get_segm_by_name(seg_name_or_ea)
        else:
            segment = ida_segment.getseg(seg_name_or_ea)

        return self.find(value, start=segment.start_ea, end=segment.end_ea)

    def finditer_in_segment(self, value, seg_name_or_ea):
        """
        Searches memory for given value within the range of a specific segment.

        :param bytes value: byte string to search for
        :param seg_name_or_ea: segment name or address withing segment.

        :return int: address where value was located or -1 if not found
        """
        if isinstance(seg_name_or_ea, str):
            segment = ida_segment.get_segm_by_name(seg_name_or_ea)
        else:
            segment = ida_segment.getseg(seg_name_or_ea)

        for offset in self.finditer(value, start=segment.start_ea, end=segment.end_ea):
            yield offset

    def find_in_heap(self, value):
        """
        Searches memory for given value within the allocated heap.

        :param bytes value: byte string to search for

        :return int: address where value was located or -1 if not found
        """
        return self.find(value, start=self.HEAP_BASE)

    def finditer_in_heap(self, value):
        """
        Searches memory for given value within the allocated heap.

        :param bytes value: byte string to search for

        :return int: address where value was located or -1 if not found
        """
        for offset in self.finditer(value, start=self.HEAP_BASE):
            yield offset
