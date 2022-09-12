"""
Interface for memory management.
"""
from __future__ import annotations

import collections
import contextlib
import io
import os
import logging
from copy import deepcopy

import ida_bytes
import ida_segment
import idc

from kordesii.utils.function_tracing.utils import get_bits

logger = logging.getLogger(__name__)


class Stream(io.RawIOBase):
    """
    Creates a read-only file-like stream of the emulated memory.
    """

    def __init__(self, memory: Memory, start: int):
        self._memory = memory
        self._start = start
        self._offset = 0
        # Figure out which block we are in and use the end of the block as end.
        for base_address, size in memory.blocks:
            if start in range(base_address, base_address + size):
                self._end = size
                break
        else:
            raise RuntimeError(f"Failed to determine end address.")

    def readable(self) -> bool:
        return True

    def writeable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            return self.readall()
        size = min(self._end - self._offset, size)
        if size <= 0:
            return b""
        address = self.tell_address()
        data = self._memory.read(address, size)
        self._offset += len(data)
        return data

    def readline(self, size: int = 1) -> bytes:
        address = self.tell_address()
        end = self._memory.find(b"\n", start=address)
        if end == -1:
            return b""
        return self.read(end - address)

    def readall(self) -> bytes:
        return self.read(self._end - self._offset)

    def write(self, data: bytes) -> int:
        address = self.tell_address()
        num_bytes = self._memory.write(address, data)
        self._offset += num_bytes
        return num_bytes

    def tell(self) -> int:
        return self._offset

    def tell_address(self) -> int:
        return self._start + self._offset

    def seek(self, offset: int, whence=os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            if offset < 0:
                raise ValueError(f"Offset must be positive.")
            self._offset = offset
        elif whence == os.SEEK_CUR:
            self._offset = max(0, self._offset + offset)
        elif whence == os.SEEK_END:
            self._offset = min(self._end, self._end + offset)
        return self._offset

    def seek_address(self, address: int) -> int:
        return self.seek(address - self._start)


class PageMap(collections.defaultdict):
    """
    Dictionary of page indexes to pages.

    Creates a new page when missing.
    New pages uses the bytes from the IDB if in a segment.
    Segments pages will be mapped, but data retrieval will be delayed until the page
    is requested. (Helps to avoid unnecessary processing of large unused data segments.)
    """

    PAGE_SIZE = 0x1000

    # Cache of segment pages.
    # Used to prevent multiple calls to pull data from the IDB.
    _segment_cache = {}

    def __init__(self, map_segments=True):
        # Setting default_factory to None, because we have overwritten it in __missing__()
        super(PageMap, self).__init__(None)
        if map_segments:
            self.map_segments()

    def __deepcopy__(self, memo):
        copy = PageMap(map_segments=False)
        memo[id(self)] = copy
        copy.update({index: (page[:] if page is not None else None) for index, page in self.items()})
        return copy

    def __missing__(self, page_index):
        """
        Creates a new page when index first encountered.

        :return: page
        :rtype: bytearray
        """
        ret = self[page_index] = self._new_page(page_index)
        return ret

    def __getitem__(self, page_index):
        try:
            page = super(PageMap, self).__getitem__(page_index)
        except KeyError:
            return self.__missing__(page_index)

        # If page is None, that means this was set for delayed retrieval.
        # Retrieve page now that it is being requested.
        if page is None:
            return self.__missing__(page_index)

        return page

    def _is_delayed(self, page_index):
        """Determines if page is set for delayed retrieval."""
        return page_index in self and super(PageMap, self).__getitem__(page_index) is None

    def map_segments(self):
        """Sets segment pages for delayed retrieval"""
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if seg:
                for page_index in range(seg.start_ea >> 12, ((seg.end_ea - 1) >> 12) + 1):
                    self[page_index] = None

    @staticmethod
    def _obtain_bytes(start, end):
        """
        Obtain bytes efficiently, sets non-loaded bytes to \x00

        :param int start: starting address
        :param int end: ending address

        :return bytearray: bytearray containing bytes within range
        """
        # Reconstruct the segment, account for bytes which are not loaded.
        bytes_range = range(start, end)  # a range from start -> end
        return bytearray(ida_bytes.get_wide_byte(i) if idc.is_loaded(i) else 0 for i in bytes_range)

    def _new_page(self, page_index):
        """
        Creates a new page based on index.

        :return: page
        :rtype: bytearray
        """
        if page_index in self._segment_cache:
            return self._segment_cache[page_index][:]

        start_ea = page_index * self.PAGE_SIZE
        end_ea = start_ea + self.PAGE_SIZE

        # If page was set for delayed retrieval it is coming from segment data, so pull from IDB.
        # Update this check if ever use delayed retrieval for non-segment data.
        if self._is_delayed(page_index):
            logger.debug("Reading segment data 0x%X -> 0x%X from IDB", start_ea, end_ea)
            page = self._obtain_bytes(start_ea, end_ea)
            self._segment_cache[page_index] = page[:]  # cache page first
            return page

        # If range is not in a segment, provide a page of all zeros.
        return bytearray(self.PAGE_SIZE)

    def peek(self, page_index):
        """
        Returns the page for the given page index.
        If page doesn't exist, it creates the page but doesn't set it in the map.

        .. warning:: If you are using this you shouldn't try to modify the page since its
            effects may not propagate to the map.
            (ie. this is a read-only copy)

        :param page_index:
        :return: page
        :rtype: bytearray
        """
        if page_index in self and not self._is_delayed(page_index):
            return self[page_index]
        return self._new_page(page_index)


def clear_cache():
    """
    Clears the internal cache of segment bytes.
    Calling this will be necessary if you have patched in new bytes into the IDB.
    """
    PageMap._segment_cache = {}


class Memory:
    """
    Class which implements the CPU memory controller backed by the segment data in the input file.

    This class provides a read() and write() function for CPU emulation.
    If a memory address has not been written to, null bytes will be returned.
    """

    PAGE_SIZE = PageMap.PAGE_SIZE

    HEAP_BASE = idc.get_inf_attr(idc.INF_MAX_EA)
    # Slack space between heap allocations.
    HEAP_SLACK = 0x3000

    # maximum amount of memory allowed to read/write
    # (if we are reading/writing more than ~ 268 MB we have bigger problems.)
    MAX_MEM_READ = 0x10000000
    MAX_MEM_WRITE = 0x10000000

    def __init__(self, _copying=False):
        """Initializes Memory object."""
        self._pages = PageMap(map_segments=not _copying)
        # A map of base addresses to size for heap allocations.
        self._heap_allocations = {}

    def __deepcopy__(self, memo):
        copy = Memory(_copying=True)
        memo[id(self)] = copy
        copy._pages = deepcopy(self._pages, memo)
        copy._heap_allocations = self._heap_allocations.copy()
        return copy

    def open(self, start: int = None) -> Stream:
        """
        Opens memory as a file-like stream.

        :param start: Starting address for the window of data. (defaults to the address of the first allocated block)
        """
        if start is None:
            blocks = self.blocks
            if not blocks:
                raise ValueError("No memory blocks have been allocated.")
            start, _ = blocks[0]
        return Stream(self, start)

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
            memory_ranges.append(
                "{}{}{}".format(
                    _hex_fmt.format(base_address).ljust(_just),
                    "{} - {}".format(_hex_fmt.format(base_address), _hex_fmt.format(base_address + size)).ljust(_just),
                    size,
                )
            )

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
            max_base_address = max(self._heap_allocations)
            heap_size = self._heap_allocations[max_base_address]
            address = max_base_address + heap_size + self.HEAP_SLACK

        # NOTE: We are just going to record that the memory as been allocated
        # but not actually trigger any data from being written. (The calls to write() will do that)
        # This helps to prevent us from wasting (real) memory if someone allocates
        # a huge amount of memory but only uses a small amount.
        self._heap_allocations[address] = size
        logger.debug("Allocated %d bytes at 0x%08X", size, address)
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
            raise ValueError("0x{:X} address is not allocated.".format(address))

        previous_size = self._heap_allocations[address]

        # See if we need to relocate the heap address.
        if size > previous_size:
            for base_address in sorted(self._heap_allocations):
                if address < base_address < address + size:
                    # We need to relocate the memory block.
                    new_address = self.alloc(size)

                    # Copy over data from previous allocation.
                    # Since relocation is very rare, we will accept the loss in cycles
                    # if we end up writing emptyf data.
                    self.write(new_address, self.read(address, previous_size))

                    # Don't free the old, because the user may want to search it.
                    logger.debug("Relocated 0x%08X -> 0x%08X", address, new_address)
                    return new_address

        # Otherwise we just need to adjust the size.
        if previous_size != size:
            logger.debug(
                "Reallocating heap size at 0x%08X from %d to %d bytes.",
                address, previous_size, size
            )
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
            raise ValueError("Address must be a positive integer. Got 0x{:08X}".format(address))
        if size < 0:
            raise ValueError("Size must be a positive integer.")
        if size > self.MAX_MEM_READ:
            logger.error(
                "Attempted to read %d bytes from 0x%08X. "
                "Ignoring request and reading the first %d bytes instead.",
                size, address, self.MAX_MEM_READ
            )
            size = self.MAX_MEM_READ

        logger.debug("Reading %d bytes from 0x%08X", size, address)

        page_index = address >> 12
        page_offset = address & 0xFFF

        # Read data from pages.
        out = bytearray()
        while size:
            # We don't want to trigger a page creation on read().. only write().
            page = self._pages.peek(page_index)
            read_bytes = page[page_offset : page_offset + size]
            out += read_bytes
            size -= len(read_bytes)
            page_offset = 0
            page_index += 1

        return bytes(out)

    def write(self, address: int, data: bytes) -> int:
        """
        Writes data to given addre ss.

        :param address: Address to write data to.
        :param data: data to write
        :returns: Number of bytes written
        """
        if address < 0:
            raise ValueError("Address must be a positive integer. Got 0x{:08X}".format(address))

        size = len(data)
        if size > self.MAX_MEM_WRITE:
            logger.error(
                "Attempted to write %d bytes from 0x%08X. "
                "Ignoring request and writing the first %d bytes instead.",
                size, address, self.MAX_MEM_WRITE
            )
            data = data[: self.MAX_MEM_WRITE]
        size = len(data)

        logger.debug("Writing %d bytes to 0x%08X", size, address)

        page_index = address >> 12
        page_offset = address & 0xFFF

        # Write data into pages.
        while data:
            page = self._pages[page_index]
            split_index = self.PAGE_SIZE - page_offset
            to_write = data[:split_index]
            try:
                page[page_offset : page_offset + len(to_write)] = to_write
            except TypeError:
                raise TypeError("to_write: {} {}".format(type(to_write), repr(to_write)))
            data = data[split_index:]
            page_offset = 0
            page_index += 1

        return size

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
            raise ValueError("Search value must be less than {} bytes, got {}".format(self.PAGE_SIZE, len(value)))

        if end and end <= start:
            raise ValueError("Ending address must be greater than starting address.")

        page_index = start >> 12
        page_offset = start & 0xFFF

        if end:
            end_page_index = end >> 12
            end_page_offset = end & 0xFFF
        else:
            end_page_index = end_page_offset = None

        page = self._pages.peek(page_index)

        # First search for the entire value in the page.
        if end and end_page_index == page_index:
            # Since we end in this page, don't attempt to read overlap.
            offset = page.find(value, page_offset, end_page_offset)
            if offset <= -1:
                return -1
            return page_index << 12 | offset

        offset = page.find(value, page_offset)
        if offset > -1:
            return page_index << 12 | offset

        # If we can't find it, try again with part of the next page attached
        # to account for data overlapping onto another page.
        _start = max(page_offset, self.PAGE_SIZE - len(value) + 1)
        _end = self.PAGE_SIZE + len(value) - 1
        if end and end_page_index == page_index + 1:
            _end = min(_end, self.PAGE_SIZE + end_page_offset)
            if _end == self.PAGE_SIZE + end_page_offset and _end <= _start:
                return -1

        next_page = self._pages.peek(page_index + 1)
        offset = (page + next_page).find(value, _start, _end)
        if offset > -1:
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
