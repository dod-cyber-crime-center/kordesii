"""
Interface for variable management.
"""

from builtins import map
from builtins import range
from builtins import object
from copy import deepcopy
import functools
import logging

import idc

from kordesii.utils.function_tracing import utils


logger = logging.getLogger(__name__)


class VariableMap(object):
    """Class that stores a set of variables that have been encountered during emulation."""

    def __init__(self, cpu_context):
        self._variables = {}
        self._cpu_context = cpu_context

    def __repr__(self):
        return "<VariableMap : \n\t{}\n>".format(
            "\n\t".join(map(repr, sorted(list(self._variables.values()), key=lambda var: var.addr)))
        )

    def __deepcopy__(self, memo):
        """
        Custom implementation of deepcopy to improve efficiency.
        """
        copy = VariableMap(deepcopy(self._cpu_context, memo))
        memo[id(self)] = copy
        copy._variables = {addr: deepcopy(variable, memo) for addr, variable in list(self._variables.items())}
        return copy

    def __getitem__(self, addr_or_name):
        """Gets a variable by name or address."""
        if isinstance(addr_or_name, str):
            for var in list(self._variables.values()):
                if addr_or_name == var.name:
                    return var
            raise KeyError("{} not found.".format(addr_or_name))
        elif isinstance(addr_or_name, int):
            return self._variables[addr_or_name]
        else:
            raise ValueError("Invalid variable name or address: {!r}".format(addr_or_name))

    def get(self, addr_or_name, default=None):
        """Gets a variable by name or address."""
        try:
            return self[addr_or_name]
        except (KeyError, ValueError):
            return default

    def at(self, ip):
        """
        Retrieves the variables referenced at the given instruction address.

        :param ip: Instruction address to get pointers from.
        :return: List of Variable objects that were found within the given instruction.

        :raises ValueError: If instruction has not been executed yet.
        """
        if ip not in self._cpu_context.executed_instructions:
            raise ValueError("Unable to get variables. Instruction at 0x{:0x} has not been executed.".format(ip))

        return [var for var in self if ip in var.references]

    def __setitem__(self, addr_or_name, variable):
        """Sets a variable by name or address."""
        if isinstance(addr_or_name, str):  # TODO
            raise NotImplementedError("Creating new variable by name is currently not supported.")
        elif isinstance(addr_or_name, int):
            self._variables[addr_or_name] = variable
        else:
            raise ValueError("Invalid variable name or address: {!r}".format(addr_or_name))

    def __contains__(self, addr_or_name):
        if isinstance(addr_or_name, str):
            for var in list(self._variables.values()):
                if addr_or_name == var.name:
                    return True
            return False
        elif isinstance(addr_or_name, int):
            return addr_or_name in self._variables
        else:
            raise ValueError("Invalid variable name or address: {!r}".format(addr_or_name))

    def __iter__(self):
        return iter(list(self._variables.values()))

    def add(self, addr, frame_id=None, stack_offset=None, reference=None):
        """
        Creates and adds a variable object to mapping by object

        If the variable already exists, this function does nothing.

        :return: Variable object that has been created or one that already exists.
        """
        if addr in self._variables:
            var = self._variables[addr]
        else:
            var = Variable(self._cpu_context, addr, frame_id=frame_id, stack_offset=stack_offset)
            # logger.debug('VariableMap :: Created variable: {!r}'.format(var))
            self._variables[addr] = var
        if reference:
            var.add_reference(reference)
        return var

    @property
    def names(self):
        return [var.name for var in list(self._variables.values())]

    @property
    def addrs(self):
        return list(self._variables.keys())

    @property
    def stack_variables(self):
        return [var for var in list(self._variables.values()) if var.is_stack]

    @property
    def global_variables(self):
        return [var for var in list(self._variables.values()) if not var.is_stack]


@functools.total_ordering
class Variable(object):
    """Stores information for a local / global variable for a specific CPU context state."""

    # Maps data types to their sizes.
    SIZE_MAP = {
        idc.FF_BYTE: 1,
        idc.FF_WORD: 2,
        idc.FF_DWORD: 4,
        idc.FF_QWORD: 8,
        idc.FF_OWORD: 16,
    }

    def __init__(self, cpu_context, addr, frame_id=None, stack_offset=None):
        if (frame_id is not None and stack_offset is None) or (frame_id is None and stack_offset is not None):
            raise ValueError("Both frame_id and stack_offset must be provided.")
        self._cpu_context = cpu_context
        self.addr = addr
        self.frame_id = frame_id
        self.stack_offset = stack_offset
        self.references = []  # list of instruction pointers where the variable was encountered.

    def __deepcopy__(self, memo):
        copy = self.__new__(self.__class__)
        memo[id(self)] = copy
        copy._cpu_context = deepcopy(self._cpu_context, memo)
        copy.addr = self.addr
        copy.frame_id = self.frame_id
        copy.stack_offset = self.stack_offset
        copy.references = list(self.references)
        return copy

    def __repr__(self):
        string = "<Variable {} : addr = 0x{:0x} : value = {!r} : size = {}".format(
            self.name, self.addr, self.value, self.size
        )
        if self.is_stack:
            string += " : frame_id = 0x{:0x} : stack_offset = {}".format(self.frame_id, self.stack_offset)
        string += ">"
        return string

    def __eq__(self, other):
        return self.addr == other.addr

    def __lt__(self, other):
        return self.addr < other.addr

    @property
    def is_stack(self):
        """True if variable is on stack."""
        return self.stack_offset is not None

    @property
    def is_func_ptr(self):
        return utils.is_func_ptr(self.addr)

    @property
    def name(self):
        if self.is_stack:
            name = idc.get_member_name(self.frame_id, self.stack_offset)
        else:
            name = idc.get_name(self.addr)
        if not name:
            return ""
        return name

    @property
    def size(self):
        if self.is_stack:
            return idc.get_member_size(self.frame_id, self.stack_offset)
        else:
            return idc.get_item_size(self.addr)

    @property
    def data(self):
        """The raw data the variable is pointing to."""
        return self._cpu_context.mem_read(self.addr, self.size)

    def add_reference(self, ip):
        """Adds ip to list of references for this variable."""
        # Ignore duplicate calls.
        if self.references and ip == self.references[-1]:
            return
        self.references.append(ip)

    @property
    def value(self):
        """The unpacked data the variable is pointing to."""
        if self.is_func_ptr:
            return self.addr

        if self.is_stack:
            flag = idc.get_member_flag(self.frame_id, self.stack_offset)
            data_type = flag & idc.DT_TYPE
            # Unpack if an integer type.
            if data_type in self.SIZE_MAP:
                data_type_size = self.SIZE_MAP[data_type]
                if self.size == data_type_size:
                    return utils.struct_unpack(self.data)
                else:
                    # If data size is greater than type size, then we have an array.
                    data = self.data
                    return [
                        utils.struct_unpack(data[i : i + data_type_size]) for i in range(0, len(data), data_type_size)
                    ]
            else:
                return self.data
        else:
            # TODO: Determine how to unpack based on type for global variables.
            return self.data

    @property
    def history(self):
        """The history of variables by following memory copies."""
        # (We shouldn't have Nones)
        history = []
        for addr in self._cpu_context.get_pointer_history(self.addr):
            var = self._cpu_context.variables.get(addr, None)
            if var:
                history.append(var)
        return history
