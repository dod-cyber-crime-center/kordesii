"""
Interface for variable management.
"""

from copy import deepcopy
import functools
import logging
from typing import List, Iterable

import idc
import ida_bytes
import ida_struct
import ida_typeinf

from kordesii.utils.function_tracing import utils


logger = logging.getLogger(__name__)


class VariableMap(object):
    """
    Class that stores a set of variables that have been encountered during emulation.
    """

    def __init__(self, cpu_context):
        self._variables = {}
        self._cpu_context = cpu_context

    def __repr__(self):
        return "<VariableMap : \n\t{}\n>".format(
            "\n\t".join(([repr(var) for addr, var in sorted(self._variables.items())]))
        )

    def __deepcopy__(self, memo):
        """
        Custom implementation of deepcopy to improve efficiency.
        """
        copy = VariableMap(deepcopy(self._cpu_context, memo))
        memo[id(self)] = copy
        copy._variables = {addr: deepcopy(variable, memo) for addr, variable in list(self._variables.items())}
        return copy

    def __getitem__(self, addr_or_name) -> "Variable":
        """Gets a variable by name or address."""
        if isinstance(addr_or_name, str):
            name = addr_or_name
            for var in self:
                if name == var.name:
                    return var
            raise KeyError(f"{name} not found.")
        elif isinstance(addr_or_name, int):
            return self._variables[addr_or_name]
        else:
            raise ValueError("Invalid variable name or address: {!r}".format(addr_or_name))

    def __len__(self):
        return len(self._variables)

    def get(self, addr_or_name, default=None) -> "Variable":
        """Gets a variable by name or address."""
        try:
            return self[addr_or_name]
        except (KeyError, ValueError):
            return default

    def at(self, ip) -> List["Variable"]:
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

    def __contains__(self, addr_or_name) -> bool:
        if isinstance(addr_or_name, str):
            name = addr_or_name
            return any(name == var.name for var in self)
        elif isinstance(addr_or_name, int):
            addr = addr_or_name
            return addr in self._variables
        else:
            raise ValueError("Invalid variable name or address: {!r}".format(addr_or_name))

    def __iter__(self) -> Iterable["Variable"]:
        return iter(self._variables.values())

    def add(self, addr, frame_id=None, stack_offset=None, reference=None) -> "Variable":
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
    def names(self) -> List[str]:
        return [var.name for var in self]

    @property
    def addrs(self) -> List[int]:
        return list(self._variables.keys())

    @property
    def stack_variables(self) -> List["Variable"]:
        return [var for var in self if var.is_stack]

    @property
    def global_variables(self) -> List["Variable"]:
        return [var for var in self if not var.is_stack]


@functools.total_ordering
class Variable(object):
    """
    Stores information for a local / global variable for a specific CPU context state.
    """

    TYPE_MAP = {
        idc.FF_BYTE: "byte",
        idc.FF_WORD: "word",
        idc.FF_DWORD: "dword",
        idc.FF_QWORD: "qword",
        idc.FF_OWORD: "oword",
        idc.FF_TBYTE: "tbyte",
        idc.FF_STRLIT: "char",
        idc.FF_STRUCT: "struct",
        idc.FF_FLOAT: "float",
        idc.FF_DOUBLE: "double",
        idc.FF_PACKREAL: "packed decimal real",
        idc.FF_ALIGN: "alignment directive",
    }

    SIZE_MAP = {
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
        data_type_str = self.data_type
        if self.count > 1 and data_type_str != "func_ptr":
            data_type_str += f"[{self.count}]"
        string = (
            f"<Variable {self.name} "
            f": type = {data_type_str} "
            f": addr = 0x{self.addr:0x} "
            f": value = {repr(self.value)} "
            f": size = {self.size} "
        )
        if self.is_stack:
            string += f": frame_id = 0x{self.frame_id:0x} : stack_offset = {self.stack_offset} "
        string += ">"
        return string

    def __eq__(self, other):
        return self.addr == other.addr

    def __lt__(self, other):
        return self.addr < other.addr

    @property
    def _struc(self):
        return ida_struct.get_struc(self.frame_id)

    @property
    def _member(self):
        return ida_struct.get_member(self._struc, self.stack_offset)

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
            name = ida_struct.get_member_name(self._member.id)
        else:
            name = idc.get_name(self.addr)
        if not name:
            return ""
        return name

    @property
    def size(self):
        """Size of data"""
        if self.is_stack:
            return ida_struct.get_member_size(self._member)
        else:
            return ida_bytes.get_item_size(self.addr)

    @property
    def data_type_size(self) -> int:
        """The data type size, defaults to 1 if unknown"""
        if self.is_stack:
            tif = ida_typeinf.tinfo_t()
            success = ida_struct.get_member_tinfo(tif, self._member)
            if not success:
                # Sometimes IDA will fail to get member type information for unknown reasons.
                # In these cases, set the type size ourselves if it is obvious or default to 1.
                return self.SIZE_MAP.get(self._data_type_enum, 1)
            return tif.get_size()
        else:
            return ida_bytes.get_data_elsize(self.addr, self._data_type_enum)

    @property
    def count(self):
        """Count of elements in the array."""
        return self.size // self.data_type_size

    @property
    def data(self):
        """The raw data the variable is pointing to."""
        return self._cpu_context.mem_read(self.addr, self.size)

    @data.setter
    def data(self, value):
        """Sets the raw data the variable is pointing to."""
        size = self.size
        if len(value) > size:
            raise ValueError(f"Data size for variable at 0x{self.addr:08x} ({self.name}) must be <= {size} bytes.")

        self._cpu_context.mem_write(self.addr, value)

    @property
    def _data_type_enum(self) -> int:
        """The data type as a IDA enum"""
        if self.is_stack:
            flags = self._member.flag
        else:
            flags = ida_bytes.get_flags(self.addr)
        return flags & idc.DT_TYPE

    @property
    def data_type(self) -> str:
        """The data type as a string."""
        if self.is_func_ptr:
            return "func_ptr"
        else:
            return self.TYPE_MAP.get(self._data_type_enum, "")

    def add_reference(self, ip):
        """Adds ip to list of references for this variable."""
        # Ignore duplicate calls.
        if self.references and ip == self.references[-1]:
            return
        self.references.append(ip)

    def _data_array(self) -> List[int]:
        """Returns data as an array of unpacked integers based on data_type size."""
        data = self.data
        data_type_size = self.data_type_size
        return [utils.struct_unpack(data[i:i + data_type_size]) for i in range(0, len(data), data_type_size)]

    @property
    def value(self):
        """The unpacked data the variable is pointing to."""
        data_type = self.data_type

        if data_type == "func_ptr":
            return self.addr

        if data_type in ("char", "byte", "tbyte"):
            return self.data

        if data_type in ("word", "dword", "qword", "oword"):
            data_array = self._data_array()
            if len(data_array) == 1:
                return data_array[0]
            return data_array

        if data_type in ("float", "double"):
            data_array = [utils.int_to_float(value) for value in self._data_array()]
            if len(data_array) == 1:
                return data_array[0]
            return data_array

        if data_type == "struct":
            # TODO: Support returning some type of dictionary for structs.
            return self.data

        raise NotImplementedError(f"Unsupported data type: {data_type}")

    @value.setter
    def value(self, value):
        """Set the data the variable is pointing to."""
        data_type = self.data_type

        if data_type in ("char", "tbyte"):
            self.data = value

        elif data_type in ("byte", "word", "dword", "qword", "oword"):
            width = self.data_type_size
            if isinstance(value, list):
                self.data = b''.join(utils.struct_pack(_value, width=width) for _value in value)
            else:
                self.data = utils.struct_pack(value, width=width)

        elif data_type in ("float", "double"):
            width = self.data_type_size
            if isinstance(value, list):
                self.data = b''.join(
                    utils.struct_pack(utils.float_to_int(_value), width=width) for _value in value)
            else:
                self.data = utils.struct_pack(utils.float_to_int(value), width=width)

        else:
            raise NotImplementedError(f"Unsupported data type: {data_type}")

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
