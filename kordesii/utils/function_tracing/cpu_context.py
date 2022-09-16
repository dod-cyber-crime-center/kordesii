"""
Implements the "hardware" for tracing a function.

Will perform the instructions and updates CPU registers, stack information, etc.

WARNING:
    Do NOT rely on the flags registers being correct.  There are places were flags are NOT being updated when they
    should, and the very fact that CALL instructions are skipped could cause flags to be incorrect.
"""
from copy import deepcopy
import collections
import logging
import warnings
from typing import List, Tuple, Optional, Union

import ida_frame
import ida_funcs
import ida_idp
import idaapi
import idc
import ida_struct
import ida_ua

from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.constants import *
from kordesii.utils.function_tracing.instruction import Instruction
from kordesii.utils.function_tracing.memory import Memory
from kordesii.utils.function_tracing.variables import VariableMap
from kordesii.utils.function_tracing.operands import Operand, OperandLite
from kordesii.utils.function_tracing.functions import FunctionSignature, FunctionArg
from kordesii.utils.function_tracing.objects import File, RegKey, Service, ObjectMap
from kordesii.utils.function_tracing.actions import ActionList
from kordesii.utils.functions import Function

logger = logging.getLogger(__name__)


class JccContext(object):
    """
    Stores information pertaining to a Jcc instruction encountered when tracing.

    When a Jcc instruction is encountered, several pieces of information inherently need to be tracked since
    we are blindly taking every branch to ensure we get all possible data at any given address.  It turns out
    we need to know the target of the Jcc instruction for the condition as emulated
    (condition_target_ea).  We also need to know the value of the branch we would NOT have taken (at least as
    best of a guess as we can make in some cases) and where that value would have been set.  In order to
    calculate the value, we need to know what kind of test instruction was used, so that mnem is tracked as well.When
    we trace our condition_target_ea branch, we need not modify the context.  Whenever we trace the alternative branch,
    we'll need to modify the context as specified.
    """

    def __init__(self):
        self.condition_target_ea = None  # The branch actually taken
        self.alt_branch_data_dst = None  # The location which was tested (typically opnd 0 of the condition test)
        self.alt_branch_data = None  # The data stored in _alt_branc_data_dst
        self.flag_opnds = {}  # Dictionary containing the operands at a particular instruction which set
        # specific flags.  Dictionary is keyed on flag registery names.

    def __deepcopy__(self, memo):
        copy = JccContext()
        copy.condition_target_ea = self.condition_target_ea
        copy.alt_branch_data_dst = self.alt_branch_data_dst
        copy.alt_branch_data = self.alt_branch_data
        copy.flag_opnds = {flag: list(operands) for flag, operands in list(self.flag_opnds.items())}
        return copy

    def update_flag_opnds(self, flags, opnds):
        """
        Set the operands which last changed the specified flags.

        :param flags: list of flags which were modified utilizing the supplied opnds
        :param opnds: list of operands (instance of Operand) at the instruction which modified the flags
        """
        for flag in flags:
            # Converting Operand classes to OperandLite classes to help speed up deepcopies.
            self.flag_opnds[flag] = [OperandLite(opnd.ip, opnd.idx, opnd.text, opnd.value) for opnd in opnds]

    def get_flag_opnds(self, flags):
        """
        Extracts all the operands of for the list of flags and reduces the set.  However, since the operands
        need to remain in order, we can't use set operations.  In all actuality, assuming our code is correct and
        the compiler isn't doing something funky, any more than 1 flag should really just be a duplicate list.

        :param flags: list of flags for which to extract operands
        :return: list of operands which were utilized in the instruction that modified the requested flags
        """
        # TODO: Is there a better way to do this?
        operands = []
        for flag in flags:
            for operand in self.flag_opnds.get(flag, []):
                if operand not in operands:
                    operands.append(operand)

        return operands

    def is_alt_branch(self, ip):
        """
        Test our IP against the branch information to determine if we are in the branch that would have been
        emulated or in the alternate branch.
        """
        return self.condition_target_ea and self.condition_target_ea != ip


class ProcessorContext(object):
    """
    Stores the context of the processor during execution.

    :param emulator: Instance of Emulator to use during emulation.
    :param registers: Instance of an initialized RegisterMap object used to store register values
        for the given architecture.
    :param str instruction_pointer: Name of the register used to point to the current instruction
        being currently executed or to-be executed.
    :param str stack_pointer: Name of the register used to hold the stack pointer.
    """

    # Must be set by inherited classes.
    OPCODES = {}  # Map of opcode mnemonics to functions that emulate them.

    # Class used to generate instructions.
    _instruction_class = Instruction

    # Cache for keeping track of instructions and their operand indexes.
    _operand_indices = {}

    def __init__(self, emulator, registers, instruction_pointer, stack_pointer, return_register):
        self.emulator = emulator
        self.registers = registers
        self.jcccontext = JccContext()
        self.memory = Memory()
        self.call_history = []  # Keeps track of function calls.
        self.executed_instructions = []  # Keeps track of the instructions that have been executed.
        self.memory_copies = collections.defaultdict(list)  # Keeps track of memory moves.
        self.bitness = utils.get_bits()
        self.byteness = self.bitness // 8
        self.variables = VariableMap(self)
        self.objects = ObjectMap(self)
        self.actions = ActionList()
        self.stdout = ""

        # Function start address of a function we are currently hooking.
        self.hooking_call = None
        self._call_depth = 0

        self._sp = stack_pointer
        self._ip = instruction_pointer
        self._ret = return_register
        self._sp_start = self.sp

    def __deepcopy__(self, memo):
        """Implementing our own deepcopy to improve speed."""
        # Create class, but avoid calling __init__()
        # so we don't trigger the unnecessary initialization of Memory and JccContext
        klass = self.__class__
        copy = klass.__new__(klass)
        memo[id(self)] = copy

        copy.emulator = self.emulator  # This is a reference, don't create a new instance.
        copy.hooking_call = self.hooking_call
        copy.registers = deepcopy(self.registers, memo)
        copy.jcccontext = deepcopy(self.jcccontext, memo)
        copy.memory = deepcopy(self.memory, memo)
        copy.variables = deepcopy(self.variables, memo)
        copy.objects = deepcopy(self.objects, memo)
        copy.actions = deepcopy(self.actions, memo)
        copy.call_history = list(self.call_history)
        copy.executed_instructions = list(self.executed_instructions)
        copy.memory_copies = self.memory_copies.copy()
        copy.stdout = self.stdout
        copy.bitness = self.bitness
        copy.byteness = self.byteness
        copy._call_depth = self._call_depth
        copy._sp = self._sp
        copy._ip = self._ip
        copy._ret = self._ret
        copy._sp_start = self._sp_start

        return copy

    @property
    def ip(self) -> int:
        """Alias for retrieving instruction pointer."""
        return self.registers[self._ip]

    @ip.setter
    def ip(self, value):
        """Alias for setting instruction pointer."""
        self.registers[self._ip] = value

    @property
    def sp(self) -> int:
        """Alias for retrieving stack pointer."""
        return self.registers[self._sp]

    @sp.setter
    def sp(self, value):
        """Alias for setting stack pointer."""
        self.registers[self._sp] = value

    @property
    def sp_diff(self) -> int:
        """
        The difference between the current stack pointer and the
        stack pointer at the beginning of the function.

        This helps with debugging since this number should match the number
        shown in the IDA disassembly.
        """
        return self._sp_start - self.sp

    # TODO: A subroutine in ARM can technically pass in larger values, in which
    #   case the value spans multiple registers r0-r3
    @property
    def ret(self) -> int:
        """Alias for retrieving the return value."""
        return self.registers[self._ret]

    @ret.setter
    def ret(self, value):
        """Alias for setting return value."""
        logger.debug("Setting 0x%X into %s", value, self._ret)
        self.registers[self._ret] = value

    @property
    def prev_instruction(self):
        """That last instruction that was executed or None if no instructions have been executed."""
        if self.executed_instructions:
            return self.executed_instructions[-1]
        else:
            return None

    def execute(self, start=None, end=None, call_depth: int = 0, max_instructions: int = None):
        """
        "Execute" the instruction at IP and store results in the context.
        The instruction pointer register will be set to the value supplied in .ip so that
        it is correct.

        :param start: instruction address to start execution (defaults to currently set ip)
        :param end: instruction to stop execution (not including)
            (defaults to only run start)
        :param call_depth: Number of function calls we are allowed to emulate into.
            When we hit our limit (depth is 0), emulation will no longer jump into function calls.
            (Defaults to not emulating into any function calls.)
            NOTE: This does not affect call hooks.
        :param max_instructions: Maximum number of instructions to execute before
            raising an RuntimeError.
            Uses max_instructions set by emulator constructor if not provided.

        :raises RuntimeError: If maximum number of instructions get hit.
        """
        if max_instructions is None:
            max_instructions = self.emulator.max_instructions

        if not start:
            start = self.ip

        # Set instruction pointer to where we are currently executing.
        self.ip = start

        # Set current call depth.
        if call_depth < 0:
            raise ValueError(f"call_depth must be a positive number.")
        self._call_depth = call_depth

        # If end is provided, recursively run execute() until ip is end.
        if end is not None:
            count = max_instructions
            while self.ip != end:
                instruction = self.instruction
                if instruction.is_terminal:
                    return  # TODO: Should we be executing the terminal instruction?
                instruction.execute()
                count -= 1
                if not count:
                    raise RuntimeError('Hit maximum number of instructions.')
            return
        else:
            self.instruction.execute()

    def _execute_call(self, func_name: str, func_address: int, call_address: int = None):
        """
        Executes the call to the given function.
        If a call hook has been provided, the hook will get run. Otherwise, instructions in the function
        will get emulated if set call_depth allows.

        :param func_name: Name of the function (or empty string)
        :param func_address: Address of function to call.
        :param call_address: Address of call instruction (if available)
        """
        # Tell context that we are currently emulating a function hook.
        # This information is important for things like pulling out function arguments out correctly.
        self.hooking_call = func_address

        try:
            # Report on function call and their arguments.
            arg_objs = self.get_function_arg_objects(func_address)
            args = [arg_obj.value for arg_obj in arg_objs]
            self.call_history.append((call_address, func_name, args))

            # Emulate the effects of any known builtin functions.
            call_hook = self.emulator.get_call_hook(func_address)
            if not call_hook:
                call_hook = self.emulator.get_call_hook(func_name)
                if not call_hook:
                    # Try one more time with a sanitized name.
                    func_name = utils.sanitize_func_name(func_name)
                    call_hook = self.emulator.get_call_hook(func_name)

            # Execute call hook if provided.
            if call_hook:
                try:
                    logger.debug(
                        "Emulating %s(%s)",
                        func_name,
                        ", ".join(f"{arg_obj.name}={hex(arg_obj.value)}" for arg_obj in arg_objs)
                    )
                    logger.debug("Running hook: %r", call_hook)
                    ret = call_hook(self, func_name, args)
                    if ret is True:
                        ret = 1
                    elif ret is False:
                        ret = 0
                    # Set return value to rax
                    if ret is not None:
                        if not isinstance(ret, int):
                            raise TypeError(f"Invalid return type. Expected 'int' but got '{type(ret)}'")
                        self.ret = ret
                except RuntimeError:
                    raise  # Allow RuntimeError exceptions to be thrown.
                except Exception as e:
                    logger.debug("Failed to emulate builtin function: %s() with error: %s", func_name, e)

            # Otherwise, emulate the function instructions if set call_depth allows.
            elif self._call_depth:
                try:
                    func = Function(func_address)
                except AttributeError as e:
                    logger.warning("Failed to execute call at 0x%X : %s", func_address, e)
                    return
                call_depth = self._call_depth
                sp_start = self._sp_start
                try:
                    self.execute(start=func.start_ea, end=func.end_ea, call_depth=call_depth - 1)
                finally:
                    # Reset after we leave call.
                    self._call_depth = call_depth
                    self._sp_start = sp_start

        finally:
            self.hooking_call = None

    @property
    def func_calls(self) -> dict:
        warnings.warn(f".func_calls is deprecated. Please use .call_history instead.", DeprecationWarning)
        # Original .func_calls overwrote calls at the same instruction. So pulling the last one to replicate this logic.
        return {address: (func_name, args) for address, func_name, args in self.call_history}

    def get_call_history(self, func_name_or_ea) -> List[Tuple[int, List]]:
        """
        Returns the call history for a specific function name.

        :returns: List of tuples containing: (ea of call, list of function arguments)
        """
        if isinstance(func_name_or_ea, str):
            func_name = func_name_or_ea
        else:
            ea = func_name_or_ea
            func_name = utils.get_function_name(ea)
        return [(address, args) for address, _func_name, args in self.call_history if _func_name == func_name]

    def prep_for_branch(self, bb_start_ea):
        """
        Modify this current context in preparation for a specific path.
        """
        if self.jcccontext.is_alt_branch(bb_start_ea):
            logger.debug("Modifying context for branch at 0x%08X", bb_start_ea)
            # Set the destination operand relative to the current context
            # to a valid value that makes this branch true.
            dst_opnd = self.jcccontext.alt_branch_data_dst
            dst_opnd = self.get_operands(ip=dst_opnd.ip)[dst_opnd.idx]
            dst_opnd.value = self.jcccontext.alt_branch_data

        self.jcccontext = JccContext()

    def get_instruction(self, ip=None) -> Instruction:
        """
        Gets the Instruction object for the current instruction pointed by the instruction pointer.

        :param ip: location of instruction pointer to pull Instruction from (default to current ip in context)
        :return: Instruction object
        """
        if ip is None:
            ip = self.ip
        return self._instruction_class(self, ip)

    @property
    def instruction(self) -> Instruction:
        return self.get_instruction()

    def get_operands(self, ip=None) -> List[Operand]:
        """
        Gets the Operand objects of all operands in the current instruction and returns them in a list.

        :param int ip: location of instruction pointer to pull operands from (defaults to current rip in context)

        :return: list of Operand objects
        """
        return self.get_instruction(ip=ip).operands

    @property
    def operands(self) -> List[Operand]:
        return self.get_operands()

    def reg_read(self, reg):
        """
        Read a register value

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.reg_read("EIP")

        :param str reg: register name to be read

        :return int: value contained in specified register as int
        """
        return self.registers[reg.lower()]

    def reg_write(self, reg, val):
        """
        Write a register value

        :param str reg: register name to be written

        :param int val: value to be written to register as an int of width of the register (will be truncated as necessary)
        """
        self.registers[reg.lower()] = val

    def mem_alloc(self, size):
        """
        Allocates heap region with size number of bytes.

        :param size: Number of bytes to allocate.
        :return: starting address of allocated memory.
        """
        return self.memory.alloc(size)

    def mem_realloc(self, address, size):
        """
        Reallocates heap region with size number of bytes.

        :param address: base address to reallocate.
        :param size: Number of bytes to allocate.
        :return: address of the reallocated memory block.
        """
        new_address = self.memory.realloc(address, size)
        # Record a memory copy if pointer has changed.
        if new_address != address:
            self.memory_copies[self.ip].append((address, new_address, size))
        return new_address

    def mem_copy(self, src, dst, size):
        """
        Copy data from src address to dst address
        (Use this over mem_read/mem_write in order to allow the context to keep track of memory pointer history.)

        :param src: Source address
        :param dst: Destination address
        :param size: Number of bytes to copy over.
        :return:
        """
        self.memory_copies[self.ip].append((src, dst, size))
        self.mem_write(dst, self.mem_read(src, size))

    def get_pointer_history(self, ea):
        """
        Retrieves the history of a specific pointer.
        :param ea: Pointer to start with.
        :return: list of tuples containing (address of the memory copy, source pointer)
            - sorted by earliest to latest incarnation of the pointer. (not including itself)
        """
        history = []
        for ip, copies in sorted(list(self.memory_copies.items()), reverse=True):
            for src, dst, size in sorted(copies, reverse=True):
                if dst == ea:
                    history.append((ip, src))
                    ea = src
        history.reverse()
        return history

    def get_original_location(self, addr):
        """
        Retrieves the original location for a given address by looking through it's pointer history.

        :param addr: address of interest

        :return: a tuple containing:
            - instruction pointer where the original location was first copied
                or None if given address is already loaded or the original location could not be found.
            - either a loaded address, a tuple containing (frame_id, stack_offset) for a stack variable,
                or None if the original location could not be found.
        """
        # TODO: Consider refactoring.

        # Pull either the first seen loaded address or last seen stack variable.
        if idc.is_loaded(addr):
            return None, addr
        ip = None

        var = self.variables.get(addr, None)
        for ip, ea in reversed(self.get_pointer_history(addr)):
            if idc.is_loaded(ea):
                return ip, ea
            var = self.variables.get(ea, var)

        if var and var.is_stack:
            return ip, (var.frame_id, var.stack_offset)
        else:
            return ip, None

    def mem_read(self, address, size):
        """
        Read memory at the specified address of size size

        :param int address: address to read memory from
        :param int size: size of data to be read
        :return bytes: read data as bytes
        """
        return self.memory.read(address, size)

    def mem_write(self, address, data):
        """
        Write content contained in data to specified address

        :param int address: address to write data at
        :param bytes data: data to be written as bytes
        """
        self.memory.write(address, data)

    def mem_find(self, value, start=0, end=None):
        return self.memory.find(value, start=start, end=end)

    def mem_find_in_segment(self, value, seg_name_or_ea):
        return self.memory.find_in_segment(value, seg_name_or_ea)

    def mem_find_in_heap(self, value):
        return self.memory.find_in_heap(value)

    # TODO: Move this into Memory class and automatically decode values.
    def read_data(self, addr, size=None, data_type=None):
        """
        Reads memory at the specified address, of the specified size and convert
        the resulting data into the specified type.

        :param int addr: address to read data from
        :param int size: size of data to read
        :param data_type: type of data to be extracted
            (default to BYTE_STRING is size provided or STRING if not)
        """
        if not data_type:
            data_type = STRING if size is None else BYTE_STRING
        if size is None:
            size = 0

        if data_type == STRING:
            null_offset = self.memory.find(b"\0", start=addr)
            # It should always eventually find a null since unmapped pages
            # are all null. If we get -1 we have a bug.
            assert null_offset != -1, "Unable to find a null character!"
            return self.memory.read(addr, null_offset - addr)

        elif data_type == WIDE_STRING:
            # Step by 2 bytes to find 2 nulls on an even alignment.
            # (This helps prevent the need to take endianness into account.)
            null_offset = addr
            while self.memory.read(null_offset, 2) != b"\0\0":
                null_offset += 2

            return self.memory.read(addr, null_offset - addr)

        elif data_type == BYTE_STRING:
            return self.memory.read(addr, size)

        elif data_type == BYTE:
            return utils.struct_unpack(self.mem_read(addr, 1))

        elif data_type == WORD:
            return utils.struct_unpack(self.mem_read(addr, 2))

        elif data_type == DWORD:
            return utils.struct_unpack(self.mem_read(addr, 4))

        elif data_type == QWORD:
            return utils.struct_unpack(self.mem_read(addr, 8))

        raise ValueError("Invalid data_type: {!r}".format(data_type))

    def write_data(self, addr, value, data_type=None):
        """
        Writes memory at the specified address after converting the value
        into data based on the specified data type.

        :param int addr: address to write data to
        :param value: integer or byte string to write
        :param data_type: type of data to convert value from.
            (defaults to BYTE_STRING, STRING, or DWORD based on input data)
        """
        if not data_type:
            if isinstance(value, str):
                data_type = STRING
            elif isinstance(value, bytes):
                data_type = BYTE_STRING
            elif isinstance(value, int):
                data_type = DWORD
            else:
                raise ValueError(f"Invalid data type: {type(value)}")

        if data_type == BYTE_STRING:
            data = value

        elif data_type == STRING:
            data = value
            if isinstance(data, str):
                data = data.encode("utf8")
            data += b"\0"

        elif data_type == WIDE_STRING:
            data = value
            if isinstance(data, str):
                data = data.encode("utf-16-le")
            data += b"\0\0"

        elif data_type == BYTE:
            data = bytes([value])

        elif data_type == WORD:
            data = utils.struct_pack(value, width=2)

        elif data_type == DWORD:
            data = utils.struct_pack(value, width=4)

        elif data_type == QWORD:
            data = utils.struct_pack(value, width=8)

        else:
            raise ValueError(f"Invalid data_type: {repr(data_type)}")

        self.mem_write(addr, data)

    def get_function_signature(self, func_ea=None, force=False, num_args=None) -> Optional[FunctionSignature]:
        """
        Returns the function signature of the given func_ea with argument values pulled
        from this context.

        :param int func_ea: address of the function to pull signature from.
            The first operand is used if not provided. (helpful for a "call" instruction)
        :param bool force: Whether to force a function signature using cdecl calling
            convention and no arguments if we fail to generate the signature.
            (Useful when trying to declare a function that was dynamically created in a register)
        :param int num_args: Force a specific number of arguments in the signature.
            If not provided, number of arguments is determined by the disassembler.
            Extra arguments not defined by the disassembler are assumed to be 'int' type.
            Avoid using num_args and adjust the returned FunctionSignature manually
            if more customization is needed.
            (NOTE: The function signature will be forced on failure if this is set.)

        :return: FunctionSignature object or None if not applicable

        :raises RuntimeError: If a function signature could not be created from given ea.
        :raises ValueError: If num_args is negative
        """
        # If func_ea is not given, assume we are using the first operand from a call instruction.
        if not func_ea:
            if not self.operands:
                return None
            operand = self.operands[0]
            # function pointer can be a memory reference or immediate.
            func_ea = operand.addr or operand.value
        else:
            operand = None

        force = force or num_args is not None

        try:
            func_sig = FunctionSignature(self, func_ea, operand=operand)
        except RuntimeError as e:
            # If we fail to get a function signature but force is set, set the type to
            # cdecl with no arguments.
            if force:
                logger.warning(
                    "Failed to create function signature at 0x{:0X} with error: {}\n"
                    "Forcing signature with assumed cdecl calling convention.".format(func_ea, e)
                )
                idc.SetType(func_ea, "int __cdecl no_name();")
                func_sig = FunctionSignature(self, func_ea)
            else:
                raise

        if num_args is not None:
            if num_args < 0:
                raise ValueError("num_args is negative")
            arg_types = func_sig.arg_types
            if len(arg_types) > num_args:
                func_sig.arg_types = arg_types[:num_args]
            elif len(arg_types) < num_args:
                func_sig.arg_types = arg_types + ("int",) * (num_args - len(arg_types))

        return func_sig

    def get_function_arg_objects(self, func_ea=None, num_args=None) -> List[FunctionArg]:
        """
        Returns the FunctionArg objects for this context based on the
        given function.

        >>> cpu_context = ProcessorContext()
        >>> args = cpu_context.get_function_arg_objects(0x180011772)

        :param int func_ea: Ea of the function to pull a signature from.
        :param int num_args: Force a specific number of arguments.
            If not provided, number of arguments is determined by the disassembler.
            Extra arguments not defined by the disassembler are assumed to be 'int' type.
            Use get_function_signature() and adjust the FunctionSignature manually
            if more customization is needed.
            (NOTE: The function signature will be forced on failure if this is set.)

        :returns: list of FunctionArg objects
        """
        func_sig = self.get_function_signature(func_ea, num_args=num_args)
        if not func_sig:
            return []

        return func_sig.args

    # TODO: Replace this function with get_function_arg_objects()
    def get_function_args(self, func_ea=None, num_args=None) -> List[int]:
        """
        Returns the FunctionArg values for this context based on the given function.
        """
        args = self.get_function_arg_objects(func_ea=func_ea, num_args=num_args)
        return [arg.value for arg in args]

    @property
    def function_args(self) -> List[FunctionArg]:
        """
        The function arguments currently set based on the function in the first operand.
        """
        return self.get_function_arg_objects()

    @property
    def passed_in_args(self) -> List[FunctionArg]:
        """
        The function arguments for the current function.
        """
        func = ida_funcs.get_func(self.ip)
        return self.get_function_arg_objects(func.start_ea)

    @property
    def files(self) -> List[File]:
        """
        All File objects in the current context.
        """
        return list(self.objects.query(File))

    def get_file(self, handle_or_path: Union[int, str], default=None) -> File:
        """
        Gets a file by handle or path. Returns default if not existent.

        :raises TypeError: if handle points and object that is not a File.
        """
        warnings.warn(
            "get_file() is deprecated. Please use objects.query() instead.",
            DeprecationWarning
        )
        if isinstance(handle_or_path, int):
            condition = dict(handle=handle_or_path)
        else:
            condition = dict(path=handle_or_path)

        for obj in self.objects.query(File, **condition):
            return obj
        return default

    @property
    def regkeys(self) -> List[RegKey]:
        """
        The opened registry keys for this context.
        """
        return list(self.objects.query(RegKey))

    @property
    def services(self) -> List[Service]:
        """
        The created services for this context.
        """
        return list(self.objects.query(Service))
