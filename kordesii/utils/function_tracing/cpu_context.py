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

import idaapi
import idc
import ida_struct
import ida_ua

from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.constants import *
from kordesii.utils.function_tracing.memory import Memory
from kordesii.utils.function_tracing.variables import VariableMap
from kordesii.utils.function_tracing.operands import Operand, OperandLite
from kordesii.utils.function_tracing.functions import FunctionSignature


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


# TODO: Create architecture specific Context types.
class ProcessorContext(object):
    """
    Stores the context of the processor during execution.

    :param registers: Instance of an initialized RegisterMap object used to store register values
        for the given architecture.
    :param str instruction_pointer: Name of the register used to point to the current instruction
        being currently executed or to-be executed.
    :param [str] stack_registers: List of register names used for handling the stack.
    """

    # Must be set by inherited classes.
    ARCH_NAME = None  # Name of architecture as reported by disassembler.
    OPCODES = {}  # Map of opcode mnemonics to functions that emulate them.

    def __init__(self, registers, instruction_pointer, stack_pointer, stack_registers=None):
        self.registers = registers
        self.jcccontext = JccContext()
        self.memory = Memory()
        self.func_calls = {}  # Keeps track of function calls.
        self.executed_instructions = []  # Keeps track of the instructions that have been executed.
        self.memory_copies = collections.defaultdict(list)  # Keeps track of memory moves.
        self.bitness = utils.get_bits()
        self.byteness = self.bitness // 8
        self.stack_registers = stack_registers or []
        self.variables = VariableMap(self)
        self._sp = stack_pointer
        self._ip = instruction_pointer

    @classmethod
    def from_arch(cls, arch_name=None):
        """
        Factory method for initializing a ProcessorContext based on detected architecture.

        :param arch_name: Name of architecture to initializes (according to the disassembler)
                          Architecture is automatically detected if not provided.

        :raises NotImplementedError: If architecture is not supported.
        """
        # Pull from disassembler if not provided.
        if not arch_name:
            info = idaapi.get_inf_structure()
            arch_name = info.procName

        for subclass in cls.__subclasses__():
            if subclass.ARCH_NAME == arch_name:
                return subclass()  # Subclasses shouldn't have any initialization parameters.
        raise NotImplementedError("Architecture not supported: {}".format(arch_name))

    def __deepcopy__(self, memo):
        """Implementing our own deepcopy to improve speed."""
        # Create class, but avoid calling __init__()
        # so we don't trigger the unnecessary initialization of Memory and JccContext
        klass = self.__class__
        copy = klass.__new__(klass)
        memo[id(self)] = copy

        copy.registers = deepcopy(self.registers, memo)
        copy.jcccontext = deepcopy(self.jcccontext, memo)
        copy.memory = deepcopy(self.memory, memo)
        copy.variables = deepcopy(self.variables, memo)
        copy.func_calls = dict(self.func_calls)
        copy.executed_instructions = list(self.executed_instructions)
        copy.memory_copies = self.memory_copies.copy()
        copy.bitness = self.bitness
        copy.byteness = self.byteness
        copy.stack_registers = self.stack_registers
        copy._sp = self._sp
        copy._ip = self._ip

        return copy

    @property
    def ip(self):
        """Alias for retrieving instruction pointer."""
        return self.registers[self._ip]

    @ip.setter
    def ip(self, value):
        """Alias for setting instruction pointer."""
        self.registers[self._ip] = value

    @property
    def sp(self):
        """Alias for retrieving stack pointer."""
        return self.registers[self._sp]

    @sp.setter
    def sp(self, value):
        """Alias for setting stack pointer."""
        self.registers[self._sp] = value

    @property
    def prev_instruction(self):
        """That last instruction that was executed or None if no instructions have been executed."""
        if self.executed_instructions:
            return self.executed_instructions[-1]
        else:
            return None

    def execute(self, ip=None):
        """
        "Execute" the instruction at IP and store results in the context.
        The RIP/EIP register will be set to the value supplied in IP so that it is
        correct.

        :param ip: instruction address to execute (defaults to currently set ip)
        """
        if not ip:
            ip = self.ip

        # Set instruction pointer to where we are currently executing.
        self.ip = ip

        # Determine if a rep* instruction and add termination condition.
        term_condition = None
        if idc.get_wide_byte(ip) in (0xF2, 0xF3):
            insn = idc.GetDisasm(ip)  # IDA pro never has operands for rep opcodes.
            if insn.startswith("rep "):
                term_condition = lambda: self.registers.ecx == 0
            elif insn.startswith(("repe ", "repz ")):
                term_condition = lambda: self.registers.ecx == 0 or self.registers.zf == 0
            elif insn.startswith(("repne ", "repnz ")):
                term_condition = lambda: self.registers.ecx == 0 or self.registers.zf == 1

        # Emulate instruction.
        mnem = idc.print_insn_mnem(ip)
        operands = self.operands
        instruction = self.OPCODES.get(mnem)
        if instruction:
            try:
                if term_condition:
                    # As a safety measure, don't allow rep instructions to surpass
                    # our max memory read limit.
                    if self.registers.ecx > self.memory.MAX_MEM_READ:
                        logger.warning(
                            "0x{:08X} :: Emulation attempted to read {} instruction {} times. "
                            "Ignoring instruction.".format(ip, mnem, self.registers.ecx)
                        )
                    else:
                        logger.debug("Emulating {} instruction {} times.".format(mnem, self.registers.ecx))
                        while not term_condition():
                            instruction(self, ip, mnem, operands)
                            self.registers.ecx -= 1
                else:
                    instruction(self, ip, mnem, operands)
            except Exception:
                logger.exception("Failed to execute address 0x{:X}: {}".format(ip, idc.GetDisasm(ip)))
        else:
            logger.debug("{} instruction not implemented.".format(mnem))

        # Record executed instruction.
        self.executed_instructions.append(ip)

        # After execution, set instruction pointer to next instruction assuming
        # standard code flow and if no jump was made.
        if self.ip == ip:
            self.ip = idc.next_head(ip)

    def get_call_history(self, func_name):
        """
        Returns the call history for a specific function name.

        :returns: List of tulples containing: (ea of call, list of function arguments)
        """
        return [(ea, args) for ea, (_func_name, args) in list(self.func_calls.items()) if _func_name == func_name]

    def prep_for_branch(self, bb_start_ea):
        """
        Modify this current context in preparation for a specific path.
        """
        if self.jcccontext.is_alt_branch(bb_start_ea):
            logger.debug("Modifying context for branch at 0x{:X}".format(bb_start_ea))
            # Set the destination operand relative to the current context
            # to a valid value that makes this branch true.
            dst_opnd = self.jcccontext.alt_branch_data_dst
            dst_opnd = self.get_operands(ip=dst_opnd.ip)[dst_opnd.idx]
            dst_opnd.value = self.jcccontext.alt_branch_data

        self.jcccontext = JccContext()

    def get_operands(self, ip=None):
        """
        Gets the Operand objects of all operands in the current instruction and returns them in a list.

        :param int ip: location of instruction pointer to pull operands from (defaults to current rip in context)

        :return: list of Operand objects
        """
        if ip is None:
            ip = self.ip

        operands = []
        cmd = ida_ua.insn_t()
        # NOTE: We can't trust the instruction length returned by decode_ins.
        ida_ua.decode_insn(cmd, ip)
        for idx, op in enumerate(cmd.ops):
            operand = Operand(self, ip, idx)
            # IDA will sometimes create hidden or "fake" operands.
            # These are there to represent things like an implicit EAX register.
            # To help avoid confusion to the opcode developer, these fake operands will not be included.
            if not operand.is_hidden:
                operands.append(operand)

            if operand.is_void:
                break  # no more operands

        return operands

    @property
    def operands(self):
        return self.get_operands()

    def reg_read(self, reg):
        """
        Read a register value

        >>> cpu_context = ProcessorContext()
        >>> cpu_context.reg_read("EIP")

        :param str reg: register name to be read

        :return int: value contained in specified register as int
        """
        return self.registers[reg]

    def reg_write(self, reg, val):
        """
        Write a register value

        :param str reg: register name to be written

        :param int val: value to be written to register as an int of width of the register (will be truncated as necessary)
        """
        self.registers[reg] = val

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

    def read_data(self, addr, size=None, data_type=None):
        """
        Reads memory at the specified address, of the specified size and convert
        the resulting data into the specified type.

        :param int addr: address to read data from
        :param int size: size of data to read
        :param data_type: type of data to be extracted
            (default to byte string is size provided or C string if not)
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

    def get_function_signature(self, func_ea=None, force=False) -> FunctionSignature:
        """
        Returns the function signature of the given func_ea with argument values pulled
        from this context.

        :param int func_ea: address of the function to pull signature from.
            The first operand is used if not provided. (helpful for a "call" instruction)
        :param bool force: Whether to force a function signature using cdecl calling
            convention and no arguments if we fail to generate the signature.
            (Useful when trying to declare a function that was dynamically created in a register)
        :return: FunctionSignature object

        :raises RuntimeError: If a function signature could not be created from given ea.
        """
        # If func_ea is not given, assume we are using the first operand from a call instruction.
        if not func_ea:
            operand = self.operands[0]
            # function pointer can be a memory reference or immediate.
            func_ea = operand.addr or operand.value

        try:
            return FunctionSignature(self, func_ea)
        except RuntimeError as e:
            # If we fail to get a function signature but force is set, set the type to
            # cdecl with no arguments.
            if force:
                logger.warning(
                    "Failed to create function signature at 0x{:0X} with error: {}\n"
                    "Forcing signature with assumed cdecl calling convention.".format(func_ea, e)
                )
                idc.SetType(func_ea, "int __cdecl no_name();")
                return FunctionSignature(self, func_ea)
            else:
                raise

    def get_function_args(self, func_ea=None, num_args=None):
        """
        Returns the function argument values for this context based on the
        given function.

        >>> cpu_context = ProcessorContext()
        >>> args = cpu_context.get_function_args(0x180011772)

        :param int func_ea: Ea of the function to pull a signature from.
        :param int num_args: Force a specific number of arguments.
            If not provided, number of arguments is determined by the disassembler.
            Extra arguments not defined by the disassembler are assumed to be 'int' type.
            Use get_function_signature() and adjust the FunctionSignature manually
            if more customization is needed.
            (NOTE: The function signature will be forced on failure if this is set.)

        :returns: list of function arguments
        """
        func_sig = self.get_function_signature(func_ea, force=num_args is not None)

        if num_args is not None:
            if num_args < 0:
                raise ValueError("num_args is negative")
            arg_types = func_sig.arg_types
            if len(arg_types) > num_args:
                func_sig.arg_types = arg_types[:num_args]
            elif len(arg_types) < num_args:
                func_sig.arg_types = arg_types + ("int",) * (num_args - len(arg_types))

        return [arg.value for arg in func_sig.args]
