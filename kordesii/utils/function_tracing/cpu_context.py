"""
Implements the "hardware" for tracing a function.

Will perform the instructions and updates CPU registers, stack information, etc.

WARNING:
    Do NOT rely on the flags registers being correct.  There are places were flags are NOT being updated when they
    should, and the very fact that CALL instructions are skipped could cause flags to be incorrect.
"""

import collections
import numpy
import logging

import idaapi
import idautils
import idc
import ida_frame
import ida_struct

from kordesii.utils.function_tracing.exceptions import FunctionTracingError
from kordesii.utils.function_tracing import utils
from kordesii.utils.function_tracing.constants import *
from kordesii.utils.function_tracing.memory import Memory


logger = logging.getLogger(__name__)


class Operand(object):
    """Stores information for a given operand for a specific CPU context state."""

    TYPE_DICT = {
        0: 1,  # dt_byte -> 8 bit
        1: 2,  # dt_word -> 16 bit
        2: 4,  # dt_dword -> 32 bit
        3: 4,  # dt_float -> 4 bytes
        4: 8,  # dt_double -> 8 bytes
        5: 0,  # dt_tbyte -> variable
        6: 0,  # packed real format for mc68040
        7: 8,  # dt_qword -> 64 bit
        8: 16,  # dt_byte16 -> 128 bit
        9: 0,  # dt_code -> ptr to code (not used?)
        10: 0,  # dt_void -> none
        11: 6,  # dt_fword -> 48 bit
        12: 0,  # dt_bitfild -> bit field (mc680x0)
        13: 4,  # dt_string -> pointer to asciiz string
        14: 4,  # dt_unicode -> pointer to unicode string
        # 15: 3, # dt_3byte -> no longer used
        16: 0,  # dt_ldbl -> long double (which may be different from tbyte)
        17: 32,  # dt_byte32 -> 256 bit
        18: 64  # dt_byte64 -> 512 bit
    }

    def __init__(self, cpu_context, ip, idx):
        """
        :param cpu_context: CPU context to pull operand value
        :param ip: instruction pointer
        :param idx: operand number (0 = first operand, 1 = second operand, ...)
        """
        self.ip = ip
        self.idx = idx
        self.type = idc.get_operand_type(ip, idx)
        self.text = idc.print_operand(ip, idx)
        self._cpu_context = cpu_context
        self._width = None

    def __repr__(self):
        string = '<Operand 0x{:0x}:{} : {} = {!r}'.format(self.ip, self.idx, self.text, self.value)
        if self.addr is not None:
            string += ' : &{} = 0x{:0x}'.format(self.text, self.addr)
        string += ' : width = {}>'.format(self.width)
        return string

    @property
    def width(self):
        """
        Based on the dtyp value, return the size of the operand in bytes

        :return: size of data type
        """
        if self._width is not None:
            return self._width
        insn = idautils.DecodeInstruction(self.ip)
        if not insn:
            raise FunctionTracingError('Failed to decode instruction at 0x:{:X}'.format(self.ip))
        dtype = insn.ops[self.idx].dtype
        self._width = self.TYPE_DICT[dtype]
        return self._width

    @property
    def is_fake(self):
        """
        Returns true if the operand is not a real operand.
        (Ie. fake operands IDA likes to put in for some reason.)
        """
        return self.text == "" or self.type == idc.o_void

    @property
    def is_register(self):
        """Returns true if the operand is a single register."""
        return self.type == idc.o_reg

    @property
    def has_register(self):
        """Returns true if the operand contains a register."""
        return self.type in (idc.o_reg, idc.o_displ, idc.o_phrase)

    @property
    def is_immediate(self):
        """Returns true if the operand is an immediate value."""
        return self.type in (idc.o_imm, idc.o_near, idc.o_far)

    @property
    def is_memory_reference(self):
        """Returns true if the operand is a memory reference."""
        return self.type in (idc.o_mem, idc.o_phrase, idc.o_displ)

    @property
    def has_phrase(self):
        """Returns true if the operand contains a phrase."""
        return self.type in (idc.o_phrase, idc.o_displ)

    def _is_func_ptr(self, offset):
        """Returns true if the given offset is a function pointer."""
        # Sometimes we will get a really strange issue where the IDA disassember has set a type for an
        # address that should not have been set during our course of emulation.
        # Therefore, before attempting to use get_function_data() to test if it's a function pointer,
        # first see if guess_type() will return None while is_loaded() is true.
        # If it doesn't, we know that it shouldn't be a function pointer.
        # (plus it saves on time)
        # TODO: Determine if we could have false negatives.
        try:
            if idc.is_loaded(offset) and not idc.guess_type(offset):
                return False
        except TypeError:
            return False
        try:
            utils.get_function_data(offset)
            return True
        except RuntimeError:
            return False
        except Exception as e:
            # If we get any other type of exception raise a more friendly error message.
            raise FunctionTracingError(
                'Failed to retrieve function data from {!r}: {}'.format(offset, e), ip=self.ip)

    @property
    def is_func_ptr(self):
        """Returns true if the operand is a pointer to a function."""
        return self._is_func_ptr(self.addr or self.value)

    def _calc_displacement(self):
        """
        Calculate the displacement offset of the operand's text.

        e.g:
            word ptr [rdi+rbx]

        :return int: calculated value
        """
        size = 8 if idc.__EA64__ else 4
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, self.ip)
        op = insn.ops[self.idx]
        offset = utils.signed(op.addr, utils.get_bits())
        scale = utils.sib_scale(op)
        base_reg = utils.x86_base_reg(insn, op)
        indx_reg = utils.x86_index_reg(insn, op)
        base_val = self._cpu_context.registers[utils.reg2str(base_reg, size)]
        indx_val = self._cpu_context.registers[utils.reg2str(indx_reg, size)] if indx_reg != -1 else 0
        result = base_val + indx_val * scale + offset
        logger.debug("calc_displacement :: Displacement {} -> {}".format(self.text, result))

        # Before returning, record the frame_id and stack_offset for this address.
        # (This can become useful information for retrieving the original location of a variable)
        frame_id = idc.get_frame_id(self.ip)
        stack_var = ida_frame.get_stkvar(insn, op, offset)
        if stack_var:
            _, stack_offset = stack_var
            self._cpu_context.stack_variables[result] = (frame_id, stack_offset)

        return result

    @property
    def addr(self):
        """
        Retrieves the referenced memory address of the operand.

        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = None
        if self.has_phrase:
            # These need to be handled in the same way even if they don't contain the same types of data...
            addr = self._calc_displacement()
        elif self.type == idc.o_mem:
            addr = idc.get_operand_value(self.ip, self.idx)
        return addr

    @property
    def value(self):
        """
        Retrieve the value of the operand as it is currently in the cpu_context.
        NOTE: We can't cache this value because the value may change based on the cpu context.

        :return int: An integer of the operand value.
        """
        if self.is_fake:
            return None

        if self.is_immediate:
            return idc.get_operand_value(self.ip, self.idx)

        if self.is_register:
            return self._cpu_context.registers[self.text]

        # TODO: Determine if this is still necessary.
        # FS, GS (at least) registers are identified as memory addresses.  We need to identify them as registers
        # and handle them as such
        if self.type == idc.o_mem:
            if "fs" in self.text:
                return self._cpu_context.registers.fs
            elif "gs" in self.text:
                return self._cpu_context.registers.gs

        # If a memory reference, return read in memory.
        if self.is_memory_reference:
            # If a function pointer, we want to return the address.
            # This is because a function may be seen as a memory reference, but we don't
            # want to dereference it in case it in a non-call instruction.
            # (e.g.  "mov  esi, ds:LoadLibraryA")
            # NOTE: Must use internal function to avoid recursive loop.
            if self._is_func_ptr(self.addr):
                return self.addr

            # Return empty
            if not self.width:
                logger.debug('Width is zero for {}, returning empty string.'.format(self.text))
                return b''

            # Otherwise, dereference the address.
            value = self._cpu_context.mem_read(self.addr, self.width)
            return utils.struct_unpack(value)

        raise FunctionTracingError('Invalid operand type: {}'.format(self.type), ip=self.ip)

    @value.setter
    def value(self, value):
        """
        Set the operand to the specified value within the cpu_context.
        """
        # If we are writing to an immediate, I believe they want to write to the memory at the immediate.
        # TODO: Should we fail instead?
        if self.is_immediate:
            offset = self.value
            if idaapi.is_loaded(offset):
                self._cpu_context.mem_write(offset, value)
            return

        if self.is_register:
            # Convert the value from string to integer...
            if isinstance(value, str):
                value = utils.struct_unpack(value)

            # On 64-bit, the destination register must be set to 0 first (per documentation)
            # TODO: Check if this happens regardless of the source size
            if idc.__EA64__ and self.width == 4:  # Only do this for 32-bit setting
                reg64 = utils.convert_reg(self.text, 8)
                self._cpu_context.registers[reg64] = 0

            self._cpu_context.registers[self.text] = value
            return

        # TODO: Determine if this is still necessary.
        # FS, GS (at least) registers are identified as memory addresses.  We need to identify them as registers
        # and handle them as such
        if self.type == idc.o_mem:
            if "fs" in self.text:
                self._cpu_context.registers.fs = value
                return
            elif "gs" in self.text:
                self._cpu_context.registers.gs = value
                return

        if self.is_memory_reference:
            # For data written to the frame or memory, this data MUST be a byte string.
            if numpy.issubdtype(type(value), numpy.integer):
                value = utils.struct_pack(value, width=self.width)
            self._cpu_context.mem_write(self.addr, value)
            return

        raise FunctionTracingError('Invalid operand type: {}'.format(self.type), ip=self.ip)


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

    def update_flag_opnds(self, flags, opnds):
        """
        Set the operands which last changed the specified flags.

        :param flags: list of flags which were modified utilizing the supplied opnds
        :param opnds: list of operands (instance of cpu_emulator.Operand) at the instruction which modified the flags
        """
        for flag in flags:
            self.flag_opnds[flag] = opnds

    def get_flag_opnds(self, flags):
        """
        Extracts all the operands of for the list of flags and reduces the set.  However, since the operands
        need to remain in order, we can't use set operations.  In all actuality, assuming our code is correct and
        the compiler isn't doing something funky, any more than 1 flag should really just be a duplicate list.

        :param flags: list of flags for which to extract operands
        :return: list of operands which were utilized in the instruction that modified the requested flags
        """
        # TODO: Is there a better way to do this?
        opvalues = []
        for flag in flags:
            _opvalues = self.flag_opnds.get(flag, None)
            if not _opvalues:
                continue

            for _opvalue in _opvalues:
                if _opvalue not in opvalues:
                    opvalues.append(_opvalue)

        return opvalues

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
        self.byteness = self.bitness / 8
        self.stack_registers = stack_registers or []
        self.stack_variables = {}  # maps memory addresses -> (frame_id, stack_offset)
        self.stack = []
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
        raise NotImplementedError('Architecture not supported: {}'.format(arch_name))

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
        if idc.get_wide_byte(ip) in (0xf2, 0xf3):
            insn = idc.GetDisasm(ip)  # IDA pro never has operands for rep opcodes.
            if insn.startswith('rep '):
                term_condition = lambda: self.registers.ecx == 0
            elif insn.startswith(('repe ', 'repz ')):
                term_condition = lambda: self.registers.ecx == 0 or self.registers.zf == 0
            elif insn.startswith(('repne ', 'repnz ')):
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
                            '0x{:08X} :: Emulation attempted to read {} instruction {} times. '
                            'Ignoring instruction.'.format(ip, mnem, self.registers.ecx))
                    else:
                        logger.debug('Emulating {} instruction {} times.'.format(mnem, self.registers.ecx))
                        while not term_condition():
                            instruction(self, ip, mnem, operands)
                            self.registers.ecx -= 1
                else:
                    instruction(self, ip, mnem, operands)
            except Exception:
                logger.exception('Failed to execute address 0x{:X}: {}'.format(ip, idc.GetDisasm(ip)))
        else:
            logger.debug('{} instruction not implemented.'.format(mnem))

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
        return [(ea, args) for ea, (_func_name, args) in self.func_calls.items() if _func_name == func_name]

    def prep_for_branch(self, bb_start_ea):
        """
        Modify this current context in preparation for a specific path.
        """
        if self.jcccontext.is_alt_branch(bb_start_ea):
            logger.debug("Modifying context for branch at 0x{:X}".format(bb_start_ea))
            dst_opnd = self.jcccontext.alt_branch_data_dst
            # TODO: There is probably a more elegant way of doing this. Jcccontext should not store the full operand objects.
            # Grab the operands relative to this current context and set the value.
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
        cmd = idaapi.insn_t()
        inslen = idaapi.decode_insn(cmd, ip)
        for i in range(inslen):
            try:
                operand = Operand(self, ip, i)
                # IDA will sometimes create hidden or "fake" operands.
                # These are there to represent things like an implicit EAX register.
                # To help avoid confusion to the opcode developer, these fake operands will not be included.
                if not operand.is_fake:
                    operands.append(operand)
            except (IndexError, RuntimeError):
                # IDA will identify more operands than there actually are causing an issue.
                # Just break out of the loop if this happens.
                # IDA 7 throws RuntimeError instead of IndexError
                break

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
        for ip, copies in sorted(self.memory_copies.items(), reverse=True):
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
        # Pull either the first seen loaded address or last seen stack variable.
        if idc.is_loaded(addr):
            return None, addr
        ip = None
        if addr in self.stack_variables:
            stack_var = self.stack_variables[addr]
        else:
            stack_var = None
        for ip, ea in reversed(self.get_pointer_history(addr)):
            if idc.is_loaded(ea):
                return ip, ea
            if ea in self.stack_variables:
                stack_var = self.stack_variables[ea]
        return ip, stack_var

    # TODO: We should be recording local and global variables and their values.
    #   This will most likely require us making a "Variable" object similar
    #   to what we do with Operand.
    def get_variable_name(self, ea_or_stack_tuple):
        """
        Returns the name of the variable for the given ea or stack tuple.

        :param ea_or_stack_tuple: ea address or tuple containing: (frame_id, stack_offset)
        :return: string of name or None
        """
        if isinstance(ea_or_stack_tuple, tuple):
            frame_id, stack_offset = ea_or_stack_tuple
            member_id = idc.get_member_id(frame_id, stack_offset)
            return ida_struct.get_member_fullname(member_id)
        else:
            ea = ea_or_stack_tuple
            name = idc.get_name(ea)
            if name:
                return name
            _, original_location = self.get_original_location(ea)
            if original_location:
                return self.get_variable_name(original_location)

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
            null_offset = self.memory.find(b'\0', start=addr)
            # It should always eventually find a null since unmapped pages
            # are all null. If we get -1 we have a bug.
            assert null_offset != -1, "Unable to find a null character!"
            return self.memory.read(addr, null_offset - addr)

        elif data_type == WIDE_STRING:
            # Step by 2 bytes to find 2 nulls on an even alignment.
            # (This helps prevent the need to take endianness into account.)
            null_offset = addr
            while self.memory.read(null_offset, 2) != b'\0\0':
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

        raise ValueError('Invalid data_type: {!r}'.format(data_type))

    def get_function_args(self, func_ea=None):
        """
        Returns the function argument values for this context based on the
        given function.

        >>> cpu_context = ProcessorContext()
        >>> args = cpu_context.get_function_args(0x180011772)

        :param int func_ea: Ea of the function to pull a signature from.

        :returns: list of function arguments
        """
        # If func_ea is not given, assume we are using the first operand from a call instruction.
        if not func_ea:
            operand = self.operands[0]
            # function pointer can be a memory reference or immediate.
            func_ea = operand.addr or operand.value

        # First get a func_type_data_t structure for the function
        funcdata = utils.get_function_data(func_ea)

        # Now use the data contained in funcdata to obtain the values for the arguments.
        args = []
        for i in range(funcdata.size()):
            loc_type = funcdata[i].argloc.atype()
            # Where was this parameter passed?
            if loc_type == 0:  # ALOC_NONE, not sure what this means...
                raise NotImplementedError("Argument {} location of type ALOC_NONE".format(i))
            elif loc_type == 1:  # ALOC_STACK
                # read the argument from the stack using the calculated stack offset from the disassembler
                cur_esp = self.sp + funcdata[i].argloc.stkoff()
                arg = self.mem_read(cur_esp, self.byteness)
                args.append(utils.struct_unpack(arg))
            elif loc_type == 2:  # ALOC_DIST, arguments described by multiple locations
                # TODO: Uses the scattered_aloc_t class, which is a qvector or argpart_t objects
                # funcdata[i].argloc.scattered()
                raise NotImplementedError("Argument {} location of type ALOC_DIST".format(i))
            elif loc_type == 3:  # ALOC_REG1, single register
                arg = self.reg_read(utils.REG_MAP.get(funcdata[i].argloc.reg1()))
                width = funcdata[i].type.get_size()
                args.append(arg & utils.get_mask(width))
            elif loc_type == 4:  # ALOC_REG2, register pair (eg: edx:eax [reg2:reg1])
                # TODO: CURRENTLY UNTESTED
                logger.info("Argument {} of untested type ALOC_REG2.  Verify results and report issues".format(i))
                reg1_val = self.reg_read(utils.REG_MAP.get(funcdata[i].argloc.reg1()))
                reg2_val = self.reg_read(utils.REG_MAP.get(funcdata[i].argloc.reg2()))
                # TODO: Probably need to determine how to check the width of these register values in order to shift
                #       the data accordingly.  Will likely need examples for testing/verification of functionality.
                args.append(reg2_val << 32 | reg1_val)
            elif loc_type == 5:  # ALOC_RREL, register relative (displacement from address pointed by register
                # TODO: CURRENTLY UNTESTED
                logger.info("Argument {} of untested type ALOC_RREL.  Verify results and report issues.".format(i))
                # Obtain the register-relative argument location
                rrel = funcdata[i].argloc.get_rrel()
                # Extract the pointer value in the register
                ptr_val = self.reg_read(utils.REG_MAP.get(rrel.reg))
                # Get the offset
                offset = rrel.off
                args.append(ptr_val + offset)
            elif loc_type == 6:  # ALOC_STATIC, global address
                # TODO: CURRENTLY UNTESTED
                logger.info("Argument {} of untested type ALOC_STATIC.  Verify results and report issues.".format(i))
                args.append(funcdata[i].argloc.get_ea())
            elif loc_type >= 7:  # ALOC_CUSTOM, custom argloc
                # TODO: Will need to figure out the functionality and usage for the custloc_desc_t structure
                # funcdata[i].argloc.get_custom()
                raise NotImplementedError("Argument {} location of type ALOC_CUSTOM".format(i))

        return args
