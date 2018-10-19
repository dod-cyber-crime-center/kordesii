"""
Contains various helper functions for our tracing, which is static pseudo-execution of assembly.
"""

import idc
import idaapi

# FE
POS_FIRST = 0
POS_SECOND = 1
POS_THIRD = 2

ESI_REG_FAM = ['rsi', 'esi', 'si', 'sil']
EDI_REG_FAM = ['rdi', 'edi', 'di', 'dil']
EBP_REG_FAM = ['rbp', 'ebp', 'bp', 'bpl']
ESP_REG_FAM = ['rsp', 'esp', 'sp', 'spl']
EIP_REG_FAM = ['rip', 'eip', 'ip']
EAX_REG_FAM = ['rax', 'eax', 'ax', 'ah', 'al']
EBX_REG_FAM = ['rbx', 'ebx', 'bx', 'bh', 'bl']
ECX_REG_FAM = ['rcx', 'ecx', 'cx', 'ch', 'cl']
EDX_REG_FAM = ['rdx', 'edx', 'dx', 'dh', 'dl']
R8_REG_FAM = ['r8', 'r8d', 'r8w', 'r8b']
R9_REG_FAM = ['r9', 'r9d', 'r9w', 'r9b']
R10_REG_FAM = ['r10', 'r10d', 'r10w', 'r10b']
R11_REG_FAM = ['r11', 'r11d', 'r11w', 'r11b']
R12_REG_FAM = ['r12', 'r12d', 'r12w', 'r12b']
R13_REG_FAM = ['r13', 'r13d', 'r13w', 'r13b']
R14_REG_FAM = ['r14', 'r14d', 'r14w', 'r14b']
R15_REG_FAM = ['r15', 'r15d', 'r15w', 'r15b']
XMM0_REG_FAM = ["xmm0"]
XMM1_REG_FAM = ["xmm1"]

''' All x86 registers, broken up into families (such as rax, eax, ax, ah, al)'''
REG_FAM = [ESI_REG_FAM, EDI_REG_FAM, EBP_REG_FAM,
           ESP_REG_FAM, EIP_REG_FAM, EAX_REG_FAM,
           EBX_REG_FAM, ECX_REG_FAM, EDX_REG_FAM,
           R8_REG_FAM, R9_REG_FAM, R10_REG_FAM,
           R11_REG_FAM, R12_REG_FAM, R13_REG_FAM,
           R14_REG_FAM, R15_REG_FAM, XMM0_REG_FAM,
           XMM1_REG_FAM]

''' Non-general registers '''
RESERVED_REG_FAM = [ESI_REG_FAM, EDI_REG_FAM, EBP_REG_FAM, ESP_REG_FAM, EIP_REG_FAM]

''' Move mnemonics '''
MOVS = ('rep mov', 'movsb', 'movsw', 'movsd')


class TraceState(object):
    """
    An object to hold all tracing's stateful info.
    """

    def __init__(self):
        self.regs = {}
        self.stack = {}
        self.visited_eas = []
        self.pp_track = []  # push/pop tracker

    def get_reg_value(self, reg):
        """Get the value of the register. The register or the register family can be specified.

        :param reg: The register to retrieve the value of. May be the register family.

        :return: The value of the register if known, or None
        """
        if type(reg) == type(''):
            reg = unsafe_get_reg_fam(reg)
        if reg:
            return self.regs.get(reg[0], (None, None))[0]
        else:
            return None

    def set_reg_value(self, reg, value, ea):
        """Set the value of the register. The register or the register family can be specified.

        :param reg: The register to set the value of. May be the register family.
        :param value: The value to set, or None if the value is not known/cannot be determined.
        :param ea: The address where the register is being set.

        :return:
        """
        if type(reg) == type(''):
            reg = unsafe_get_reg_fam(reg)
        if reg:
            if value is not None:
                self.regs[reg[0]] = (value, ea)
            elif reg[0] in self.regs:
                del self.regs[reg[0]]


class BranchingTraceState(TraceState):
    """
    An object to hold all tracing's stateful info including ea.
    """

    def __init__(self, ea=None, state=None):
        super(BranchingTraceState, self).__init__()
        self.ea = idc.BADADDR if ea is None else ea
        if state is not None:
            if ea == idc.BADADDR:
                self.ea = state.ea
            # Note: this needs to be "global" amongst all derived states, so it cannot be a new list.
            self.visited_eas = state.visited_eas
            self.pp_track = list(state.pp_track)
            self.regs = dict(state.regs)
            self.stack = dict(state.stack)


def unsafe_get_reg_fam(reg):
    """Gets the register family for any register

        :param reg: register string representation such as 'eax'

        :return: list of all associated register names, such as ['rax', 'eax',  'ax', 'ah', 'al']
    """
    for family in REG_FAM:
        if reg in family:
            return family


def get_reg_fam(reg):
    """ Gets the register family, returns None if it is a reserved register

        :param reg: register string representation such as 'eax'

        :return: list of all associated register names, such as ['rax', 'eax',  'ax', 'ah', 'al']
    """
    if get_reserved_reg(reg):
        return
    return unsafe_get_reg_fam(reg)


def get_reserved_reg(reg):
    """Gets the family of a reserved register, returns None otherwise

        :param reg: register string representation such as 'eax'

        :return: list of all associated register names, such as ['rax', 'eax',  'ax', 'ah', 'al']
    """
    for family in RESERVED_REG_FAM:
        if reg in family:
            return family


def get_reg_value(reg_values, reg):
    """
        Helper function to retrieve the current value of a register given the register dictionary returned from
        create_stack and the string representation of the register name

        :param reg_values: register dictionary returned by create_stack function
        :param reg: string representation of the register name

        :return: value of register, None if register not in dictionary
    """
    regfam = unsafe_get_reg_fam(reg)
    if regfam:
        try:
            if reg_values[regfam[0]]:
                return reg_values[regfam[0]][0]
        except KeyError:
            return None
    else:
        return None


def get_reg_value_offset(reg_values, reg):
    """
    Obtain the tuple of value, offset for a specified register when provided the TracerState().regs dictionary.

    :param reg_values: TracerState().regs dictionary
    :param reg: Target register

    :return: Tuple of value, offset if register in dictionary, otherwise None, None
    """
    regfam = unsafe_get_reg_fam(reg)
    if regfam:
        try:
            return reg_values[regfam[0]]
        except KeyError:
            return None, None
    else:
        return None, None


def is_64_bit():
    """Returns True if the code is 64-bit code, false otherwise"""
    return idaapi.get_inf_structure().is_64bit()


def get_int(val):
    """Attempts to convert the string given into the correct integer"""
    try:
        if val.isdigit():
            return int(val)
        elif val.endswith('h'):
            return int(val[:-1], 16)
        elif val.endswith('o'):
            return int(val[:-1], 8)
        elif val.endswith('b'):
            return int(val[:-1], 2)
    except:
        logger.warning("Failed to get int from value: " + str(val))
        return 0


OPERAND_BYTE_SIZES = {0: 1,
                      1: 2,
                      2: 4,
                      3: 4,
                      4: 8,
                      5: 4,  # Actually variable, so may not be 4
                      6: 4,  # Actually packed real format for mc68040, so may not be 4
                      7: 8,
                      8: 16,
                      9: 4,  # Actually a pointer, so may not be 4
                      10: 4,  # Actually a void, so may not be 4
                      11: 5,
                      12: 1,  # Actually a bit field, so less than one.
                      13: 4,  # Actually a pointer, so may not be 4
                      14: 4,  # Actually a pointer, so may not be 4
                      15: 3,
                      16: 16,  # Actually a long double, so may not be 16
                      17: 32,
                      18: 64}


def get_byte_size_of_operand(ea, pos):
    """Gets the byte size of the operand at the given ea and position"""
    idaapi.decode_insn(ea)
    return OPERAND_BYTE_SIZES.get(idaapi.cmd.Operands[pos].dtyp, 4)  # 4 is Unknown


def get_opnd_replacement(ea, pos):
    """ A replacement for IDA's idc.GetOpnd that can de-alias register names"""
    # TODO: Support renames in other operand types
    if idc.GetOpType(ea, pos) == idc.o_reg:
        return idaapi.get_reg_name(idc.GetOperandValue(ea, pos), get_byte_size_of_operand(ea, pos))
    else:
        return idc.GetOpnd(ea, pos)


def obtain_phrase_register(ea, pos):
    """
    Obtain the register referenced in an idc.o_phrase

    :param ea: Memory location
    :param pos: Argument location

    :return: Register or None
    """
    if idc.GetOpType(ea, pos) == idc.o_phrase:
        opnd = get_opnd_replacement(ea, pos)
        for family in REG_FAM:
            for member in family:
                if member in opnd:
                    return member


def is_displ(ea, pos):
    """Determines if the ea/position is a displacement, such as [esp + 8]

        :param ea: memory location
        :param pos: argument location
                    example:
                        add eax, ebx
                        eax is position 0, ebx is position 1

        :return: True or False
    """
    return idc.GetOpType(ea, pos) in (idc.o_phrase, idc.o_displ)


def get_operand_value_replacement(ea, pos, state):
    """ A replacement for Ida's idc.GetOperandValue that handles displacements more reasonably

        :param ea: memory location
        :param pos: argument location
                    example:
                        add eax, ebx
                        eax is position 0, ebx is position 1
        :param state: the current stack pointer register family (usually sp)

        :return: computes a numerical replacement for an operand
    """
    if is_displ(ea, pos):
        bit_size = 64 if is_64_bit() else 32
        stack_reg = 'rsp' if bit_size == 64 else 'esp'
        idaapi.decode_insn(ea)
        offset = idaapi.cmd.Operands[pos].addr
        # Convert the offset to a signed value
        if offset & (1 << (bit_size - 1)):
            offset -= (1 << bit_size)
        if stack_reg in get_opnd_replacement(ea, pos):
            offset += idc.GetSpd(ea) or 0
        return offset
    else:
        return idc.GetOperandValue(ea, pos)


def get_encoded_stack_string(stack, startoffset, size=None):
    """
        given a stack and the starting offset, pull out the string from the stack\
        if size is given, pull that many bytes off stack

        :param stack: stack dictionary of your current working stack as created by the create_stack function
        :param startoffset: offset to start from on stack
        :param size: optional parameter for size to pull off stack, if not set will read until a null byte

        :return: string of characters from the stack dictionary starting at offset and reading until size or a null byte
    """
    encrypted = []
    offset = startoffset
    while stack.get(offset):
        if not size and stack[offset][0] == 0:
            break
        if size and size + startoffset == offset:
            break
        encrypted.append(stack[offset][0])
        offset += 1
    return ''.join(map(chr, encrypted))


def get_encoded_stack_string_wide(stack, startoffset, size=None):
    """
        given a stack and the starting offset, pull out the string from the stack\
        if size is given, pull that many bytes off stack

        :param stack: stack dictionary of your current working stack as created by the create_stack function
        :param startoffset: offset to start from on stack
        :param size: optional parameter for size to pull off stack, if not set will read until two null bytes
                    (wchar null)

        :return: string of characters from the stack dictionary starting at offset and reading until size or a null byte
                 this will not be wide characters
    """
    encrypted = []
    offset = startoffset
    while stack.get(offset) and stack.get(offset + 1):
        if not size and stack[offset][0] == 0 and stack[offset + 1][0] == 0:
            break
        if size and size + startoffset >= offset:
            break
        encrypted.append(stack[offset][0])
        encrypted.append(stack[offset + 1][0])
        offset += 2
    return ''.join(map(chr, encrypted))


def set_stack(offset, ea, pos, state):
    """Sets the stack dictionary, at the given offset, to contain the value at the given position at the given ea,
        performing a lookup in the register dictionary if needed. Used by create_stack

        :param offset: offset to set on stack
        :param ea: instruction location
        :param pos: argument position
        :param state: the current TraceState

        :return: None - updates state
    """
    if idc.GetOpType(ea, pos) == idc.o_imm:
        val = idc.GetOperandValue(ea, pos)
    else:
        val = state.get_reg_value(get_opnd_replacement(ea, pos))
    if val is not None:
        for i in xrange(get_byte_size_of_operand(ea, pos)):
            state.stack[offset + i] = (val & 0xff, ea)
            val >>= 8


def handle_string_mov(ea, state):
    """Updates the stack based on a movs instruction.  Used by create_stack
        If a rep/repne prefix is used, takes the count from ecx.  If the count cannot be determined, will ignore
        the instruction.  Also assumes that esi points to memory within the executable, and edi points to the
        stack. On any errors, this will ignore the instruction.

        :param ea: instruction location
        :param state: the current TraceState

        :return: None - updates stack or regs
    """
    opcode = idaapi.get_many_bytes(ea, 1)
    rep_inst = opcode in ['\xf2', '\xf3']
    count = state.get_reg_value('ecx') if rep_inst else 1
    if not count or count < 0:
        return

    inslen = idaapi.decode_insn(ea)
    dtyp = idaapi.cmd.Operands[0].dtyp
    word_size = [1, 2, 4][dtyp] if dtyp < 3 else 4
    count *= word_size

    src = state.get_reg_value('esi')
    dst = state.get_reg_value('edi')
    if src is None or dst is None:
        return
    # In IDA 7, get_many_bytes doesn't return None on failure, instead it will return
    # a string of \xff the size of count. My theory is that the function changed
    # to return -1 for each byte within the c code and something is casting it to a string before returning.
    # Since, all \xff's could be valid we need to check if src is valid instead.
    if not idc.is_loaded(src):
        return
    bytes = idaapi.get_many_bytes(src, count)
    if bytes in (None, -1):  # Keep this around in-case they fix it in a future version.
        return
    for i in xrange(count):
        state.stack[dst + i] = (ord(bytes[i]), ea)

    if rep_inst:
        state.set_reg_value('ecx', 0, ea)
    state.set_reg_value('esi', src + count, ea)
    state.set_reg_value('edi', dst + count, ea)


def handle_mov(ea, state):
    """Updates the stack based on a mov instruction. Used by create_stack

        :param ea: instruction location
        :param state: the current TraceState

        :return: None - updates stack or regs
    """
    op1 = get_opnd_replacement(ea, POS_FIRST)
    if idc.GetOpType(ea, POS_FIRST) != idc.o_reg:
        offset = get_operand_value_replacement(ea, POS_FIRST, state)
        set_stack(offset, ea, POS_SECOND, state)
    else:
        type_ = idc.GetOpType(ea, POS_SECOND)
        val = None
        if type_ == idc.o_reg:
            val = state.get_reg_value(get_opnd_replacement(ea, POS_SECOND))
        elif type_ == idc.o_mem:
            bytes = idc.GetManyBytes(idc.GetOperandValue(ea, POS_SECOND), get_byte_size_of_operand(ea, POS_SECOND))
            if bytes:
                val = 0
                for x in range(len(bytes)):
                    val += ord(bytes[x]) << (8 * x)
        elif type_ == idc.o_imm:
            val = idc.GetOperandValue(ea, POS_SECOND)
        else:
            offset = get_operand_value_replacement(ea, POS_SECOND, state)
            val, ea = state.stack.get(offset, (None, ea))
        state.set_reg_value(op1, val, ea)


def handle_lea(ea, state):
    """Updates the stack based on an lea instruction. Used by create_stack

        :param ea: instruction location
        :param state: the current TraceState

        :return: None - updates stack or regs
    """
    value = get_operand_value_replacement(ea, POS_SECOND, state)
    if not value and idc.GetOpType(ea, POS_SECOND) != idc.o_mem:
        return

    state.set_reg_value(get_opnd_replacement(ea, POS_FIRST), value, ea)


def handle_push(ea, state):
    """
        Loosely tracks the values that get pushed onto the stack, if the value is unknown when pushed.
        Should be called any time you see a push instruction if tracking

        :param ea: instruction location
        :param state: the current TraceState
    """
    op_type = idc.GetOpType(ea, POS_FIRST)
    if op_type == idc.o_reg:
        value = state.get_reg_value(get_opnd_replacement(ea, POS_FIRST))
    elif op_type == idc.o_imm:
        value = get_operand_value_replacement(ea, POS_FIRST, state)
    else:
        value = None
    state.pp_track.append(value)


def handle_pop(ea, state):
    """
        if op type is a reg, pops the tracked value if not none into the appropriate reg
        should be called anytime a pop is seen if tracking

        :param ea: instruction location
        :param state: the current TraceState
    """
    value = state.pp_track.pop() if state.pp_track else None
    if idc.GetOpType(ea, POS_FIRST) == idc.o_reg:
        state.set_reg_value(get_opnd_replacement(ea, POS_FIRST), value, ea)


def handle_test(ea, state):
    """
        If a test of a register against itself occurs and the next instruction is a jnz,
        then the register can be set to zero (code is followed linearly, jumps are ignored),
        unless the next instruction is a jmp.

        :param ea: instruction location
        :param state: the current TraceState
    """
    if idc.GetOpType(ea, POS_FIRST) == idc.o_reg and idc.GetOpType(ea, POS_SECOND) == idc.o_reg:
        op1 = get_opnd_replacement(ea, POS_FIRST)
        op2 = get_opnd_replacement(ea, POS_SECOND)
        next_ea = ea + idc.ItemSize(ea)
        if op1 == op2 and idc.GetMnem(next_ea) == 'jnz':
            next_ea += idc.ItemSize(next_ea)
            if not idc.GetMnem(next_ea).startswith('j'):
                state.set_reg_value(op1, 0, ea)


def create_state(endEA, startEA=None):
    """
        Quick and dirty representation of stack and regs from start of function to this ea.

        :param endEA: The EA of which you want to compute the stack up until
        :param startEA: Optional param of the beginning of the function - sometimes necessary if ida can't
                        compute and you can

        :return A newly created TraceState
    """
    if not startEA:
        startEA = idaapi.get_func(endEA).startEA
    state = TraceState()
    ea = startEA
    while ea < endEA:
        mnemonic = idc.GetMnem(ea)
        if mnemonic.startswith('movs'):
            handle_string_mov(ea, state)
        elif mnemonic.startswith('mov'):
            handle_mov(ea, state)
        elif mnemonic in ['xor', 'sub'] and get_opnd_replacement(ea, POS_FIRST) == get_opnd_replacement(ea, POS_SECOND):
            state.set_reg_value(get_opnd_replacement(ea, POS_FIRST), 0, ea)
        elif mnemonic == 'lea':
            handle_lea(ea, state)
        elif mnemonic == 'push':
            handle_push(ea, state)
        elif mnemonic == 'pop':
            handle_pop(ea, state)
        elif mnemonic in ['test', 'cmp']:
            handle_test(ea, state)
        elif mnemonic:
            if idc.GetOpType(ea, POS_FIRST) == idc.o_reg:
                state.set_reg_value(get_opnd_replacement(ea, POS_FIRST), None, ea)

        ea += idc.ItemSize(ea)
    return state


def trace_rep_mov(stack_var, loc, func_ea, state):
    """
    Helper function to trace back a rep mov
    """
    loc = idc.PrevHead(loc)
    while loc != func_ea:
        mnem = idc.GetMnem(loc)
        if mnem == 'lea' and idc.GetOpnd(loc, 0) == 'edi':
            if stack_var == get_operand_value_replacement(loc, 1, state):
                return trace_register('esi', loc, func_ea, state)
            return None
        loc = idc.PrevHead(loc)
    return None


def trace_stack_var(stack_var, loc, func_ea, state=None):
    """
    Trace a provided stack variable to the location in which it is set. If it is set using a mov operation, the
    value may be set from a register, which we then need to call back to trace_register in order to acquire the
    value. Otherwise it is either an o_imm type (return the immediate value) or an o_mem type, that means the
    referenced location MAY a pointer to the actual data, which we need to acquire. We validate this by ensuring
    the acquired value is within the loaded memory range of the application. Otherwise we return idc.BADADDR.

    :param stack_var: The stack variable which a location is loaded into
    :param loc: The starting offset for tracing back from
    :param func_ea: Starting function offset
    :param state: the current TraceState

    :return: The acquired location, or idc.BADADDR
    """
    if state is None:
        state = TraceState()
    loc = idc.PrevHead(loc)
    while loc != func_ea:
        op_type_1 = idc.GetOpType(loc, 1)
        opval_1 = idc.GetOperandValue(loc, 1)
        mnem = idc.GetMnem(loc)
        dis = idc.GetDisasm(loc)
        if mnem == 'mov' and stack_var == get_operand_value_replacement(loc, 0, state):
            if op_type_1 == idc.o_reg:
                return trace_register(idc.GetOpnd(loc, 1), loc, func_ea, state)
            elif op_type_1 == idc.o_imm:
                return opval_1
            elif op_type_1 == idc.o_mem:
                poss_loc = idc.Dword(opval_1)
                if idaapi.cvar.inf.minEA <= poss_loc < idaapi.cvar.inf.maxEA:
                    return poss_loc
                else:
                    return opval_1
            else:
                return idc.BADADDR
        elif any(x in dis for x in MOVS):
            result = trace_rep_mov(stack_var, loc, func_ea, state)
            if result:
                return result
        loc = idc.PrevHead(loc)
    return idc.BADADDR


def trace_register(reg, loc, func_ea, state=None):
    """
    Trace a provided register to the location in which it is set. If it is set using a mov operation, the
    value is either an o_imm type (return the immediate value) or an o_mem type, that means the referenced location
    MAY a pointer to the actual data, which we need to acquire. We validate this by ensuring the acquired value is
    within the loaded memory range of the application. Otherwise we return idc.BADADDR.

    If the register is set using an lea operation, it is likely done so using a stack variable (which we validate)
    and then trace back to determine how the stack variable is set.

    :param reg: The referenced register which a location is loaded into
    :param loc: The starting offset for tracing back from
    :param func_ea: Starting function offset
    :param state: the current TraceState

    :return: The acquired location, or idc.BADADDR
    """
    if state is None:
        state = TraceState()
    loc = idc.PrevHead(loc)
    while loc != func_ea:
        opnd = idc.GetOpnd(loc, 0)
        op_type_1 = idc.GetOpType(loc, 1)
        opval_1 = idc.GetOperandValue(loc, 1)
        mnem = idc.GetMnem(loc)
        if 'mov' in mnem and opnd == reg:
            if op_type_1 == idc.o_imm:
                return opval_1
            elif op_type_1 == idc.o_mem:
                poss_loc = idc.Dword(opval_1)
                if idaapi.cvar.inf.minEA <= poss_loc < idaapi.cvar.inf.maxEA:
                    return poss_loc
                else:
                    return opval_1
            else:
                return idc.BADADDR
        elif mnem == 'lea' and op_type_1 == idc.o_displ and opnd == reg:
            stack_var = get_operand_value_replacement(loc, 1, state)
            return trace_stack_var(stack_var, loc, func_ea, state)
        elif is_64_bit() and mnem == 'lea' and opnd == reg:
            if op_type_1 == idc.o_mem:
                return opval_1
        loc = idc.PrevHead(loc)
    return idc.BADADDR


def trace_register_family(reg, loc, func_ea, state=None):
    """
    Trace a provided register to the location in which any member of its register family is set. If it is set using a
    mov operation, the value is either an o_imm type (return the immediate value) or an o_mem type, that means the
    referenced location MAY a pointer to the actual data, which we need to acquire. We validate this by ensuring the
    acquired value is within the loaded memory range of the application. Otherwise we return idc.BADADDR.

    If the register is set using an lea operation, it is likely done so using a stack variable (which we validate)
    and then trace back to determine how the stack variable is set.

    :param reg: The referenced register which a location is loaded into
    :param loc: The starting offset for tracing back from
    :param func_ea: Starting function offset
    :param state: the current TraceState (a new state will be created if one is not provided)

    :return: The acquired location, or idc.BADADDR
    """
    if state is None:
        state = TraceState()
    reg_fam = unsafe_get_reg_fam(reg)
    if reg_fam:
        loc = idc.PrevHead(loc)
        while loc != func_ea:
            opnd = idc.GetOpnd(loc, 0)
            op_type_1 = idc.GetOpType(loc, 1)
            opval_1 = idc.GetOperandValue(loc, 1)
            mnem = idc.GetMnem(loc)
            if 'mov' in mnem and opnd in reg_fam:
                if op_type_1 == idc.o_imm:
                    return opval_1
                elif op_type_1 == idc.o_mem:
                    poss_loc = idc.Dword(opval_1)
                    if idaapi.cvar.inf.minEA <= poss_loc < idaapi.cvar.inf.maxEA:
                        return poss_loc
                    else:
                        return opval_1
                else:
                    return idc.BADADDR
            elif mnem == 'lea' and op_type_1 == idc.o_displ and opnd in reg_fam:
                stack_var = get_operand_value_replacement(loc, 1, state)
                return trace_stack_var(stack_var, loc, func_ea, state)
            elif is_64_bit() and mnem == 'lea' and opnd in reg_fam:
                if op_type_1 == idc.o_mem:
                    return opval_1
            loc = idc.PrevHead(loc)
    return idc.BADADDR


def trace_register_family_x64(reg, loc, func_ea, state=None):
    """
    Shouldn't be any different than trace_register_family except for continuing a trace if a register is loaded into
    the target register. However, using it in trace_register_family was not behaving properly, so keeping it separate
    for now. Also unsure of what the repercussions would be of adding that into the existing trace_register_family.

    :param reg: The referenced register which a location is loaded into
    :param loc: The starting offset for tracing back from
    :param func_ea: Starting function offset
    :param state: the current TraceState

    :return: The acquired location, or idc.BADADDR
    """
    if state is None:
        state = TraceState()
    reg_fam = unsafe_get_reg_fam(reg)
    if reg_fam:
        loc = idc.PrevHead(loc)
        while loc != func_ea:
            opnd = idc.GetOpnd(loc, 0)
            op_type_1 = idc.GetOpType(loc, 1)
            opval_1 = idc.GetOperandValue(loc, 1)
            mnem = idc.GetMnem(loc)
            if 'mov' in mnem and opnd in reg_fam:
                if op_type_1 == idc.o_imm:
                    return opval_1
                elif op_type_1 == idc.o_mem:
                    poss_loc = idc.Dword(opval_1)
                    if idaapi.cvar.inf.minEA <= poss_loc < idaapi.cvar.inf.maxEA:
                        return poss_loc
                    else:
                        return opval_1
                elif op_type_1 == idc.o_reg:
                    return trace_register_family_x64(idc.GetOpnd(loc, 1), loc, func_ea, state)
                else:
                    return idc.BADADDR
            elif mnem == 'lea' and op_type_1 == idc.o_displ and opnd in reg_fam:
                stack_var = get_operand_value_replacement(loc, 1, state)
                return trace_stack_var(stack_var, loc, func_ea, state)
            elif is_64_bit() and mnem == 'lea' and opnd in reg_fam:
                if op_type_1 == idc.o_mem:
                    return opval_1
            loc = idc.PrevHead(loc)
    return idc.BADADDR
