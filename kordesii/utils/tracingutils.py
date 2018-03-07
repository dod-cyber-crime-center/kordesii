'''
Contains various helper functions for our tracing, which is static pseudo-execution of assembly.
'''

import idc
import idaapi
import re

# FE
POS_FIRST  = 0
POS_SECOND = 1
POS_THIRD  = 2
POS_ALL    = 3
POS_DATA   = 10
POS_STACK  = 20

ESI_REG_FAM = ['rsi', 'esi',  'si',      'sil']
EDI_REG_FAM = ['rdi', 'edi',  'di',      'dil']
EBP_REG_FAM = ['rbp', 'ebp',  'bp',      'bpl']
ESP_REG_FAM = ['rsp', 'esp',  'sp',      'spl']
EIP_REG_FAM = ['rip', 'eip',  'ip'            ]
EAX_REG_FAM = ['rax', 'eax',  'ax', 'ah', 'al']
EBX_REG_FAM = ['rbx', 'ebx',  'bx', 'bh', 'bl']
ECX_REG_FAM = ['rcx', 'ecx',  'cx', 'ch', 'cl']
EDX_REG_FAM = ['rdx', 'edx',  'dx', 'dh', 'dl']
R8_REG_FAM  = ['r8',  'r8d',  'r8w',     'r8b']
R9_REG_FAM  = ['r9',  'r9d',  'r9w',     'r9b']
R10_REG_FAM = ['r10', 'r10d', 'r10w',    'r10b']
R11_REG_FAM = ['r11', 'r11d', 'r11w',    'r11b']
R12_REG_FAM = ['r12', 'r12d', 'r12w',    'r12b']
R13_REG_FAM = ['r13', 'r13d', 'r13w',    'r13b']
R14_REG_FAM = ['r14', 'r14d', 'r14w',    'r14b']
R15_REG_FAM = ['r15', 'r15d', 'r15w',    'r15b']

''' All x86 registers, broken up into families (such as rax, eax, ax, ah, al)'''
REG_FAM = [ESI_REG_FAM, EDI_REG_FAM, EBP_REG_FAM,
           ESP_REG_FAM, EIP_REG_FAM, EAX_REG_FAM,
           EBX_REG_FAM, ECX_REG_FAM, EDX_REG_FAM, 
           R8_REG_FAM,  R9_REG_FAM,  R10_REG_FAM,
           R11_REG_FAM, R12_REG_FAM, R13_REG_FAM,
           R14_REG_FAM, R15_REG_FAM]

''' Non-general registers '''
RESERVED_REG_FAM = [ESI_REG_FAM, EDI_REG_FAM, EBP_REG_FAM, ESP_REG_FAM, EIP_REG_FAM]

'''Registers we don't try tracing in absolute terms'''
UNEXTRACTABLE_REG_FAM = [EBP_REG_FAM, ESP_REG_FAM, EIP_REG_FAM]

''' Move mnemonics '''
MOVS = ('rep mov', 'movsb', 'movsw', 'movsd')


class TraceState(object):
    '''
    An object to hold all tracing's stateful info.
    '''
    def __init__(self):
        self.regs = {}
        self.stack = {}
        self.visited_eas = []
        self.stack_pointer_reg_fams = [ESP_REG_FAM]
        self.pp_track = [] # push/pop tracker

class BranchingTraceState(TraceState):
    '''
    An object to hold all tracing's stateful info including ea.
    '''
    def __init__(self, ea = None, state = None):
        super(BranchingTraceState, self).__init__()
        self.ea = idc.BADADDR if ea is None else ea
        if state is not None:
            if ea == idc.BADADDR:
                self.ea = state.ea
            self.visited_eas = state.visited_eas
            self.stack_pointer_reg_fams = state.stack_pointer_reg_fams
            self.pp_track = state.pp_track
            self.regs = dict(state.regs)
            self.stack = dict(state.stack)


def unsafe_get_reg_fam(reg):
    '''Gets the register family for any register
    
        :param reg: register string representaion such as 'eax'
        
        :return: list of all associated register names, such as ['rax', 'eax',  'ax', 'ah', 'al']
    '''
    for family in REG_FAM:
        if reg in family:
            return family

def get_reg_fam(reg):
    ''' Gets the register family, returns None if it is a reserved register
    
        :param reg: register string representaion such as 'eax'
        
        :return: list of all associated register names, such as ['rax', 'eax',  'ax', 'ah', 'al']
    '''
    if get_reserved_reg(reg):
        return
    return unsafe_get_reg_fam(reg)

def get_reserved_reg(reg):
    '''Gets the family of a reserved register, returns None otherwise
        
        :param reg: register string representaion such as 'eax'
        
        :return: list of all associated register names, such as ['rax', 'eax',  'ax', 'ah', 'al']
    '''
    for family in RESERVED_REG_FAM:
        if reg in family:
            return family
        
def get_unextractable_reg(reg):
    '''Gets the family of an unextractable register
    
        :param reg: register string representaion such as 'eax'
        
        :return: list of all associated register names, such as ['rax', 'eax',  'ax', 'ah', 'al']
    '''
    for family in UNEXTRACTABLE_REG_FAM:
        if reg in family:
            return family

def get_reg_value(reg_values, reg):
    '''
        Helper function to retrieve the current value of a register given the register dictionary
        returned from create_stack and the string representation of the register name
        
        :param reg_values: register dictionary returned by create_stack fucntion
        :param reg: string representation of the register name
        
        :return: value of register, None if register not in dictionary
    '''
    regfam = unsafe_get_reg_fam(reg)
    if regfam:
        try:
            if reg_values[regfam[0]]:
                return reg_values[regfam[0]][0]
        except KeyError:
            return None
    else:
        return None

def concatenate(op1_bit_count, op1_value, op2_value):
    '''Puts the two operands together with op1_value being the high bits'''
    return (op2_value << op1_bit_count) + op1_value

# Python will take this number as being signed, so we need to convert out of 2's compliment
def convert_from_2s_compliment(value, bitness_mask):
    '''Converts a signed int to the proper 2's complement value'''
    if value >> (get_bit_count(bitness_mask) - 1):
        return -((value ^ bitness_mask) + 1)
    else:
        return value
    
def get_bit_count(bitness_mask):
    '''Gets the bit count of a bit mask'''
    return hex(bitness_mask).count('f') * 4

def get_reg_bitness_mask(opnd):
    ''' Gets the proper bitmask for a register operand'''
    if opnd[-1] == 'l' or opnd[-1] == 'b':
        return 0xFF
    elif opnd[-1] == 'h':
        return 0xFF00
    elif (len(opnd) == 2 and opnd[0] != 'r') or opnd[-1] == 'w':
        return 0xFFFF
    elif opnd[0] == 'e' or opnd[-1] == 'd':
        return 0xFFFFFFFF
    else:
        return 0xFFFFFFFFFFFFFFFF
    
def get_byteness(value):
    '''Gets the byte-size of the value'''
    value = abs(value)
    if 0xFFFFFFFFFFFFFFFF >= value > 0xFFFFFFFF:
        return 8
    elif 0xFFFFFFFF >= value > 0xFFFF:
        return 4
    elif 0xFFFF >= value > 0xFF:
        return 2
    else:
        return 1
    
def is_reg(opnd):
    '''Checks if the value is a register name'''
    return bool(get_reg_fam(opnd))

def is_var(var):
    '''Returns true for non-integer values'''
    #TODO: This probably needs to be fixed for floats and whatnot.
    try:
        int(var)
        return False
    except ValueError:
        return True
    
def get_current_segment(ea):
    '''Gets the segment start ea of the current segment'''
    for index in xrange(idaapi.get_segm_qty()):
        segm = idaapi.getnseg(index)
        if segm.startEA <= ea < segm.endEA:
            return segm.startEA 

def is_64_bit(ea):
    '''Returns True if the ea is in a 64 bit segment, false otherwise'''
    seg_ea = get_current_segment(ea)
    if seg_ea:
        return idc.GetSegmentAttr(seg_ea, idc.SEGATTR_BITNESS) == 2
    else:
        return False # Assume things are 32-bit if all else fails.

def get_int(val):
    '''Attempts to convert the string given into the correct integer'''
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
                      5: 4, # Actually variable, so may not be 4
                      6: 4, # Actually packed real format for mc68040, so may not be 4
                      7: 8,
                      8: 16,
                      9: 4, # Actually a pointer, so may not be 4
                      10: 4, # Actually a void, so may not be 4
                      11: 5,
                      12: 1, # Actually a bit field, so less than one.
                      13: 4, # Actually a pointer, so may not be 4
                      14: 4, # Actually a pointer, so may not be 4
                      15: 3,
                      16: 16, # Actually a long double, so may not be 16
                      17: 32,
                      18: 64}
def get_byte_size_of_operand(ea, pos):
    '''Gets the byte size of the operand at the given ea and position'''
    idaapi.decode_insn(ea)
    return OPERAND_BYTE_SIZES.get(idaapi.cmd.Operands[pos].dtyp, 4) # 4 is Unknown

def get_opnd_replacement(ea, pos):
    ''' A replacement for IDA's idc.GetOpnd that can de-alias register names'''
    # TODO: Support renames in other operand types
    if idc.GetOpType(ea, pos) == idc.o_reg:
        return idaapi.get_reg_name(idc.GetOperandValue(ea, pos), get_byte_size_of_operand(ea, pos))
    else:
        return idc.GetOpnd(ea, pos)
    
def _protected_is_displ(ea, pos):
    '''Determines if the given ea/position is a displacement. Do not call this directly
    
        :param ea: memory location
        :param pos: argument location
                    example:
                        add eax, ebx
                        eax is position 0, ebx is position 1
                        
        :return: True or False
    '''
    TOKENS = '\[|\]|\*|\+|\-|\/| '
    opnd = idc.GetOpnd(ea, pos)
    split_opnds = re.split(TOKENS, opnd)
    for potential_reg in split_opnds:
        if unsafe_get_reg_fam(potential_reg):
            return True
    return False

def is_phrase(ea, pos):
    '''Determines if the ea/position is a phrase, such as [eax + ebx*8]
        
        :param ea: memory location
        :param pos: argument location
                    example:
                        add eax, ebx
                        eax is position 0, ebx is position 1
                        
        :return: True or False
    '''
    if idc.GetOpType(ea, pos) in (idc.o_phrase, idc.o_displ):
        return not _protected_is_displ(ea, pos)
    return False


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
    '''Determines if the ea/position is a displacement, such as [esp + 8]
    
        :param ea: memory location
        :param pos: argument location
                    example:
                        add eax, ebx
                        eax is position 0, ebx is position 1
                        
        :return: True or False
    '''
    if idc.GetOpType(ea, pos) in (idc.o_phrase, idc.o_displ):
        return _protected_is_displ(ea, pos)
    return False
    
def get_operand_value_replacement(ea, pos, state):
    ''' A replacement for Ida's idc.GetOperandValue that handles displacements more reasonably
        
        :param ea: memory location
        :param pos: argument location
                    example:
                        add eax, ebx
                        eax is position 0, ebx is position 1
        :param state: the current stack pointer register family (usually sp)
                        
        :return: computes a numerical replacement for an operand
    '''
    if is_displ(ea, pos):
        idaapi.decode_insn(ea)
        offset = idaapi.cmd.Operands[pos].addr
        flipped = (offset ^ (0xffffffffffffffff if is_64_bit(ea) else 0xffffffff)) + 1
        # Use reg_fam[2] here as opposed to reg_fam[0] like usual because we need to mach the reg name string
        if any(reg_fam[2] in get_opnd_replacement(ea, pos) for reg_fam in state.stack_pointer_reg_fams):
            adjustment = idc.GetSpd(ea)
        else:
            adjustment = 0
        if not adjustment:
            adjustment = 0
        if flipped < offset:
            return -flipped + adjustment
        else:
            return offset + adjustment
    else:
        return idc.GetOperandValue(ea, pos)

def get_encoded_stack_string(stack, startoffset, size = None):
    '''
        given a stack and the starting offset, pull out the string from the stack\
        if size is given, pull that many bytes off stack
        
        :param stack: stack dictionary of your current working stack as created by the create_stack function
        :param startoffset: offset to start from on stack
        :param size: optional parameter for size to pull off stack, if not set will read until a null byte
        
        :return: string of characters from the stack dictionary starting at offset and reading until size or a null byte
    '''
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
    
def get_encoded_stack_string_wide(stack, startoffset, size = None):
    '''
        given a stack and the starting offset, pull out the string from the stack\
        if size is given, pull that many bytes off stack
        
        :param stack: stack dictionary of your current working stack as created by the create_stack function
        :param startoffset: offset to start from on stack
        :param size: optional parameter for size to pull off stack, if not set will read until two null bytes (wchar null)
        
        :return: string of characters from the stack dictionary starting at offset and reading until size or a null byte
                 this will not be wide characters
    '''
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
    '''Sets the stack dictionary, at the given offset, to contain the value at the given position at the given ea,
        performing a lookup in the register dictionary if needed. Used by create_stack
    
        :param offset: offset to set on stack
        :param ea: instruction location
        :param pos: argument position
        :param state: the current TraceState

        :return: None - updates state
    '''
    fill = False
    if idc.GetOpType(ea, pos) == idc.o_imm:
        val = idc.GetOperandValue(ea, pos)
        state.stack[offset] = (val, ea)
        fill = True
    else:
        reg = unsafe_get_reg_fam(get_opnd_replacement(ea, pos))
        if reg and reg[0] in state.regs:
            val = state.regs[reg[0]][0]
            state.stack[offset] = (state.regs[reg[0]][0], ea)
            fill = True
    if fill:
        for i in xrange(0, get_byte_size_of_operand(ea, pos)):
            state.stack[offset + i] = (val & 0xff, ea)
            val /= 256

def handle_mov(ea, state):
    '''Updates the stack based on a mov instruction. Used by create_stack
    
        :param ea: instruction location
        :param state: the current TraceState
        
        :return: None - updates stack or regs
    '''
    op1 = get_opnd_replacement(ea, POS_FIRST)
    if '[' in op1:
        offset = get_operand_value_replacement(ea, POS_FIRST, state)
        set_stack(offset, ea, POS_SECOND, state)
    else:
        reg = unsafe_get_reg_fam(op1)
        type_ = idc.GetOpType(ea, POS_SECOND)
        if reg:
            if type_ != idc.o_phrase and type_ != idc.o_displ:
                val = None
                if type_ == idc.o_reg:
                    reg2 = unsafe_get_reg_fam(get_opnd_replacement(ea, POS_SECOND))
                    if reg2 and reg2[0] in state.regs:
                        val = state.regs[reg2[0]][0]
                        if reg2 in state.stack_pointer_reg_fams:
                            state.stack_pointer_reg_fams.remove(reg2)
                    else:
                        if reg2 in state.stack_pointer_reg_fams:
                            state.stack_pointer_reg_fams.append(reg2)
                        else:
                            val = None
                elif type_ == idc.o_mem:
                    bytes = idc.GetManyBytes(idc.GetOperandValue(ea, POS_SECOND), get_byte_size_of_operand(ea, 1))
                    val = 0
                    if bytes:
                        for x in range(len(bytes)):
                            val += ord(bytes[x]) << x
                else:
                    val = idc.GetOperandValue(ea, POS_SECOND)
                if val is not None:
                    state.regs[reg[0]] = (val, ea)
            else:
                offset = get_operand_value_replacement(ea, POS_SECOND, state)
                value = state.stack.get(offset, None)
                if value is not None:
                    state.regs[reg[0]] = value
                
                    
def handle_lea(ea, state):
    '''Updates the stack based on an lea instruction. Used by create_stack
    
        :param ea: instruction location
        :param state: the current TraceState
        
        :return: None - updates stack or regs
    '''
    if idc.GetOpType(ea, POS_SECOND) == idc.o_reg:
        source_reg = unsafe_get_reg_fam(get_opnd_replacement(ea, POS_SECOND))
        if source_reg and source_reg[0] in state.regs:
            value = state.regs[source_reg[0]]
        else:
            value = None
    else:
        try:
            value = get_operand_value_replacement(ea, POS_SECOND, state)
        except:
            value = None
    
    if not value:
        return
    
    op1 = get_opnd_replacement(ea, POS_FIRST)
    if '[' in op1:
        offset = get_operand_value_replacement(ea, POS_FIRST, state)
        set_stack(offset, ea, POS_SECOND, state)
    else:
        reg = unsafe_get_reg_fam(op1)
        if reg:
            state.regs[reg[0]] = (value,ea)
    
def handle_push(ea, state):
    '''
        Loosely tracks the values that get pushed onto the stack, if the value is unknown
        when pushed. Should be called any time you see a push instruction if tracking
        
        :param ea: instruction location
        :param state: the current TraceState
    '''
    if idc.GetOpType(ea, POS_FIRST) == idc.o_reg:
        source_reg = unsafe_get_reg_fam(get_opnd_replacement(ea, POS_SECOND))
        if source_reg and source_reg[0] in state.regs:
            value = state.regs[source_reg[0]]
        else:
            value = None
        state.pp_track.append(value)
    else:
        value  = get_operand_value_replacement(ea, POS_FIRST, state)
        state.pp_track.append(value)
        
        
def handle_pop(ea, state):
    '''
        if op type is a reg, pops the tracked value if not none into the appropriate reg
        should be called anytime a pop is seen if tracking
        
        :param ea: instruction location
        :param state: the current TraceState
    '''
    try:
        value = state.pp_track.pop()
    except:
        value = None
        
    if idc.GetOpType(ea, POS_FIRST) == idc.o_reg:
        op1 = get_opnd_replacement(ea, POS_FIRST)
        reg = unsafe_get_reg_fam(op1)
        if value is not None and reg:
            state.regs[reg[0]] = (value, ea)
    
    
def create_state(endEA, startEA = None):
    '''
        Quick and dirty representation of stack and regs from start of function to this ea.
        
        :param endEA: The EA of which you want to compute the stack up until
        :param startEA: Optional param of the beginning of the function - sometimes necessary
                        if ida can't compute and you can
        
        :return A newly created TraceState
    '''
    if not startEA:
        startEA = idaapi.get_func(endEA).startEA
    state = TraceState()
    ea = startEA
    while ea < endEA:
        mnemonic = idc.GetMnem(ea)
        if 'mov' in mnemonic:
            handle_mov(ea, state)
        elif ('xor' in mnemonic and unsafe_get_reg_fam(get_opnd_replacement(ea, POS_FIRST)) ==
              unsafe_get_reg_fam(get_opnd_replacement(ea, POS_SECOND))) or \
             ('lea' in mnemonic and idc.GetOpnd(ea, POS_SECOND) == '[0]') or \
             ('sub' in mnemonic and get_opnd_replacement(ea, POS_FIRST) ==
              get_opnd_replacement(ea, POS_SECOND)):
            reg = unsafe_get_reg_fam(get_opnd_replacement(ea, POS_FIRST))
            if reg:
                state.regs[reg[0]] = (0, ea)
        elif 'lea' in mnemonic:
            handle_lea(ea, state)
        elif 'push' in mnemonic:
            handle_push(ea, state)
        elif 'pop' in mnemonic:
            handle_pop(ea, state)
        
        ea += idc.ItemSize(ea)
    return state

def trace_rep_mov(stack_var, loc, func_ea, state):
    '''
    Helper function to trace back a rep mov
    '''
    loc = idc.PrevHead(loc)
    while loc != func_ea:
        mnem = idc.GetMnem(loc)
        if mnem == 'lea' and idc.GetOpnd(loc, 0) == 'edi':
            if stack_var == get_operand_value_replacement(loc, 1, state):
                return trace_register('esi', loc, func_ea, state)
            return None
        loc = idc.PrevHead(loc)
    return None

def trace_stack_var(stack_var, loc, func_ea, state = None):
    '''
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
    '''
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
                if poss_loc in range(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA):
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


def trace_register(reg, loc, func_ea, state = None):
    '''
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
    '''
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
                if poss_loc in range(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA):
                    return poss_loc
                else:
                    return opval_1
            else:
                return idc.BADADDR
        elif mnem == 'lea' and op_type_1 == idc.o_displ and opnd == reg:
            stack_var = get_operand_value_replacement(loc, 1, state)
            return trace_stack_var(stack_var, loc, func_ea, state)
        elif idaapi.get_inf_structure().is_64bit() and mnem == 'lea' and opnd == reg:
            if op_type_1 == idc.o_mem:
                return opval_1
        loc = idc.PrevHead(loc)
    return idc.BADADDR


def trace_register_family(reg, loc, func_ea, state = None):
    '''
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
    '''
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
                    if poss_loc in range(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA):
                        return poss_loc
                    else:
                        return opval_1
                else:
                    return idc.BADADDR
            elif mnem == 'lea' and op_type_1 == idc.o_displ and opnd in reg_fam:
                stack_var = get_operand_value_replacement(loc, 1, state)
                return trace_stack_var(stack_var, loc, func_ea, state)
            elif idaapi.get_inf_structure().is_64bit() and mnem == 'lea' and opnd in reg_fam:
                if op_type_1 == idc.o_mem:
                    return opval_1
            loc = idc.PrevHead(loc)
    return idc.BADADDR


def trace_register_family_x64(reg, loc, func_ea, state = None):
    '''
    Shouldn't be any different than trace_register_family except for continuing a trace if a register is loaded into
    the target register. However, using it in trace_register_family was not behaving properly, so keeping it separate
    for now. Also unsure of what the repurcussions would be of adding that into the existing trace_register_family.

    :param reg: The referenced register which a location is loaded into
    :param loc: The starting offset for tracing back from
    :param func_ea: Starting function offset
    :param state: the current TraceState

    :return: The acquired location, or idc.BADADDR
    '''
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
                    if poss_loc in range(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA):
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
            elif idaapi.get_inf_structure().is_64bit() and mnem == 'lea' and opnd in reg_fam:
                if op_type_1 == idc.o_mem:
                    return opval_1
            loc = idc.PrevHead(loc)
    return idc.BADADDR
