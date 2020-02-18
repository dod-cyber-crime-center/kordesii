from copy import deepcopy
import logging

from ..registers import Register, RegisterMap


logger = logging.getLogger(__name__)


class x86_64_Registers(RegisterMap):
    """Initializes registers for x86/x64 architecture"""

    def __init__(self):
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
            Register(
                4,
                **{
                    "cf": 0x1,
                    "pf": 0x4,
                    "af": 0x10,
                    "zf": 0x40,
                    "sf": 0x80,
                    "tf": 0x100,
                    "if": 0x200,
                    "df": 0x400,
                    "of": 0x800,
                    "iopl": 0x2000,
                    "nt": 0x4000,
                    "rf": 0x10000,
                    "vm": 0x20000,
                    "ac": 0x40000,
                    "vif": 0x80000,
                    "vip": 0x100000,
                    "id": 0x200000,
                    "flags": 0xFFFF,
                    "eflags": 0xFFFFFFFF,
                }
            ),
        ]
        super(x86_64_Registers, self).__init__(registers)
        # Create separate collection dedicated to x87 FPU registers.
        self.__dict__["fpu"] = FPURegisters()

    def __deepcopy__(self, memo):
        copy = super(x86_64_Registers, self).__deepcopy__(memo)
        copy.__dict__["fpu"] = deepcopy(self.fpu, memo)
        return copy

    def __getattr__(self, reg_name):
        try:
            return super(x86_64_Registers, self).__getattr__(reg_name)
        except AttributeError:
            return self.fpu[reg_name]

    def __setattr__(self, reg_name, value):
        try:
            super(x86_64_Registers, self).__setattr__(reg_name, value)
        except AttributeError:
            self.fpu[reg_name] = value

    @property
    def names(self):
        # Overwriting names attribute so we can also provide fpu register names.
        return super(x86_64_Registers, self).names + self.fpu.names


class FPURegisters(RegisterMap):
    """
    Holds FPU related registers and handles stack manipulation.
    """

    _TAG_MAP = ["tag0", "tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7"]
    _ST_MAP = ["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"]

    NaN = float("nan")
    INFINITY = float("inf")
    EMPTY = None

    def __init__(self):
        registers = [
            # control word
            Register(2, ic=0x1000, rc=0xC00, pc=0x300, iem=0x80, pm=0x20, um=0x10, om=0x8, zm=0x4, dm=0x2, im=0x1),
            # status word
            # TODO: IA-32 x87 indicates differently...
            Register(
                2,
                b=0x4000,
                c3=0x2000,
                top=0x1C00,
                c2=0x400,
                c1=0x200,
                c0=0x100,
                ir=0x80,
                sf=0x40,
                p=0x20,
                u=0x10,
                o=0x8,
                z=0x4,
                d=0x2,
                i=0x1,
            ),
            # tag word
            # NOTE: This register can't actually be accessed directly by the programmer but its
            # exposure is necessary for opcodes like FSTENV.
            # Therefore, these field names where made up by me and are not representative
            # of any real register names.
            Register(2, tag7=0xC000, tag6=0x3000, tag5=0xC00, tag4=0x300, tag3=0xC0, tag2=0x30, tag1=0xC, tag0=0x3),
        ]
        super(FPURegisters, self).__init__(registers)
        self.__dict__["_stack"] = [self.EMPTY] * 8

        # Initialize tag register with all empties.
        self.tag_word = 0xFFFF  # Set all stack slots to empty
        self.pc = 0b11  # 64 bit precision
        self.iem = 1  # interrupt mask disabled
        self.pm = 1  # precision mask
        self.um = 1  # underflow mask
        self.om = 1  # overflow mask
        self.zm = 1  # zero divide mask
        self.dm = 1  # denormalized operand mask
        self.im = 1  # invalid operation mask

    def __deepcopy__(self, memo):
        copy = super(FPURegisters, self).__deepcopy__(memo)
        copy.__dict__["_stack"] = list(self._stack)
        return copy

    def __getattr__(self, reg_name):
        # Handle special names.
        if reg_name == "control_word":
            return self._registers[0]._value
        elif reg_name == "status_word":
            return self._registers[1]._value
        elif reg_name == "tag_word":
            return self._registers[2]._value

        # "st*" register field is special and refers to the top of the stack.
        # TODO: Determine the name IDA uses to refer to the other stack elements.
        reg_name = reg_name.lower()
        if not reg_name.startswith("st"):
            return super(FPURegisters, self).__getattr__(reg_name)

        if reg_name == "st":
            index = 0
        else:
            try:
                index = self._ST_MAP.index(reg_name)
            except ValueError:
                raise AttributeError("Invalid register: {}".format(reg_name))
        return self._stack[(self.top + index) % 8]

    def __setattr__(self, reg_name, value):
        # Handle special names.
        if reg_name == "control_word":
            self._registers[0].__dict__["_value"] = value
            return
        elif reg_name == "status_word":
            self._registers[1].__dict__["_value"] = value
            return
        elif reg_name == "tag_word":
            self._registers[2].__dict__["_value"] = value
            return

        # "st" register field is special and refers to the top of the stack.
        reg_name = reg_name.lower()
        if not reg_name.startswith("st"):
            super(FPURegisters, self).__setattr__(reg_name, value)
            return

        if reg_name == "st":
            index = 0
        else:
            try:
                index = self._ST_MAP.index(reg_name)
            except ValueError:
                raise AttributeError("Invalid register: {}".format(reg_name))

        stack_index = (self.top + index) % 8
        self._stack[stack_index] = value

        # Also set the tag register.
        tag_field = self._TAG_MAP[stack_index]
        if value in (self.NaN, self.INFINITY):
            self[tag_field] = 0b10  # NaN, infinity, or denormal
        elif value != 0:
            self[tag_field] = 0b00  # non-zero flag
        elif value == 0:
            self[tag_field] = 0b01  # zero flag

    @property
    def names(self):
        # Overwrite to add dynamically built register fields.
        return super(FPURegisters, self).names + ["st"] + self._ST_MAP

    # TODO: Support setting sf register if value isn't free.

    def push(self, value):
        # Decrement stack pointer and then add value.
        self.top = (self.top - 1) % 8
        self.st = value
        logger.debug(":: Pushed on FPU stack: {}".format(value))

    def pop(self):
        # Retreive top of stack, mark it as empty, then increment stack pointer.
        ret = self.st
        self[self._TAG_MAP[self.top]] = 0b11  # mark as empty
        self.st = self.EMPTY
        self.top = (self.top + 1) % 8
        logger.debug(":: Popped off FPU stack: {}".format(ret))
        return ret
