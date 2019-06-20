
from ..registers import Register, RegisterMap


def x86_64_registers():
    """Initializes registers for x86/x64 architecture"""
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
        Register(4, **{
            "cf": 0x1, "pf": 0x4, "af": 0x10, "zf": 0x40, "sf": 0x80,
            "tf": 0x100, "if": 0x200, "df": 0x400, "of": 0x800,
            "iopl": 0x2000, "nt": 0x4000,
            "rf": 0x10000, "vm": 0x20000, "ac": 0x40000,
            "vif": 0x80000, "vip": 0x100000, "id": 0x200000
        }),
    ]
    return RegisterMap(registers)
