"""
CPU EMULATOR BUILTIN FUNCTIONS

These functions are used to emulate the effects of known builtin functions.

Add any builtin functions that need to be handled below.  The function should be declared as such

# Using the same function for multiple instructions:
@builtin_func("memmove")
@builtin_func("memcpy")
def _memcpy(cpu_context, call_ip, func_name, func_args):
    print "IN memmove or memcpy"

# Using a single function for a builtin
@builtin_func
def memmove(cpu_context, call_ip, func_name, func_args):
    print "IN memmove"

"""


from .cpu_emulator import builtin_func



@builtin_func
def memmove(cpu_context, call_ip, func_name, func_args):
    dst, src, size = func_args
    if dst and src:
        data = cpu_context.mem_read(src, size)
        cpu_context.mem_write(dst, data)
