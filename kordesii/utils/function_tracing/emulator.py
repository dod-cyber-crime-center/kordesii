
import collections
import inspect
import logging
import warnings
from copy import deepcopy
from typing import Generator, Optional, Tuple, List, Iterable

import ida_funcs
import idaapi

from kordesii import utils
from kordesii.utils.function_tracing import call_hooks
from kordesii.utils.function_tracing.x86_64 import x86_64ProcessorContext
from kordesii.utils.function_tracing.ARM import ARMProcessorContext
from kordesii.utils.function_tracing.cpu_context import ProcessorContext
from kordesii.utils.function_tracing.flowchart import Flowchart

logger = logging.getLogger(__name__)


class Emulator(object):
    """
    This class is the controller for emulating and getting contexts.
    This is used for controlling the hooks used for function calls as well as store options.
    """

    def __init__(self, max_instructions=10000, branch_tracking=True):
        """
        Initialize an Emulator instance

        :param max_instructions:
            Maximum number of instructions to allow when emulating loop following code.
            This is used since it is possible that the end instruction would never get reached.
        :param branch_tracking:
            When forcing emulation to go down the incorrect branch in order to reach the desired
            end address, branch_tracking is used to try to tweak the registers to make the branching
            condition true.
            This can be helpful to ensure the rest of the emulation is done correctly, however
            this will cause emulation to run slower.
            So this option allows you to turn it off when the feature is not necessary.
        """
        # Determine the appropriate class to use for generated contexts based on arch name.
        self.arch = idaapi.get_inf_structure().procname
        if self.arch == "metapc":
            self._context_class = x86_64ProcessorContext
        elif self.arch == "ARM":
            self._context_class = ARMProcessorContext
        else:
            raise NotImplementedError(f"Architecture not supported: {self.arch}")

        self._call_hooks = call_hooks.BUILTINS.copy()
        self._instruction_hooks = collections.defaultdict(list)
        self._opcode_hooks = self._context_class.OPCODES.copy()
        self.max_instructions = max_instructions
        self.branch_tracking = branch_tracking
        self.disabled_rep = False

    def disable(self, name: str):
        """
        Disables the use of a specific opcode or function hook.
        This is useful when trying to optimize processing time.

        WARNING: Once disabled, there is no way to re-enable it without
            creating a brand-new Emulator instance.

        WARNING: Disabling some opcodes like "call", "push", or "pop" may cause the stack pointer
            to be miss-aligned for future instructions. Do this at your own risk.

        :param name: Name of opcode or function hook.
            NOTE: All the "rep*" opcodes will be disabled if the name is "rep".
        """
        name = name.lower()

        if name in self._opcode_hooks:
            del self._opcode_hooks[name]
        elif name in self._call_hooks:
            del self._call_hooks[name]
        elif name.startswith("rep"):
            self.disabled_rep = True

    def new_context(self) -> ProcessorContext:
        return self._context_class(self)

    def hook_call(self, name_or_start_ea, func):
        """
        Hooks all calls to a function with a custom user defined function.
        Useful for emulating the effects of a function or reporting data.

        :param name_or_start_ea: Name or starting address of the function to hook (e.g. 'base64')
        :param func: Function to run while emulating a call to that function.
            Function must accept 3 arguments: cpu_context, func_name, and func_args and
            may return a value to be set to the rax register (or equivalent)
        :return:
        """
        if isinstance(name_or_start_ea, str):
            name_or_start_ea = name_or_start_ea.lower()
        self._call_hooks[name_or_start_ea] = func

    def hook_instruction(self, opcode_or_ea, func, pre=True):
        """
        Hooks all instructions of a given opcode or at specific address with a custom
        user defined function.

        :param opcode_or_ea: name of the opcode or address of the instruction to hook (e.g. "pop")
        :param func: Function to run while before or after emulating the instruction.
            Function must accept 2 arguments: cpu_context, instruction
        :param pre: Whether to run the function before or after the instruction has been emulated.
            (defaults to before)
        """
        # Convert callbacks using the older signature to the newer.
        sig = inspect.signature(func)
        num_parameters = len(sig.parameters)
        if num_parameters == 4:
            warnings.warn(
                "Instruction callbacks using 4 parameters is deprecated. "
                "Please update your callback to use 2 parameters: cpu_context and instruction",
                DeprecationWarning
            )
            orig_func = func
            func = lambda ctx, insn: orig_func(ctx, insn.ip, insn.mnem, insn.operands)
        elif num_parameters != 2:
            raise TypeError(f"Instruction hook should only accept 2 parameters. Got {num_parameters}")

        if isinstance(opcode_or_ea, str):
            opcode_or_ea = opcode_or_ea.lower()
        self._instruction_hooks[(opcode_or_ea, pre)].append(func)

    def hook_opcode(self, opcode, func):
        """
        Sets the callback function which implements the emulation for the given opcode.

        WARNING: Only one hook can be implemented for each opcode. If you set a hook, this will
        replace any existing implementation for the life of this Emulator instance.
        You probably want to be using `hook_instruction()` instead.

        NOTE: If you are hooking an opcode to overwrite a buggy implementation, please
        consider contributing a bugfix. :)

        :param opcode: name of the opcode to implement. (e.g. "pop")
        :param func: Function to run to emulate the opcode.
            Function must accept 2 arguments: cpu_context, instruction
        """
        self._opcode_hooks[opcode.lower()] = func

    def emulate_call(self, name_or_start_ea):
        """
        Defines whether a call to a specific function should be emulated using a combination
        of create_emulated() and hook_call()

        :param name_or_start_ea: Name or starting address of the function to emulate all calls to
        """

        if isinstance(name_or_start_ea, str):
            ea = utils.get_function_addr(name_or_start_ea)
        else:
            ea = name_or_start_ea

        # TODO: This method causes us to do unnecessarily extraction of function arguments
        #   since the emulated function will just put them right back in.
        #   Update the CALL opcode to just call context.execute() directly.
        func = self.create_emulated(ea)
        def hook(context, func_name, func_args):
            func(*func_args, context=context)

        self.hook_call(name_or_start_ea, hook)

    def clear_hooks(self):
        """Clears all currently set hooks (including builtin ones)."""
        self.reset_hooks()
        self._call_hooks = {}

    def reset_hooks(self):
        """Resets hooks back to the default builtin ones."""
        self._call_hooks = call_hooks.BUILTINS.copy()
        self._instruction_hooks = collections.defaultdict(list)
        self._opcode_hooks = self._context_class.OPCODES.copy()

    def get_call_hook(self, func_name_or_start_ea):
        """
        Gets function call hook for given function name or start address.

        :param func_name_or_start_ea: Name or start address of the function to get hook for.

        :return: A function to run or None if there is no hook for the given function.
        :rtype: function
        """
        # Convert the string to lowercase so it can match the dictionary of built-in functions
        if isinstance(func_name_or_start_ea, str):
            func_name_or_start_ea = func_name_or_start_ea.lower()

        return self._call_hooks.get(func_name_or_start_ea)

    def get_instruction_hooks(self, opcode_or_ea, pre=True):
        """
        Gets instruction hook for given opcode mnemonic or address.

        :param opcode_or_ea: Opcode mnemonic or address of the instruction
        :param pre: Whether to run the function before or after the instruction has been emulated.
            (defaults to before)

        :return: A list of hook functions.
        """
        if isinstance(opcode_or_ea, str):
            opcode_or_ea = opcode_or_ea.lower()

        return self._instruction_hooks.get((opcode_or_ea, pre), [])

    def get_opcode_hook(self, opcode) -> Optional[callable]:
        """
        Gets the opcode implementation for the given opcode mneomic.
        :param opcode: Name of the opcode to get opcode from.
        :return: The function callback or None if there is no hook.
        """
        return self._opcode_hooks.get(opcode.lower())

    def execute(self, start: int, end: int = None, *, context: ProcessorContext = None) -> ProcessorContext:
        """
        Emulates from start instruction to end instruction (not including the end instruction)
        (Or just emulates the start instruction if end is not provided.)

        Emulation will stop when either the end instruction is reached or the max number of instructions
        have been emulated. Whichever comes first.

        Loops will be emulated as expected. If you would like to force emulation down the path to the
        end instruction, use iter_context_at() or context_at() instead.

        :param start: Address of instruction to start emulation.
        :param end: Address of instruction to stop emulation. (non-inclusive)
        :param context: A premade context that you would like to use to start out emulation.
            In which case, this is just a wrapper for running execute() on the context itself.

        :returns: A ProcessorContext object after emulation has occurred.
            If a context was provided in the parameters, this context will be a reference to that.
        """
        if not context:
            context = self.new_context()

        context.execute(start=start, end=end, max_instructions=self.max_instructions)
        return context

    def _execute_to(self, ea, *, context: ProcessorContext = None) -> ProcessorContext:
        """
        Creates a cpu_context (or emulates on top of the given one) for instructions up to, but not
        including, the given ea within the current function.
        This function is a hybrid approach to the non-loop following mode in which it will
        force the other branch to be taken if the branch it wants to take will not lead to the
        desired end address.

        This is an internal function used as a helper for iter_context_at() when following loops.

        :param int ea: ea of interest
        :param context: ProcessorContext to use during emulation, a new one will be created if not provided.

        :raises RuntimeError: If maximum number of instructions have been hit.
        """
        if not context:
            context = self.new_context()

        flowchart = Flowchart.from_cache(ea)
        func_obj = utils.Function(ea)

        start_block = flowchart.find_block(func_obj.start_ea)
        end_block = flowchart.find_block(ea)
        valid_blocks = end_block.ancestors()
        valid_blocks.add(end_block)
        count = self.max_instructions

        # Starting from start_block, we are going to emulate each instruction in each basic block
        # until we get to the end_block.
        # If execution tries to branch us into a block that can't lead us to the end_block,
        # we will force the branch to go in the other direction.
        current_block = start_block
        while current_block != end_block:
            # We can't use execute() with start and end here because the end_ea of a block
            # is not actually in the block.
            for _ea in current_block.heads():
                context.execute(_ea)
                count -= 1

            if count <= 0:
                raise RuntimeError("Hit maximum number of instructions.")

            # Get the successor block that execution branched to as well as
            # is a valid block that can reach the end block.
            # If no such block exists, just pick the first valid successor block.
            valid_successors = [bb for bb in current_block.succs() if bb in valid_blocks]
            assert valid_successors, "Expected there to be at least 1 valid successor block."
            for successor in valid_successors:
                if context.ip == successor.start_ea:
                    break
            else:
                # If no valid successor, force branch.
                successor = valid_successors[0]
                context.ip = successor.start_ea
                context.prep_for_branch(successor.start_ea)

            current_block = successor

        # Emulate the instructions in the final block.
        context.execute(start=current_block.start_ea, end=ea)

        return context

    def iter_context_at(
            self, ea, *, depth=0, exhaustive=True, follow_loops=False, init_context=None, _first_call=True
    ) -> Iterable[ProcessorContext]:
        """
        Iterate over cpu context for instructions up to, but not including, a given ea.
        (within the current function)

        >>> emu = Emulator()
        >>> for cpu_context in emu.iter_context_at(0x1001b9ad):
        >>>     print(cpu_context)

        :param int ea: ea of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning emulation will start at the start of the function containing the given address)
        :param bool exhaustive:
            If true, all paths for each call level depth is processed.
            If follow_loops is also true, this will ensure loops are followed at each call level depth.
            If false, only the first path for each depth is processed.
            If follow_loops is also true, loops will only be followed for the first call level.
                All other levels will use the non-follow_loops method.
        :param follow_loops:
            If true, loops will be followed during emulation and only one possible
            path will be emulated per call level.
            If false, emulation will be forced down a specific path of flowchart blocks in order
            to get to the given ea address.
        :param init_context: Initial context to use to start emulation.
            NOTE: The yielded context will be a copy of the passed in context with emulation applied.
        :param _first_call: Detects if we are the first call in a recursive call. Please don't change this.

        :yield: cpu_context
        """
        if depth < 0:
            raise ValueError("Depth must be a positive integer.")

        if init_context and init_context.emulator != self:
            raise ValueError("Emulator of supplied init_context must be the same.")

        if not init_context:
            init_context = self.new_context()
        else:
            # Create a copy of the context in order to follow the path of least surprises.
            init_context = deepcopy(init_context)

        logger.debug(
            f"Emulating call level %d for function at 0x%08X: follow_loops = %r, exhaustive = %r",
            depth, ea, follow_loops, exhaustive
        )

        # Create a generator for getting the initial contexts at this level.
        # Normally, creating functions inside functions like this is not advisable.
        # However, this proved to be the least complex solution in this situation.
        def init_contexts():
            logger.debug("Iterating contexts for call level: %d", depth)

            if not depth:
                yield init_context
                return

            func = utils.Function(ea)
            yielded = False
            for call_ea in func.calls_to:
                if call_ea in func:
                    logger.warning("Ignoring recursive function call at 0x%08X", call_ea)
                    continue
                if not ida_funcs.get_func(call_ea):
                    logger.warning("Ignoring call at 0x%08X. Not in a function", call_ea)
                    continue
                for context in self.iter_context_at(
                    call_ea,
                    depth=depth - 1,
                    exhaustive=exhaustive,
                    follow_loops=follow_loops,
                    init_context=init_context,
                    _first_call=False
                ):
                    if issubclass(self._context_class, x86_64ProcessorContext):
                        # increase the sp to account for the return address that gets pushed
                        # onto the stack so that we are aligned correctly.
                        context.sp -= context.byteness

                    # yield a context containing the caller executed first.
                    yield context
                    yielded = True
            # If we didn't yield, then we hit a function that has no callers or valid contexts.
            if not yielded:
                yield init_context

        # Iterate contexts at this level.

        if follow_loops and (_first_call or exhaustive):
            for context in init_contexts():
                yield self._execute_to(ea, context=deepcopy(context))

        else:
            for context in init_contexts():
                flowchart = Flowchart.from_cache(ea)
                for path_node in flowchart.get_paths(ea):
                    yield path_node.cpu_context(ea, init_context=deepcopy(context))

                    # Don't process other paths if we are at the user call level and exhaustive wasn't choosen.
                    if not _first_call and not exhaustive:
                        break

    def context_at(self, ea, *, depth=0, exhaustive=True, follow_loops=False, init_context=None) -> Optional[ProcessorContext]:
        """
        Obtain a cpu context for instructions up to, but not including, a given ea.

        :param int ea: ea of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generated at the top of the current function.)
        :param bool exhaustive:
            If true, all paths for each call level depth is processed.
            If follow_loops is also true, this will ensure loops are followed at each call level depth.
            If false, only the first path for each depth is processed.
            If follow_loops is also true, loops will only be followed for the first call level.
                All other levels will use the non-follow_loops method.
        :param bool follow_loops:
            If true, loops will be followed during emulation and only one possible
            path will be emulated per call level.
            If false, emulation will be forced down a specific path of flowchart blocks in order
            to get to the given ea address.
        :param init_context: Initial context to use to start emulation.

        :return: cpu_context or None
        """
        for ctx in self.iter_context_at(ea, depth=depth, exhaustive=exhaustive, follow_loops=follow_loops, init_context=init_context):
            return ctx

    def iter_operand_value(self, ea, index, *, depth=0, exhaustive=True, follow_loops=False, init_context=None):
        """
        Trace the function to the specified ea and yield all possible values for the operand.
        This is a helper wrapper for extracting the context and then retrieving either
        the memory address or raw value from the operand.

        NOTE: We are using "get_operand_value" to help show this is the equivalent to
        idc.get_operand_value() but pulls from emulated data.


        >>> emu = Emulator()
        >>> for ctx, val in emu.iter_operand_value(0x1001b9ad, 0):
        >>>     print("Val for opnd0 at 0x1001b9ad = 0x{:x}".format(val))

        :param int ea: address to trace to
        :param int index: the operand of interest (0 - first operand, 1 - second operand, ...)
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)
        :param bool exhaustive: If true, all paths for each depth is processed
            if false, only the first path for each depth is processed.
            (defaults to exhaustive)
        :param init_context: Initial context to use to start emulation.

        :yield tuple: (context at ea, operand value)
        """
        values = set()

        # Iterate all the nodes to obtain the CPU context
        for cpu_context in self.iter_context_at(
                ea, depth=depth, exhaustive=exhaustive, follow_loops=follow_loops, init_context=init_context):
            operand = cpu_context.operands[index]
            # Pass memory address if there is one, otherwise pass the value.
            value = operand.addr or operand.value
            # Prevent returning multiple values which are the same....
            if value in values:
                continue

            values.add(value)
            yield cpu_context, value

    def get_operand_value(self, ea, index, *, depth=0, follow_loops=False, init_context=None) -> Optional[Tuple[ProcessorContext, int]]:
        """
        Trace the function to the specified ea and return the value for the specified operand.
        This is a helper wrapper for extracting the context and then retrieving either
        the memory address or raw value from the operand.

        NOTE: We are using "get_operand_value" to help show this is the equivalent to
        idc.get_operand_value() but pulls from emulated data.

        >>> val = Emulator().get_operand_value(0x1001b9ad, 0)
        >>> print("Val for opnd0 at 0x1001b9ad = 0x{:x}".format(val))

        :param int ea: address to trace to
        :param int opnd: the operand of interest (0 - first operand, 1 - second operand, ...)
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)

        :returns tuple: (context at ea, operand value)
        """
        for cpu_context, value in self.iter_operand_value(ea, index, depth=depth, follow_loops=follow_loops, init_context=init_context):
            return cpu_context, value

    def iter_function_args(self, ea, *, depth=0, exhaustive=True, num_args=None, follow_loops=False, init_context=None):
        """
        Given the EA of a function call, attempt to determine the number of arguments passed to the function and
        return those values to the caller.  Additionally, give back the context as well since it may be useful.

        >>> emu = Emulator()
        >>> call_addr = 0x1001b9d0
        >>> for context, args in emu.iter_function_args(call_addr):
        >>>     print("Args for call at 0x{:X}: {}".format(call_addr, ", ".join(args)))

        :param int ea: address containing the function call of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)
        :param bool exhaustive: If true, all paths for each depth is processed
            if false, only the first path for each depth is processed.
            (defaults to exhaustive)
        :param int num_args: Force a specific number of arguments.
            If not provided, number of arguments is determined by the disassembler.
            Extra arguments not defined by the disassembler are assumed to be 'int' type.

        :yield tuple: (context at ea, list of function parameters passed to called function in order)
        """
        # Iterate all the paths leading up to ea
        for cpu_context in self.iter_context_at(
                ea, depth=depth, exhaustive=exhaustive, follow_loops=follow_loops, init_context=init_context):
            yield cpu_context, cpu_context.get_function_args(num_args=num_args)

    def get_function_args(self, ea, *, depth=0, num_args=None, follow_loops=False, init_context=None) -> Optional[Tuple[ProcessorContext, List[int]]]:
        """
        Simply calls iter_function_args with the provided ea and returns the first set of arguments.

        >>> emu = Emulator()
        >>> call_addr = 0x1001b9d0
        >>> context, args = emu.get_function_args(call_addr):
        >>> print("Args for call at 0x{:X}: {}".format(call_addr, ", ".join(args)))

        :param int ea: address containing the function call of interest
        :param int depth: Number of calls up the stack to pull context from.
            (defaults to 0, meaning a empty context will be generate at the top of the current function.)
        :param int num_args: Force a specific number of arguments.
            If not provided, number of arguments is determined by the disassembler.
            Extra arguments not defined by the disassembler are assumed to be 'int' type.

        :return tuple: (context at ea, list of function parameters passed to called function in order)
        :rtype: Tuple[ProcessorContext, List]
        """
        for cpu_context, args in self.iter_function_args(ea, depth=depth, num_args=num_args, follow_loops=follow_loops, init_context=init_context):
            return cpu_context, args

    def create_emulated(self, func_ea, return_type=None, return_size=None, enforce_args=False):
        """
        Creates a Python function that emulates the execution of the given function.

        :param func_ea: Address of function to emulate.
        :param return_type: If set, return value will be dereferenced using set type before returning.
            (e.g. function_tracing.DWORD)
        :param return_size: If set, return value will be dereferenced as a bytes string of the given
            size before returning.
        :param enforce_args: Whether to enforce that the correct number of positional arguments
            was provided.

        :returns: A python function that emulates the function.
            This function will accept the same number (and type) of arguments as the
            emulate function as well as return the result as the emulated function.

        :raises RuntimeError: If the maximum number of allowed instruction executions have been reached.
        """
        func_obj = utils.Function(func_ea)

        def emulated_function(*args, context: ProcessorContext = None):
            """
            Emulates a function and returns result in rax.

            :param *args: Arguments to pass into function before emulation.
                If enforce_args is not enabled, the number of arguments provided can be less or more
                than the number of arguments required by the function.
                Any arguments not provided will default to whatever is set in the context.
            :param context: CPU context to use. If not provided an empty context will be used.
                If you would like to examine the context after emulation, you must provide your own.

            :returns: Value or derefernced value in rax.

            :raises TypeError: If enforce_args is enabled and incorrect number of positional args have been provided.
            """
            if context and context.emulator != self:
                raise ValueError("Supplied context must be created from same emulator.")
            context = context or self.new_context()
            # (ip must be set in order to get correct function arguments in signature.)
            context.ip = func_obj.start_ea

            # Temporarily turn off branch tracking since it is unneeded and will just waste time.
            orig_branch_tracking = self.branch_tracking
            self.branch_tracking = False

            # Fill in context with argument values.
            func_sig = context.get_function_signature(func_obj.start_ea)
            if enforce_args and len(func_sig.args) != len(args):
                raise TypeError(
                    f"Function takes {len(func_sig.args)} positional arguments, but {len(args)} were given.")

            logger.debug(f'Emulating {func_sig.name}')
            for arg, func_arg in zip(args, func_sig.args):
                if isinstance(arg, int):
                    logger.debug(f'Setting argument {func_arg.name} = {repr(arg)}')
                    func_arg.value = arg
                elif isinstance(arg, bytes):
                    ptr = context.mem_alloc(len(arg))
                    context.mem_write(ptr, arg)
                    logger.debug(f'Setting argument {func_arg.name} = {hex(ptr)} ({repr(arg)})')
                    func_arg.value = ptr
                else:
                    raise TypeError(f'Invalid arg type {type(arg)}')

            context.execute(func_obj.start_ea, end=func_obj.end_ea, max_instructions=self.max_instructions)

            if return_type is not None or return_size is not None:
                result = context.read_data(context.ret, size=return_size, data_type=return_type)
            else:
                result = context.ret

            logger.debug(f'Returned: {repr(result)}')
            self.branch_tracking = orig_branch_tracking
            return result

        return emulated_function

