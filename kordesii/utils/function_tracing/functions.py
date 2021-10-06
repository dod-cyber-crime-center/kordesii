"""
Interface for function management.
"""

import logging
import re

import ida_funcs
import ida_frame
import ida_idp
import ida_nalt
import ida_typeinf
import idc

from . import utils
from .operands import Operand

logger = logging.getLogger(__name__)


class FunctionSignature(object):
    """
    Interface for a function signature.

    NOTE: This object retrieves the signature on initialization.
    Any external changes to the function's signature after this object is created will take
    no affect.
    As well, any changes done to this object will not affect the signature in the IDB unless
    the apply() function is called.
    """

    def __init__(self, cpu_context, start_ea, operand: Operand = None):
        """
        :param cpu_context: ProcessorContext to use for pulling argument values.
        :param start_ea: Starting address of function to create function signature from.
        :param operand: Optional Operand object containing the address of the function in it's value.
            This is used for dynamically resolved functions. (e.g. call eax)

        :raises RuntimeError: If a function type could not be created from given ea.
        """
        self._cpu_context = cpu_context
        self.start_ea = start_ea
        # TODO: Possibly move the get_function_data work into this class?
        self._func_type_data, self._tif = utils.get_function_data(self.start_ea, operand=operand)

    def __repr__(self):
        return f'< FunctionSignature : {self.declaration} >'

    @property
    def name(self):
        """The demangled name of function."""
        # TODO: Move the get_function_name() into this class?
        return utils.get_function_name(self.start_ea)

    @property
    def declaration(self):
        """The full function declaration."""
        # There is no way to get the full function declaration directly from IDA with
        # the function name intact. So we have to recreate it.

        # If function doesn't have a name (usually because the function was dynamically created
        # within a register), then we are just going to call it "no_name" so we can still get the
        # function typing to still work.
        return re.sub('\(', f' {self.name or "no_name"}(', f'{str(self._tif)};')

    @declaration.setter
    def declaration(self, decl):
        """
        Changes the declaration of the function internally.
        """
        # Ensure ends with ';'
        if not decl.endswith(";"):
            decl += ";"

        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        func_type_data = ida_typeinf.func_type_data_t()
        ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
        tif.get_func_details(func_type_data)
        self._tif = tif
        self._func_type_data = func_type_data

    def apply(self):
        """Applies the currently set signature to the IDB."""
        idc.apply_type(self.start_ea, self.declaration)

    @property
    def arg_types(self):
        """Tuple of the argument types."""
        return tuple(arg.declaration for arg in self.args)

    @arg_types.setter
    def arg_types(self, arg_types):
        """Set tuple of argument types."""
        self.declaration = re.sub("\(.*\)", "({})".format(",".join(arg_types)), self.declaration)

    @property
    def args(self):
        return [FunctionArg(self._cpu_context, i, funcarg_obj, self)
                for i, funcarg_obj in enumerate(self._func_type_data)]


class FunctionArg(object):
    """
    Interface for a function argument from FunctionSignature
    """

    # TODO: Figure out how to do this without using funcarg_t object.
    def __init__(self, cpu_context, idx, funcarg_obj, func_sig):
        self._cpu_context = cpu_context
        self._funcarg_obj = funcarg_obj
        self._func_sig = func_sig
        self.idx = idx

    def __repr__(self):
        string = f'< FunctionArg {hex(self._func_sig.start_ea)}:{self.idx} ' \
                 f': {self.declaration} = {hex(self.value)}'
        if self.addr is not None:
            string += f' : &{self.name} = {hex(self.addr)}'
        string += ' >'
        return string

    @property
    def width(self):
        return self._funcarg_obj.type.get_size()

    @property
    def name(self):
        return self._funcarg_obj.name

    @name.setter
    def name(self, value):
        self._funcarg_obj.name = value

    @property
    def type(self):
        """User friendly type name."""
        return str(self._funcarg_obj.type)

    @type.setter
    def type(self, value):
        """
        Sets FunctionArg to a new type.

        NOTE: Setting the type here has no affect on the FunctionSignature object this came from.
        """
        is_ptr = value.endswith("*")
        value = value.strip(" *")

        # Create new tinfo object of type.
        tif = ida_typeinf.tinfo_t()
        tif.get_named_type(ida_typeinf.get_idati(), value)

        # If a pointer, create another tinfo object that is the pointer of the first.
        if is_ptr:
            tif2 = ida_typeinf.tinfo_t()
            tif2.create_ptr(tif)
            tif = tif2

        self._funcarg_obj.type = tif

    @property
    def declaration(self):
        """Argument type declaration."""
        return f'{self.type} {self.name}'

    @property
    def is_stack(self):
        """True if argument is on the stack."""
        return self._funcarg_obj.argloc.atype() == ida_typeinf.ALOC_STACK

    # TODO: Refactor to be more processor agnostic
    @property
    def addr(self):
        """Retrieves the address of the argument (if a memory/stack address)"""
        argloc = self._funcarg_obj.argloc
        loc_type = argloc.atype()

        if loc_type == ida_typeinf.ALOC_STACK:
            func = ida_funcs.get_func(self._func_sig.start_ea)

            if utils.is_x86_64():
                retaddr_size = self._cpu_context.byteness
            else:
                retaddr_size = 0

            # If we are in the function, we need to account for changes made to the stack.
            if self._cpu_context.ip == self._func_sig.start_ea \
                    or (func and func.contains(self._cpu_context.ip)):
                # Determine adjustment of stack based on what IDA reports as the current
                # ESP plus the size of the saved return address.
                # (More reliable and cross compatible than using ebp.)
                # TODO: This might be a x86 only thing. Need to make ARM version.
                if func:
                    sp_adjust = ida_frame.get_spd(func, self._cpu_context.ip)  # this is negative
                else:
                    sp_adjust = 0
                return self._cpu_context.sp - sp_adjust + retaddr_size + argloc.stkoff()

            # If we are in the caller, but in the middle of hooking the call instruction we need
            # to account for the pushed in return address.
            elif self._cpu_context.hooking_call == self._func_sig.start_ea:
                return self._cpu_context.sp + retaddr_size + argloc.stkoff()

            # Otherwise, we are in the caller and should base the address off the current stack.
            else:
                return self._cpu_context.sp + argloc.stkoff()

        elif loc_type == ida_typeinf.ALOC_RREL:
            return argloc.get_ea()

        return None

    @property
    def value(self):
        """Retrieves the value of the argument based on the cpu context."""
        # TODO: Pull value data based on type.

        argloc = self._funcarg_obj.argloc
        loc_type = argloc.atype()

        # This type occurs when we have created an uninitialized argument.
        if loc_type == ida_typeinf.ALOC_NONE:
            logger.warning("Argument {} location is of type ALOC_NONE".format(self.idx))
            return None

        elif loc_type == ida_typeinf.ALOC_STACK:
            # Get function
            logger.debug(f'Retrieving argument {self.idx} at {hex(self.addr)}, stack: {hex(self._cpu_context.sp)}, offset: {hex(argloc.stkoff())}')
            # read the argument from the stack using the calculated stack offset from the disassembler
            value = self._cpu_context.memory.read(self.addr, self._cpu_context.byteness)
            return utils.struct_unpack(value)

        elif loc_type == ida_typeinf.ALOC_DIST:  # arguments described by multiple locations
            # TODO: Uses the scattered_aloc_t class, which is a qvector or argpart_t objects
            # argloc.scattered()
            raise NotImplementedError("Argument {} location of type ALOC_DIST".format(self.idx))

        elif loc_type == ida_typeinf.ALOC_REG1:  #  single register
            # TODO: Determine better way to convert reg1 integer to name.
            reg_name = ida_idp.get_reg_name(argloc.reg1(), self.width)
            return self._cpu_context.registers[reg_name]

        elif loc_type == ida_typeinf.ALOC_REG2:  # register pair (eg: edx:eax [reg2:reg1])
            # Width is the combination of both registers.
            reg_width = self.width // 2
            reg1_name = ida_idp.get_reg_name(argloc.reg1(), reg_width)
            reg2_name = ida_idp.get_reg_name(argloc.reg2(), reg_width)
            logger.debug("Register pair: [%s:%s]", reg1_name, reg2_name)
            reg1_value = self._cpu_context.registers[reg1_name]
            reg2_value = self._cpu_context.registers[reg2_name]
            return (reg2_value << (reg_width * 8)) | reg1_value

        elif loc_type == ida_typeinf.ALOC_RREL:  # register relative (displacement from address pointed by register
            # TODO: CURRENTLY UNTESTED
            logger.info(
                "Argument {} of untested type ALOC_RREL.  " "Verify results and report issues.".format(self.idx)
            )
            # Obtain the register-relative argument location
            rrel = argloc.get_rrel()
            reg_name = ida_idp.get_reg_name(rrel.reg, self.width)
            value = self._cpu_context.registers[reg_name]
            return value + rrel.offset

        elif loc_type == ida_typeinf.ALOC_STATIC:  # global address
            # TODO: CURRENTLY UNTESTED
            logger.info(
                "Argument {} of untested type ALOC_STATIC.  " "Verify results and report issues.".format(self.idx)
            )
            return argloc.get_ea()

        elif loc_type >= ida_typeinf.ALOC_CUSTOM:  #  custom argloc
            # TODO: Will need to figure out the functionality and usage for the custloc_desc_t structure
            # argloc.get_custom()
            raise NotImplementedError("Argument {} location of type ALOC_CUSTOM".format(self.idx))

    @value.setter
    def value(self, value):
        """Sets the value of the argument to the cpu context."""
        # TODO: Pull value data based on type.

        argloc = self._funcarg_obj.argloc
        loc_type = argloc.atype()

        # This type occurs when we have created an uninitialized argument.
        if loc_type == ida_typeinf.ALOC_NONE:
            logger.warning('Argument {} location is of type ALOC_NONE'.format(self.idx))

        elif loc_type == ida_typeinf.ALOC_STACK:
            # read the argument from the stack using the calculated stack offset from the disassembler
            logger.debug(f'Setting argument {self.idx} at {hex(self.addr)}, stack: {hex(self._cpu_context.sp)}, offset: {hex(argloc.stkoff())}')
            self._cpu_context.memory.write(
                self.addr, utils.struct_pack(value, width=self._cpu_context.byteness))

        elif loc_type == ida_typeinf.ALOC_DIST:  # arguments described by multiple locations
            # TODO: Uses the scattered_aloc_t class, which is a qvector or argpart_t objects
            # argloc.scattered()
            raise NotImplementedError("Argument {} location of type ALOC_DIST".format(self.idx))

        elif loc_type == ida_typeinf.ALOC_REG1:  #  single register
            reg_name = ida_idp.get_reg_name(argloc.reg1(), self.width)
            self._cpu_context.registers[reg_name] = value

        elif loc_type == ida_typeinf.ALOC_REG2:  # register pair (eg: edx:eax [reg2:reg1])
            reg_width = self.width // 2
            reg1_name = ida_idp.get_reg_name(argloc.reg1(), reg_width)
            reg2_name = ida_idp.get_reg_name(argloc.reg2(), reg_width)
            self._cpu_context.registers[reg1_name] = value & utils.get_mask(reg_width)
            self._cpu_context.registers[reg2_name] = value >> (reg_width * 8)

        elif loc_type == ida_typeinf.ALOC_RREL:  # register relative (displacement from address pointed by register
            # TODO: CURRENTLY UNTESTED
            logger.info(
                "Argument {} of untested type ALOC_RREL.  " "Verify results and report issues.".format(self.idx)
            )
            # Obtain the register-relative argument location
            rrel = argloc.get_rrel()
            reg_name = ida_idp.get_reg_name(rrel.reg, self.width)
            self._cpu_context.registers[reg_name] = value - rrel.offset

        elif loc_type == ida_typeinf.ALOC_STATIC:  # global address
            # TODO: CURRENTLY UNTESTED
            logger.info(
                "Argument {} of untested type ALOC_STATIC.  "
                "Verify results and report issues.".format(self.idx))
            # return argloc.get_ea()
            raise NotImplementedError(f"Argument {self.idx} location of type ALOC_STATIC")

        elif loc_type >= ida_typeinf.ALOC_CUSTOM:  #  custom argloc
            # TODO: Will need to figure out the functionality and usage for the custloc_desc_t structure
            # argloc.get_custom()
            raise NotImplementedError(f"Argument {self.idx} location of type ALOC_CUSTOM")

