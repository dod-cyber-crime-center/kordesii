
import idc
import idaapi
import itertools
from kordesii.kordesiiidahelper import append_debug


def _un_nop(ea, HeadGetter):
    '''
    Description:
        Steps until it hits something not a nop or not starts with 90 (nop opcode).

    Input:
        ea - The location to adjust for nops. EA must be a head.
        HeadGetter - either PrevHead or NextHead

    Output:
        The corrected EA.
    '''
    while idc.GetMnem(ea) == 'nop' or (idaapi.isData(idc.GetFlags(ea)) and idc.Byte(ea) == 0x90):
        ea = HeadGetter(ea)
    return ea

def ida_make_function(location):
    '''
    Description:
        From the first non-function byte, attempt to make a function.

    Input:
        location - The EA at which IDA should attempt to make a function.

    Output:
        True if it succeeded, False otherwise.
    '''
    function_start = location
    ea = location
    while not (idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea))):
        function_start = ea
        ea = idc.PrevHead(ea)
    function_start = _un_nop(function_start, idc.NextHead)

    if idc.MakeFunction(function_start):
        last_mnem = idc.GetMnem(idc.ItemHead(idaapi.get_func(function_start).endEA - 1))
        if 'ret' not in last_mnem and 'jmp' not in last_mnem:
            idc.DelFunction(function_start)
            append_debug('Created a function at 0x%X, but there wasn\'t a jmp or ret at the end.' % function_start)
            return False
        else:
            append_debug('Created a function 0x%X.' % function_start)
            return True
    else:
        return False

def _find_function_start(location):
    '''
    Description:
        If the location is the first applicable byte, assume that's the start byte.

        Else, search up until we find the first (lowest EA) "push ebp" before either aligns or a function.
        If that fails, look for "push esp", then "push esi", and finally "push edi".

    Input:
        The EA from which to start looking for a function start

    Output:
        A list of applicable EAs (one per type) or idc.BADADDR if none are found.
    '''
    if idaapi.get_func(location - 1) or idc.isAlign(idc.GetFlags(location - 1)):
        return [location]

    eas = []
    for opcode in ['55', '54', '56', '57']:
        ea = location
        function_start = idc.BADADDR
        while ea != idc.BADADDR:
            ea = idc.FindBinary(ea - 1, idc.SEARCH_UP, opcode)
            if not (idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea))):
                function_start = ea
            else:
                break
        if function_start != idc.BADADDR:
            eas.append(_un_nop(function_start, idc.NextHead))

    eas.sort()
    return eas

def _find_function_end(location):
    '''
    Description:
        If the location is the last applicable byte, assume that's the end byte.

        Else, search down until we find the last (highest EA) "retn" before either aligns or a function.
        If that fails, look for the last (higheste EA) "jmp" instruction.

    Input:
        location - The EA from which to start looking for a function end.

    Output:
        A list of applicable EAs (one per type) or idc.BADADDR if none are found.
    '''
    if idaapi.get_func(location + 1) or idc.isAlign(idc.GetFlags(location + 1)): # This bit is inclusive
        return [location + 1] # This bit is exclusive

    eas = []
    # CA + CB are retf, but aren't used often; 'EA' is 16 bit; 'FF' jumps are too rare
    for opcode in ['C3', 'C2', 'E9', 'EB']:
        ea = location
        function_end = idc.BADADDR
        while ea != idc.BADADDR:
            ea = idc.FindBinary(ea + 1, idc.SEARCH_DOWN, opcode)
            if not (idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea))):
                function_end = ea
            else:
                break
        if function_end != idc.BADADDR:
            eas.append(_un_nop(function_end, idc.PrevHead) + 1) # Again, exclusive

    eas.sort(reverse = True)
    return eas

def split_funcs(startEA, endEA):
    '''
    Description:
        Attempt to split the function we created into a bunch of smaller functions based on
        aligns we find in the middle of the func. If we do successfully split, recurse on
        the remainder of the original function.

    Input:
        startEA - The beginning of the function
        endEA - The end of the function

    Output:
        The IDB is updated with the resulting functions
    '''
    ea = startEA
    while ea < endEA:
        # We found an align so delete the function and try to make 2 new ones in its place.
        if idaapi.isAlign(idc.GetFlags(ea)) and idc.DelFunction(startEA):
            # Make the first function.
            if idc.MakeFunction(startEA, _un_nop(ea, idc.NextHead)):
                # We found an align, now get past them.
                while idaapi.isAlign(idc.GetFlags(ea)):
                    ea += idc.ItemSize(ea)

                # Make the second function and recurse to ensure it doesn't need split too.
                if idc.MakeFunction(_un_nop(ea, idc.PrevHead), endEA):
                    append_debug('Split 0x%X - 0x%X at 0x%X.' % (startEA, endEA, ea))
                    split_funcs(ea, endEA)
                    return
                else: # We failed to make the second function, so delete the first.
                    idc.DelFunction(startEA)

            # Splitting failed - rebuild the original function.
            idc.MakeFunction(startEA, endEA)
            append_debug('Almost split 0x%X - 0x%X at 0x%X.' % (startEA, endEA, ea))

        ea += idc.ItemSize(ea)

def create_function(location, find_start = True):
    '''
    Description:
        Attempts to create a function using IDA's builtin functionality. If that fails build a
        assuming a start instruction of "push ebp", "push esp", "push esi", or "push edi" and an
        end instruction of "retn" (C2 or C3), excluding aligns and nops.

    Input:
        location - An address that should be within a function
        find_start - When False, assume location is the start of the function

    Output:
        True if it made a function, False otherwise.
    '''
    # Do a couple sanity checks.
    if idaapi.get_func(location):
        append_debug('There\'s already a function here! (0x%X)' % location)
        return False
    elif idc.isAlign(idc.GetFlags(location)) or idc.GetMnem(location) == 'nop' or \
            (idaapi.isData(idc.GetFlags(location)) and idc.Byte(location) == 0x90):
        append_debug('Can\'t make a function out of aligns and/or nops!')
        return False

    # Trace up as far as possible and have IDA do its thing.
    if ida_make_function(location):
        return True

    # Attempt to find the function ourselves.
    function_starts = _find_function_start(location) if find_start else [location]
    function_ends = _find_function_end(location)

    found_func = None
    if function_ends and function_starts:
        for function_start, function_end in itertools.product(function_starts, function_ends):
            if function_start < function_end:
                if idc.MakeFunction(function_start, function_end):
                    append_debug('Created a function 0x%X - 0x%X.' % (function_start, function_end))
                    found_func = (function_start, function_end)
                    break # Don't return here in case we have to split it yet.
                else:
                    append_debug('Tried to create a function 0x%X - 0x%X, but IDA wouldn\'t do it.' % (function_start, function_end))

    if found_func:
        split_funcs(*found_func)
        return True

    append_debug('Failed to find function based on location 0x%X.' % location)
    return False


def _force_find_start(loc):
    """
    Locate a possible function start location, if push ebp is found use that as default. Otherwise keep track of
    push esp, push esi, and push edi and use the lowest ea before finding a previous function.

    :param loc: Location a function is needed at

    :return: A possible function start location
    """
    push_esp = idc.BADADDR
    push_esi = idc.BADADDR
    push_edi = idc.BADADDR
    loc = idc.PrevHead(loc)
    while not idc.isAlign(idc.GetFlags(loc)) and not idaapi.get_func(loc):
        if idc.GetMnem(loc) == "push":
            opnd_0 = idc.GetOpnd(loc, 0)
            if opnd_0 == "ebp":
                return loc
            elif opnd_0 == "esp":
                push_esp = loc
            elif opnd_0 == "esi":
                push_esi = loc
            elif opnd_0 == "edi":
                push_edi = loc
        loc = idc.PrevHead(loc)
    min_ea = min([push_esp, push_esi, push_edi])
    return min_ea


def _find_force_end(loc):
    """
    Locate the first "ret" instruction down from the input location

    :param loc: Location a function is needed at

    :return: ItemEnd of the return location.
    """
    loc = idc.NextHead(loc)
    while not idc.isAlign(idc.GetFlags(loc)) and not idaapi.get_func(loc):
        if "ret" in idc.GetMnem(loc):
            return idc.ItemEnd(loc)
        loc = idc.NextHead(loc)
    return idc.ItemEnd(idc.PrevHead(loc))


def force_create_function(loc):
    """
    Similar to create_function above, but a little more hackish (maybe). Makes a lot of assumptions about there
    being defined code, i.e. not obfsucated code. However, won't create a function that does not include the
    desired location, which will need to be fixed at a later date.

    :param loc: Location a function is needed at

    :return: True if function is created, False otherwise
    """
    # Do a couple sanity checks.
    if idaapi.get_func(loc):
        append_debug('There\'s already a function here!')
        return False
    elif idc.isAlign(idc.GetFlags(loc)) or idc.GetMnem(loc) == 'nop' or \
            (idaapi.isData(idc.GetFlags(loc)) and idc.Byte(loc) == 0x90):
        append_debug('Can\'t make a function out of aligns and/or nops!')
        return False

    start = _force_find_start(loc)
    end = _find_force_end(loc)
    if idc.MakeFunction(start, end):
        append_debug('Created a function 0x%X - 0x%X.' % (start, end))
        return True
    else:
        append_debug('Failed to create a function 0x%X - 0x%X.' % (start, end))
        return False
