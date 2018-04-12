import idc
import idaapi
import idautils

import itertools
from kordesii.kordesiiidahelper import append_debug


def try_make_function(function_start, function_end=idc.BADADDR, target_location=None, require_term=True,
                      end_mnem_bytes=None):
    """
    Description:
        Given a function location, attempt to create a function.
        If function creation fails, delete any partially created functions.
        If function creation succeeds, ensure all of the function's bytes are analyzed as code.

    Input:
        function_start - The startEA of the function to create
        function_end - The endEA of the function to create. IDA will calculate if not provided.
        target_location - If provided, fail function creation if it does not include this EA
        require_term - If provided, fail function creation if the last instruction is not a ret or jmp
        end_mnem_bytes - If provided, fail function creation if the last instruction is not the provided bytes
                         Instructions are entered as space separated bytes (i.e. '55' for 'push ebp')

    Output:
        Returns a tuple (function_start, function_end) for the created function if successful, None otherwise
    """
    if function_start <= function_end:
        if idc.MakeFunction(function_start, function_end):
            append_debug('Created a function 0x%X - 0x%X.' % (function_start, function_end))
            if require_term:
                last_mnem_ea = idc.ItemHead(idaapi.get_func(function_start).endEA - 1)
                last_mnem = idc.GetMnem(last_mnem_ea)
                if (end_mnem_bytes is None and 'ret' not in last_mnem and 'jmp' not in last_mnem) or \
                                idaapi.get_many_bytes(last_mnem_ea, idc.ItemSize(last_mnem_ea)).encode(
                                    'hex').upper() != end_mnem_bytes.upper():
                    idc.DelFunction(function_start)
                    append_debug(
                        'Deleted function at 0x%X - the function didn\'t end with the correct mnem/bytes.' % function_start)
                    return
            if target_location is not None:
                if function_start <= target_location < idaapi.get_func(function_start).endEA:
                    idc.AnalyzeArea(function_start, idaapi.get_func(function_start).endEA)
                    return function_start, function_end
                else:
                    idc.DelFunction(function_start)
                    append_debug(
                        'Deleted function at 0x%X - the function didn\'t contain the target location.' % function_start)
                    return
        else:
            append_debug(
                'Tried to create a function 0x%X - 0x%X, but IDA wouldn\'t do it.' % (function_start, function_end))
    else:
        append_debug('The end address was not greater than the start address!')


def find_binary_instruction_start(search_start_location, search_direction, target, min_location=idc.MinEA(),
                                  max_location=idc.MaxEA()):
    """
    Description:
        Given a starting location, target, and direction, find an instruction starting with the target bytes.

    Input:
        search_start_location - The EA to start searching at
        search_direction - either idc.SEARCH_UP or idc.SEARCH_DOWN
        target - The target as space separated bytes (i.e. '55' for 'push ebp')
        min_location - The minimum EA to accept results for (default: idc.MinEA())
        max_location - The maximum EA to accept results for (default: idc.MaxEA())

    Output:
        Returns the first matching location if found, otherwise idc.BADADDR
    """
    target = target.upper()
    while search_start_location < max_location:
        ea = idc.FindBinary(search_start_location, search_direction, target)
        # print target, '0x%X <= 0x%X < 0x%X' % (min_location, ea, max_location), idaapi.get_many_bytes(ea, idc.ItemSize(ea)).encode('hex')
        if min_location <= ea < max_location and ea == idc.ItemHead(ea) and idaapi.get_many_bytes(ea, idc.ItemSize(
                ea)).encode('hex').upper().startswith(target.replace(' ', '')):
            # print target, '0x%X' % ea
            return ea
        else:
            search_start_location = ea + (1 if search_direction == idc.SEARCH_DOWN else -1)
    return idc.BADADDR


def calc_most_common_start_bytes():
    """
    Description:
        Iterate over all non-lib (and non-thunk) functions and record their first instruction.
        Return the bytes for whichever instruction appears most.

    Output:
        A space separated string of bytes of the most common first instruction.
    """
    counts = {}
    for func_ea in idautils.Functions():
        if not idc.GetFunctionFlags(func_ea) & (idc.FUNC_LIB | idc.FUNC_THUNK):
            start_bytes = idaapi.get_many_bytes(func_ea, idc.ItemSize(func_ea))
            if start_bytes in counts:
                counts[start_bytes] += 1
            else:
                counts[start_bytes] = 1
    return ' '.join('%02X' % ord(c) for c in sorted(counts.items(), key=lambda tup: tup[1], reverse=True)[0][0])


def sanity_checks(location):
    """
    Description:
        Do some basic checks to see if a function can be created containing the provided EA.

    Input:
        location - The EA to evaluate

    Output:
        True if a function can be created containing the provided EA
        False if a the provided EA was a nop or Align
        None if there is already a function containing the provided EA
    """
    if idaapi.get_func(location):
        append_debug('There\'s already a function here! (0x%X)' % location)
        return None
    elif idc.isAlign(idc.GetFlags(location)) or idc.GetMnem(location) == 'nop' or \
            (idaapi.isData(idc.GetFlags(location)) and idc.Byte(location) == 0x90):
        # Yes, the nop bit may be incorrect, but it's gonna be a very special case that needs a function with nops
        append_debug('Can\'t make a function including aligns and/or nops!')
        return False
    else:
        return True


def trim_func(ea, GetHead):
    """
    Description:
        Steps until it hits something not a nop or not starts with 90 (nop opcode) nor an align or not byte 0xCC (Align 'opcode').

    Input:
        ea - The location to adjust for nops and Aligns. EA must be a head.
        GetHead - either PrevHead or NextHead

    Output:
        The corrected EA.
    """
    while idc.GetMnem(ea) == 'nop' or (idaapi.isData(idc.GetFlags(ea)) and idc.Byte(ea) == 0x90) or \
            idc.isAlign(idc.GetFlags(ea)) or (not idc.isCode(idc.GetFlags(ea)) and idc.Byte(ea) == 0xCC):
        ea = GetHead(ea)
    return ea


def find_function_starts_near(location, start_mnem_bytes=None):
    """
    Description:
        Identifies the nearest possible function starts since the most recent function or Align.

    Input:
        location - The EA to search before
        start_mnem_bytes - Try to start functions on a particular instruction
                           Instructions are entered as space separated bytes (i.e. '55' for 'push ebp')
                           The specified pattern will be used first, then the defaults will be used
                           If no pattern is specified, the defaults will be used, which prefers 'push ebp'

    Output:
        starts - A list of function end EAs sorted: start_mnem_bytes, push ebp, (push esp, push esi, push edi)
    """
    # foreach target bytes:
    #  step instructions up
    #  if instruction matches the target bytes, add to output list
    #   then move on to the next target bytes
    #  if we hit a function or an align, quit
    # return starts in the order
    #  start_nmem_bytes
    #  push ebp
    #  others, sorted descending

    min_location = None
    ea = location
    while min_location is None:
        ea = idc.PrevHead(ea)
        if idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea)):
            min_location = ea
        elif ea == idc.BADADDR:
            min_location = idaapi.getseg(location).startEA
    min_location = max(min_location, idaapi.getseg(location).startEA)

    targets = ['55', '54', '56', '57']
    if start_mnem_bytes:
        targets.insert(0, start_mnem_bytes)

    starts = {}
    for target in targets:
        ea = find_binary_instruction_start(location - 1, idc.SEARCH_UP, target, min_location)
        if ea != idc.BADADDR:
            starts[target] = ea

    return [start for start in ([starts.get(start_mnem_bytes, None), starts.get('55', None)] +
                                sorted([starts.get(target, None) for target in targets[-3:]], reverse=True)) if start]


def find_function_starts(location, start_mnem_bytes=None):
    """
    Description:
        Identifies all possible function starts since the most recent function or Align.

    Input:
        location - The EA to search before
        start_mnem_bytes - Try to start functions on a particular instruction
                           Instructions are entered as space separated bytes (i.e. '55' for 'push ebp')
                           The specified pattern will be used first, then the defaults will be used
                           If no pattern is specified, the defaults will be used, which prefers 'push ebp'

    Output:
        starts - A list of function end EAs sorted: start_mnem_bytes, push ebp, (push esp, push esi, push edi)
    """
    # foreach target bytes:
    #  step instructions up
    #  if instruction matches the target bytes, add to the corresponding output list
    #  if we hit a function or an align, quit
    # return starts in the order:
    #  start_nmem_bytes
    #  push ebp
    #  others, sorted ascending

    min_location = None
    ea = location
    while min_location is None:
        ea = idc.PrevHead(ea)
        if idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea)):
            min_location = ea
        elif ea == idc.BADADDR:
            min_location = idaapi.getseg(location).startEA
    min_location = max(min_location, idaapi.getseg(location).startEA)

    targets = ['55', '54', '56', '57']
    if start_mnem_bytes:
        targets.insert(0, start_mnem_bytes)

    starts = {}
    for target in targets:
        function_starts = []
        ea = find_binary_instruction_start(location - 1, idc.SEARCH_UP, target, min_location)
        while ea != idc.BADADDR:
            if ea < min_location:
                break
            else:
                function_starts.append(ea)
            ea = find_binary_instruction_start(ea - 1, idc.SEARCH_UP, target, min_location)
        starts[target] = function_starts

    return (starts[start_mnem_bytes] if start_mnem_bytes else []) + starts['55'] + \
           sorted(itertools.chain.from_iterable(starts[target] for target in targets[-3:]))


def find_function_ends_near(location, end_mnem_bytes=None):
    """
    Description:
        Identifies the nearest possible function ends before the next function or Align for each end mnem.

    Input:
        location - The EA to search after
        end_mnem_bytes - Try to end functions on a particular instruction
                         Instructions are entered as space separated bytes (i.e. 'C2' for 'retn')
                         The specified pattern will be used first, then the defaults will be used
                         If no pattern is specified, the defaults will be used, which prefers 'retn'

    Output:
        ends - A list of function end EAs sorted: end_mnem_bytes, retn, jmp
    """
    # foreach target bytes:
    #  step instructions down
    #  if instruction matches the target bytes, add to output list
    #   then move on to the next target bytes
    #  if we hit a function or an align, quit
    # return ends in the order
    #  end_nmem_bytes
    #  retn
    #  jmp
    #  others, sorted ascending

    max_location = None
    ea = location
    while max_location is None:
        ea = idc.NextHead(ea)
        if idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea)):
            max_location = ea
        elif ea == idc.BADADDR:
            max_location = idaapi.getseg(location).endEA
    max_location = min(max_location, idaapi.getseg(location).endEA)

    targets = ['C2', 'C3', 'E9', 'EA', 'EB']
    if end_mnem_bytes:
        targets.insert(0, end_mnem_bytes)

    ends = {}
    for target in targets:
        ea = find_binary_instruction_start(location, idc.SEARCH_DOWN, target, max_location=max_location)
        if ea <= max_location:
            ends[target] = ea

    return [end + idc.ItemSize(end) for end in
            (([ends.get(end_mnem_bytes, None), ends.get('C2', None), ends.get('C3', None)]) +
             sorted(ends.get(target, None) for target in targets[-3:])) if end]


def find_function_ends(location, end_mnem_bytes=None):
    """
    Description:
        Identifies all possible function ends before the next function or Align.

    Input:
        location - The EA to search after
        end_mnem_bytes - Try to end functions on a particular instruction
                         Instructions are entered as space separated bytes (i.e. 'C2' for 'retn')
                         The specified pattern will be used first, then the defaults will be used
                         If no pattern is specified, the defaults will be used, which prefers 'retn'

    Output:
        ends - A list of function end EAs sorted: end_mnem_bytes, retn, jmp
    """
    # foreach target bytes:
    #  step instructions down
    #  if instruction matches the target bytes, add to the corresponding output list
    #  if we hit a function or an align, quit
    # return ends in the order:
    #  end_nmem_bytes
    #  retn
    #  jmp
    #  others, sorted ascending

    max_location = None
    ea = location
    while max_location is None:
        ea = idc.NextHead(ea)
        if idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea)):
            max_location = ea
        elif ea == idc.BADADDR:
            max_location = idaapi.getseg(location).endEA
    max_location = min(max_location, idaapi.getseg(location).endEA)

    targets = ['C3', 'C2', 'E9', 'EA', 'EB']
    if end_mnem_bytes:
        targets.insert(0, end_mnem_bytes)

    ends = {}
    for target in targets:
        function_ends = []
        ea = find_binary_instruction_start(location, idc.SEARCH_DOWN, target, max_location=max_location)
        while ea != idc.BADADDR:
            if ea > max_location:
                break
            else:
                function_ends.append(ea)
            ea = find_binary_instruction_start(ea + 11, idc.SEARCH_DOWN, target, max_location=max_location)
        ends[target] = function_ends

    return [end + idc.ItemSize(end) for end in
            ((ends[end_mnem_bytes] if end_mnem_bytes else []) + sorted(ends['C3'] + ends['C2']) +
             sorted(itertools.chain.from_iterable(ends[target] for target in targets[-3:])))]


def create_function_here(location, require_term=True, end_mnem_bytes=None):
    """
    Description:
        Attempt to make a function starting at the provided EA. First, try to have IDA find the end.
        If that fails, try to find the end ourselves.

    Input:
        location - The EA at which IDA should attempt to make a function.
        require_term - When True, requires the last instruction in all defined functions to be retn or jmp
        end_mnem_bytes - Try to end functions on a particular instruction
                         Instructions are entered as space separated bytes (i.e. 'C2' for 'retn')
                         The specified pattern will be used first, then the defaults will be used
                         If no pattern is specified, the defaults will be used, which prefers 'retn'

    Output:
        True if it made a function or a function was already present, False otherwise.
    """
    sanity = sanity_checks(location)
    if sanity is None:  # There was already a function
        return True
    elif sanity is False:  # There was something preventing function creation
        return False

    function_ends = find_function_ends(location, end_mnem_bytes)
    function_ends.insert(0, idc.BADADDR)
    for end in function_ends:
        if try_make_function(location, end, location, require_term, end_mnem_bytes):
            return True
    return False


def create_function_precise(location, require_term=True, start_mnem_bytes=None, end_mnem_bytes=None):
    """
    Description:
        Attempt to make a function containing <location> and only that function.
        First tries to let IDA find the end of the calculated start EA.
        If that fails, try to calculate the end ourselves.

    Input:
        location - An address that should be within a function
        require_term - When True, requires the last instruction in all defined functions to be retn or jmp
        start_mnem_bytes - Try to start functions on a particular instruction
                           Instructions are entered as space separated bytes (i.e. '55' for 'push ebp')
                           The specified pattern will be used first, then the defaults will be used
                           If no pattern is specified, the defaults will be used, which prefers 'push ebp'
        end_mnem_bytes - Try to end functions on a particular instruction
                         Instructions are entered as space separated bytes (i.e. 'C2' for 'retn')
                         The specified pattern will be used first, then the defaults will be used
                         If no pattern is specified, the defaults will be used, which prefers 'retn'

    Output:
        True if it made a function or a function was already present, False otherwise.
    """
    sanity = sanity_checks(location)
    if sanity is None:  # There was already a function
        return True
    elif sanity is False:  # There was something preventing function creation
        return False

    append_debug('Trying to make function for 0x%X' % location)
    function_starts = find_function_starts_near(location, start_mnem_bytes)
    if not function_starts:
        return False  # If we don't have any start points, we're up a creek

    # Don't populate function_ends at this point to avoid the tracing we aren't sure we need yet
    # This will cause two repeats in the last section if we get that far, but that's an acceptable trade-off

    # Try to make a function at the most likely start point letting IDA calculate the end
    if try_make_function(function_starts[0], target_location=location, require_term=require_term,
                         end_mnem_bytes=end_mnem_bytes):
        return True
    else:  # If that fails, try to make a function at that point with the most likely end
        function_ends = find_function_ends_near(location, end_mnem_bytes)
        # Only try the first end here. This guarantees that one of the lower tier starts won't work with idc.BADADDR before we try this end
        if function_ends and try_make_function(function_starts[0], function_ends[0], location, require_term,
                                               end_mnem_bytes):
            return True

    # Always let IDA have the first shot at finding the end for each start
    function_ends.insert(0, idc.BADADDR)
    # For each end, try each start, that way each start gets a shot at the most likely end before we try the next most likely one
    for function_end in function_ends:
        # For each start, try to make a function with the current end
        for function_start in function_starts:
            if try_make_function(function_start, function_end, location, require_term, end_mnem_bytes):
                return True
    return False


def ida_make_functions(location, require_term=True):
    """
    Description:
        Attempts to create functions based on the assumption that there should be continuous contiguous
        functions defined since the previous function or align. Stops creating functions once a function
        containing <location> is created or the next created function would be past <location>.
        Only identifies potential start EAs and lets IDA find the ends.

    Input:
        location - The EA at which IDA should attempt to make a function.
        require_term - When True, requires the last instruction in all defined functions to be retn or jmp

    Output:
        True if it made a function or a function was already present, False otherwise.
    """
    sanity = sanity_checks(location)
    if sanity is None:  # There was already a function
        return True
    elif sanity is False:  # There was something preventing function creation
        return False

    target_location = location
    function_start = location
    ea = location
    while not (idaapi.get_func(ea) or idc.isAlign(idc.GetFlags(ea))):
        function_start = ea
        ea = idc.PrevHead(ea)
    function_start = trim_func(function_start, idc.NextHead)

    if try_make_function(function_start, require_term=require_term):
        if not idaapi.get_func(target_location):
            return ida_make_functions(target_location, require_term)
        else:
            return True
    else:
        return False


def create_functions(location, require_term=True, start_mnem_bytes=None, end_mnem_bytes=None):
    """
    Description:
        Attempts to create functions based on the assumption that there should be continuous contiguous
        functions defined since the previous function or align. Stops creating functions once a function
        containing <location> is created or the next created function would be past <location>.
        Finds both start and end EAs, not using on IDA's algorithms.

    Input:
        location - An address that should be within a function
        require_term - When True, requires the last instruction in all defined functions to be retn or jmp
        start_mnem_bytes - Try to start functions on a particular instruction
                           Instructions are entered as space separated bytes (i.e. '55' for 'push ebp')
                           The specified pattern will be used first, then the defaults will be used
                           If no pattern is specified, the defaults will be used, which prefers 'push ebp'
        end_mnem_bytes - Try to end functions on a particular instruction
                         Instructions are entered as space separated bytes (i.e. 'C2' for 'retn')
                         The specified pattern will be used first, then the defaults will be used
                         If no pattern is specified, the defaults will be used, which prefers 'retn'

    Output:
        True if it made a function or a function was already present, False otherwise.
    """
    sanity = sanity_checks(location)
    if sanity is None:  # There was already a function
        return True
    elif sanity is False:  # There was something preventing function creation
        return False

    # Attempt to find the function ourselves.
    function_starts = find_function_starts(location, start_mnem_bytes)
    function_ends = find_function_ends(location, end_mnem_bytes)

    found_func = None
    for function_start, function_end in itertools.product(function_starts, function_ends):
        if function_start < function_end:
            if try_make_function(function_start, function_end,
                                 require_term=require_term) and function_start <= location < idaapi.get_func(
                function_start).endEA:
                found_func = (function_start, function_end)
                break  # Don't return here in case we have to split it yet.

    if found_func:
        return True
    else:
        append_debug('Failed to find function based on location 0x%X.' % location)
        return False
