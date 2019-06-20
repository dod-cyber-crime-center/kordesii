"""
Interface for emulating function call hooks.
"""

from contextlib import contextmanager

from .builtin_funcs import BUILTINS


# Collections of user defined hooks.
USER_DEFINED = None


def get(func_name_or_start_ea):
    """
    Gets function hook for given function name or start address.

    :param func_name_or_start_ea: Name or start address of the function to get hook for.
    :param default: What to return, if anything, when a function hook doesn't exist.

    :return: FunctionTracer object or None
    """
    # First check user defined hooks.
    if USER_DEFINED and func_name_or_start_ea in USER_DEFINED:
        return USER_DEFINED[func_name_or_start_ea]

    # Then pull from our builtins.
    return BUILTINS.get(func_name_or_start_ea)


@contextmanager
def hooks(hooks):
    """
    Context manager used to temporarily set the given user defined function hooks
    during emulation.

    :param hooks: Dictionary of function names mapping to hook functions.
    :return:
    """
    global USER_DEFINED
    try:
        USER_DEFINED = hooks
        yield
    finally:
        USER_DEFINED = None
