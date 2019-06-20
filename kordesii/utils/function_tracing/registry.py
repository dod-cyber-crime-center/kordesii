

def registrar(registry, name='entry'):
    """
    Creates and returns a register function that can be uses as a decorator
    for registering functions into the given registry dictionary.

    :param registry: Dictionary to add entry registrations to.
    :param name: Name to give to each entry. "entry" is used by default.

    :returns: A register() decorator that can be used to fill in the given registry dictionary.
    """

    def register_func(entry_name_or_func):
        """
        Registers an entry for the CPU emulator.
        """
        if callable(entry_name_or_func):
            # If function, that means no argument was passed in and we should register using the function name.
            func = entry_name_or_func
            entry_name = func.__name__.lower()
            registry[entry_name] = func
            return func

        # Otherwise, register with user provided name
        entry_name = entry_name_or_func
        if entry_name in registry:
            raise ValueError("Duplicate {} name: {}".format(name, entry_name))

        def _wrapper(func):
            # Register function as entry.
            registry[entry_name.lower()] = func
            return func  # Must return function afterwards.

        return _wrapper

    return register_func
