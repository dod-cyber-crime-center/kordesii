"""
IDA Pyro4 server used to run IDAPython remotely.
"""

import inspect
import importlib
import io
import logging
import pickle
import sys
import threading
import types
import warnings

import dill
import Pyro4

import kordesii


daemon_stop = threading.Event()
_close_ida = True


logger = kordesii.get_logger()


# The following list contains all the modules to be proxied into IDA.
proxied_modules = [
    'idc',
    'idaapi',
    'idautils',
    'ida_allins',
    'ida_auto',
    'ida_bytes',
    'ida_dbg',
    'ida_diskio',
    'ida_entry',
    'ida_enum',
    'ida_expr',
    'ida_fixup',
    'ida_fpro',
    'ida_frame',
    'ida_funcs',
    'ida_gdl',
    'ida_graph',
    'ida_hexrays',
    'ida_ida',
    'ida_idaapi',
    'ida_idc',
    'ida_idd',
    'ida_idp',
    'ida_kernwin',
    'ida_lines',
    'ida_loader',
    'ida_moves',
    'ida_nalt',
    'ida_name',
    'ida_netnode',
    'ida_offset',
    'ida_pro',
    'ida_problems',
    'ida_range',
    'ida_registry',
    'ida_search',
    'ida_segment',
    'ida_segregs',
    'ida_strlist',
    'ida_struct',
    'ida_tryblks',
    'ida_typeinf',
    'ida_ua',
    'ida_xref',

    # Add kordesii modules that will work proxied.
    'kordesii.utils.utils',
]


class IDAProxy(object):
    r"""
    This is the proxy class. This class is made accessible to client
    (kordesii) through Pyro4.

    Nearly all of the methods are `staticmethod`\ s or properties.
    This class exists to be a proxy for the IDA-specific functions and methods.
    These are added later with the :meth:`~add_module` function.
    """

    # expose at least one method so Pyro doesn't have a fit.
    @staticmethod
    def testing_method():
        return "HI!!"


def build_proxy_func(func):
    """
    Builds a proxy function for a given function.

    Designed to be used for with IDA-based functions from
    IDA modules to proxy and make available to IDARemote.

    Due to how the serialization works between processes with Pyro4
    some modifications are made to the arguments and return values

    Arguments that are of type `unicode` are encoded with ``latin1``
    to `bytes`.

    :param function func: Function to proxy
    :return: The wrapped function
    """

    def _proxy(*args, **kwargs):
        new_args = list(args)
        for idx, arg in enumerate(args):
            if isinstance(arg, unicode):
                new_args[idx] = arg.encode('latin1')

        for key, value in kwargs.items():
            if isinstance(value, unicode):
                kwargs[key] = value.encode('latin1')

        return func(*new_args, **kwargs)

    return _proxy


def build_proxy_property(prop):
    """
    Builds a very simple proxy for a property.

    This is required in order add a property to the proxy class.
    """

    # noinspection PyUnusedLocal
    def _proxy(self):
        return prop

    return _proxy


def add_module(mod, klass):
    """
    Adds as much of a module as possible to the given class.

    Sub-modules are not added.

    Methods are proxied and added as static methods. Properties
    are similarly proxied and added as properties.

    :param mod: Module to add to the given class.
    :param klass: Class to add the module's functions and attributes to.
    """
    for member_name in dir(mod):
        member = getattr(mod, member_name)

        # Some hackery needed because Pyro4 doesn't like private methods and attributes.
        if member_name.startswith('_'):
            member_name = 'priv' + member_name

        if hasattr(klass, member_name):
            continue

        # Wrap functions and class initializations.
        if inspect.isroutine(member):
            setattr(klass, member_name, staticmethod(build_proxy_func(member)))
        elif isinstance(member, (type, types.ModuleType)):
            continue
        else:
            setattr(klass, member_name, property(build_proxy_property(member)))


class MainProxy(object):
    """
    This class holds the functions and attributes available in the main proxy.

    This is used to act as a controller for the external IDA client.
    This allows us to stop the IDA server as well as run generic functions
    that were originally unexposed.
    """

    @staticmethod
    def stop_daemon(close_ida=True):
        """
        Terminate the Pyro4 daemon and (optionally) teardown IDA

        :param bool close_ida: If IDA should be closed
        """
        global _close_ida

        daemon_stop.set()
        if not close_ida:
            _close_ida = False

    @staticmethod
    def run_func(path, func, *args, **kwargs):
        """
        Runs any generic function.

        :param path: The sys.path from the caller.
            This helps to discover functions not in a package (ala, scripts)
        :param func: The pickled function to run
        :param args: positional arguments
        :param kwargs: keyword arguments.
        :return: Return value of function.
        """
        orig_path = sys.path[:]
        orig_stdout = sys.stdout
        orig_stderr = sys.stderr

        try:
            # update sys.paths, so we can find the function
            sys.path += path
            # redirect stdout and stderr so we can bring it over
            sys.stdout = io.BytesIO()
            sys.stderr = io.BytesIO()

            func = dill.loads(func)

            new_args = list(args)
            for idx, arg in enumerate(args):
                if isinstance(arg, unicode):
                    new_args[idx] = arg.encode('latin1')

            for key, value in kwargs.items():
                if isinstance(value, unicode):
                    kwargs[key] = value.encode('latin1')

            try:
                ret = func(*new_args, **kwargs)
            except Exception as e:
                # Pass any exceptions thrown as the return value
                # so we can reraise it externally.
                ret = e
            return ret, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.path = orig_path
            sys.stdout = orig_stdout
            sys.stderr = orig_stderr

    @staticmethod
    def ping():
        """Check connection is working."""
        return True


def _register(daemon):
    """
    Sets up IDA/kordesii modules to be expose to given Pyro4 daemon.

    :returns: uri information returned by Pyro4
    :raises: An exception could be raised if we fail to import a module.
    """
    for module_name in proxied_modules:
        logging.debug('registering {}'.format(module_name))
        module = importlib.import_module(module_name)
        # Pyro4 doesn't allow private module names to be exposed, so a little hackery is in order.
        klass = type(module_name.strip('_'), (IDAProxy,), {})
        add_module(module, klass)
        Pyro4.expose(klass)
        daemon.register(klass, objectId=module_name)

    # Now expose the main Proxy controller.
    Pyro4.expose(MainProxy)
    uri = daemon.register(MainProxy, objectId='main')

    return uri


def _send_result(result):
    """
    Write out a file telling client the port that was used or the exception that has occurred.
    (this also doubles as a way for the client to know we are ready)
    """
    import idc
    with open(idc.ARGV[-1], 'wb') as f:
        f.write(dill.dumps(result))


def main():
    # Don't support the legacy api.
    sys.modules["__main__"].IDAPYTHON_COMPAT_695_API = False

    import idc

    kordesii.setup_logging()

    try:
        Pyro4.config.SERVERTYPE = "multiplex"
        Pyro4.config.FLAME_ENABLED = "True"
        Pyro4.config.SERIALIZERS_ACCEPTED = {"dill"}

        logger.debug('Starting daemon...')
        daemon = Pyro4.Daemon(host='localhost')
        warnings.simplefilter("ignore")

        uri = _register(daemon)

        logger.info('Listening on {}'.format(uri))
        # Send port back to the client.
        _send_result(uri.port)

        # Start listener
        idc.auto_wait()
        daemon.requestLoop(loopCondition=lambda: not daemon_stop.is_set())

        if _close_ida:
            idc.qexit(0)

    except Exception as e:
        # Send exception back to the client, so they can raise it outside of IDA.
        _send_result(e)


if __name__ == '__main__' and kordesii.in_ida:
    logger.info('Starting')
    main()
