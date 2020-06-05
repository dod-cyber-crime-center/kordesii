"""
IDA Pyro4 server used to run IDAPython remotely.
"""
import functools
import inspect
import importlib
import io
import logging
import pickle
import sys
import threading
import traceback
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
    "idc",
    "idaapi",
    "idautils",
    "ida_allins",
    "ida_auto",
    "ida_bytes",
    "ida_dbg",
    "ida_diskio",
    "ida_entry",
    "ida_enum",
    "ida_expr",
    "ida_fixup",
    "ida_fpro",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_graph",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idc",
    "ida_idd",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_moves",
    "ida_nalt",
    "ida_name",
    "ida_netnode",
    "ida_offset",
    "ida_pro",
    "ida_problems",
    "ida_range",
    "ida_registry",
    "ida_search",
    "ida_segment",
    "ida_segregs",
    "ida_strlist",
    "ida_struct",
    "ida_tryblks",
    "ida_typeinf",
    "ida_ua",
    "ida_xref",
    # Add kordesii modules that will work proxied.
    # (ie. modules that have functions only and no exposed classes)
    "kordesii.utils.utils",
    "kordesii.utils.segments",
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


class IDAModule(object):
    """
    This is a simple carrier class to pass the object id over to ida_client.
    When ida_client sees this class, it will replace it wih a proxy of the specified object id.
    """
    def __init__(self, object_id):
        self.object_id = object_id


class IDAClass(IDAModule):
    pass


def build_proxy_property(prop):
    """
    Builds a very simple proxy for a property.

    This is required in order add a property to the proxy class.
    """

    # noinspection PyUnusedLocal
    def _proxy(self):
        return prop

    return property(_proxy)


def build_proxy_submodule(module):
    """
    Creates a simple dummy class (IDAModule) containing the object id so ida_client
    can pick this up and initialize the proxy on its side.
    """
    def _proxy(self):
        if module.__name__ in proxied_modules:
            return IDAModule(module.__name__)
        return None
    return property(_proxy)


def build_proxy_class(klass, klass_name):
    """
    Creates a simple dummy class (IDAClass) containing the object id so ida_client can
    pick this up and initialize the proxy on its side.
    This is necessary since Pyro4's autoproxy feature causes too many issues.
    """
    object_id = ".".join([klass.__module__, klass_name])
    ida_class = IDAClass(object_id)

    def _proxy(self):
        if object_id not in self._pyroDaemon.objectsById:
            proxied_klass = _generate_proxy_class(klass, klass_name, ignore_classes=True)
            self._pyroDaemon.register(proxied_klass, objectId=object_id)
        return ida_class

    return property(_proxy)


def add_module(mod, klass, ignore_classes=False):
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
        if member_name.startswith("_"):
            member_name = "priv" + member_name

        if hasattr(klass, member_name):
            continue

        # Wrap functions and class initializations.
        if inspect.isroutine(member):
            setattr(klass, member_name, staticmethod(member))
        elif isinstance(member, type):
            # Ignore setting classes ontop classes.
            if isinstance(mod, type) or ignore_classes:
                continue
            setattr(klass, member_name, build_proxy_class(member, member_name))
        elif isinstance(member, types.ModuleType):
            setattr(klass, member_name, build_proxy_submodule(member))
        else:
            setattr(klass, member_name, build_proxy_property(member))


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
    def run_func(path, _globals, func, *args, **kwargs):
        """
        Runs any generic function.

        :param path: The sys.path from the caller.
            This helps to discover functions not in a package (ala, scripts)
        :param func: The pickled function to run
        :param _globals: Exposed global functions marked as run_in_ida.
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
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()

            func = dill.loads(func)
            _globals = dill.loads(_globals)

            try:
                # Apply exposed global functions.
                globals().update(_globals)

                # Now run the function.
                ret = func(*args, **kwargs)
            except Exception as e:
                # Pass any exceptions thrown as the return value
                # so we can reraise it externally.
                # Attach the traceback, so it can be printed out externally.
                e.ida_traceback = traceback.format_exception(None, e, e.__traceback__)
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


memo = {}


def _generate_proxy_class(module_or_class, name, ignore_classes=False):
    """Generates a safe proxyable class from given module or class."""
    if module_or_class not in memo:
        # Pyro4 doesn't allow private module names to be exposed, so a little hackery is in order.
        klass = type(name.strip("_"), (IDAProxy,), {})
        add_module(module_or_class, klass, ignore_classes=ignore_classes)
        Pyro4.expose(klass)
        memo[module_or_class] = klass
        return klass
    else:
        return memo[module_or_class]


def _register(daemon):
    """
    Sets up IDA/kordesii modules to be expose to given Pyro4 daemon.

    :returns: uri information returned by Pyro4
    :raises: An exception could be raised if we fail to import a module.
    """
    for module_name in proxied_modules:
        logging.debug("registering {}".format(module_name))
        module = importlib.import_module(module_name)
        klass = _generate_proxy_class(module, module_name)
        daemon.register(klass, objectId=module_name)

    # Now expose the main Proxy controller.
    Pyro4.expose(MainProxy)
    uri = daemon.register(MainProxy, objectId="main")

    return uri


def _send_result(result):
    """
    Write out a file telling client the port that was used or the exception that has occurred.
    (this also doubles as a way for the client to know we are ready)
    """
    import idc
    with open(idc.ARGV[3], "wb") as f:
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

        logger.debug("Starting daemon...")
        daemon = Pyro4.Daemon(host="localhost")
        warnings.simplefilter("ignore")

        uri = _register(daemon)

        logger.info("Listening on {}".format(uri))
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


if __name__ == "__main__" and kordesii.in_ida:
    logger.info("Starting")
    main()
