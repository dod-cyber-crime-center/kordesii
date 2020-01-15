"""
IDA Pyro4 client used to run IDAPython remotely.
"""

from __future__ import print_function

import logging
import functools
import os
import subprocess
import sys
import tempfile
import time
import threading

import dill
import Pyro4

import kordesii
from kordesii import ida_server
from kordesii import logutil


logger = logging.getLogger(__name__)

Pyro4.config.SERIALIZER = 'dill'
Pyro4.config.PICKLE_PROTOCOL_VERSION = 2  # Allows for Py2/3 compatibility

_open_proxies = {}           # Maps package full name to Proxy object.
_port = None                 # Port currently used to access Proxies
_instance_running = False    # Whether a current IDA instance is running.


def run_in_ida(func):
    """Decorates a functions to make available within the IDA proxy."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if kordesii.in_ida:
            return func(*args, **kwargs)

        if not _instance_running:
            raise RuntimeError('IDA instance is not started!')

        # We get a pickling error if we allow Pyro4 to serialize the function.
        # But doing it ourselves seems to work fine.
        main_proxy = _open_proxies['main']
        ret, stdout, stderr = main_proxy.run_func(sys.path, dill.dumps(func), *args, **kwargs)
        sys.stdout.write(stdout)
        sys.stderr.write(stderr)
        if isinstance(ret, Exception):
            raise ret  # Exception occurred in IDA
        return ret
    return wrapper


def communicate(proc):
    """
    Drop the annoying swig memory leak warning. This is not a real concern for our purposes
    and only clutters the test results.
    """
    stdout, stderr = proc.communicate()
    ignore_str = "swig/python detected a memory leak of type 'std::out_of_range *', no destructor found."
    if stdout:
        for out_line in stdout.splitlines(True):
            if out_line.strip() == ignore_str:
                continue
            sys.stdout.write(out_line)

    if stderr:
        for out_line in stderr.splitlines(True):
            if out_line.strip() == ignore_str:
                continue
            sys.stderr.write(out_line)


class IDAModule(object):
    """
    Replicates an IDA module externally.

    Redirects all function and attributes to the proxied module within IDA.
    """

    def __init__(self, fullname):
        # Using self.__dict__ to avoid triggering the overwritten __setattr__()
        self.__dict__['fullname'] = fullname

    def __repr__(self):
        status = 'open' if _instance_running else 'closed'
        return '<kordesii.ida_client.IDAModule for {} : {}>'.format(self.fullname, status)

    def __dir__(self):
        dir_ = []
        for name in dir(self._proxy):
            if name.startswith(('_pyro', '_Proxy')):
                continue
            if name.startswith('priv_'):
                name = name[4:]
            dir_.append(name)
        return dir_

    def __getattr__(self, item):
        if not _instance_running:
            raise AttributeError('IDA instance is closed.')

        # Hackery due to Pyro4 not allowing private methods and attributes.
        if item.startswith('_'):
            item = 'priv' + item

        value = getattr(self._proxy, item)
        return value

    def __setattr__(self, key, value):
        if not _instance_running:
            raise AttributeError('IDA instance is closed.')

        # Hackery due to Pyro4 not allowing private methods and attributes.
        if key.startswith('_'):
            key = 'priv' + key

        setattr(self._proxy, key, value)

    @property
    def _proxy(self):
        """
        Property to retrieve the Pyro4 proxy for the given module.
        Opens the proxy if not already.

        :return: proxy object
        :rtype: Pyro4.Proxy
        """
        if not _instance_running:
            raise AttributeError('IDA instance is closed.')
        try:
            return _open_proxies[self.fullname]
        except KeyError:
            try:
                proxy = Pyro4.Proxy('PYRO:{}@localhost:{}'.format(self.fullname, _port))
                _open_proxies[self.fullname] = proxy

                # Replace any attributes that this module would have overwritten.
                self.__dict__['__doc__'] = getattr(proxy, 'priv__doc__', self.__doc__)

                return proxy
            except Exception as e:
                raise RuntimeError('Cannot connect to IDA: {}'.format(e))


class IDALoader(object):
    """Import loader used to wrap any to-be proxied modules with IDAModule."""

    def load_module(self, fullname):
        try:
            return sys.modules[fullname]
        except KeyError:
            pass

        module = IDAModule(fullname)
        sys.modules[fullname] = module
        return module


class IDAFinder(object):
    """Import finder that passes IDALoader to any modules that should be proxied."""

    def find_module(self, fullname, path=None):
        # Fake the loader anytime we try to import a proxied module.
        if fullname in ida_server.proxied_modules:
            return IDALoader()
        return None


class IDA(object):
    """Allows running IDAPython script outside if IDA!"""

    _internal_extensions = ['.id0', '.id1', '.id2', '.nam', '.til']

    def __init__(self, input_path, keep_idb=False):
        """
        :param input_path: Path to file to examine.
        :param keep_idb: Whether to keep the idb around after stopping.
        """
        self.input_path = input_path
        # Keep idb if requested or an idb already was there.
        self.keep_idb = keep_idb or os.path.exists(input_path + '.idb') or os.path.exists(input_path + '.i64')
        self._orig_path = None
        self._orig_modules = None
        self._orig_meta_path = None
        self._thread = None
        self._process = None
        self._started = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def __del__(self):
        self.stop()

    @staticmethod
    def _make_port_file():
        """
        Creates a temporary file to transfer the connection port.

        The path to this file is transferred over the command line
        and the Pyro4 server (run in IDA) writes the connection port
        to it when it's been generated.
        """
        temp = tempfile.NamedTemporaryFile('rb', delete=False)
        temp.file.close()
        return temp.name

    @staticmethod
    def _get_port(port_path):
        """
        Get the saved connection port. Occasionally it takes
        a couple seconds for IDA to start up and write the port.

        :raises: An exception if occurred in ida_server.py
        """
        attempts = 0
        while attempts < 100:
            with open(port_path, 'r') as f:
                data = f.read()

            if data:
                ret = dill.loads(data)
                if isinstance(ret, Exception):
                    raise ret  # This exception occurred within IDA during setup.
                return ret

            attempts += 1
            time.sleep(0.25)

        raise RuntimeError("Unable to get IDA server port file.")

    def _open_in_ida(self):
        """
        Checks if input file is already open in idea by checking for the existance of
        internal runtime files.
        """
        return any(os.path.exists(self.input_path + ext) for ext in self._internal_extensions)

    def start(self):
        """
        Starts IDA proxy server and sets up import hooks.

        :raises RuntimeError: If we fail to start or connect to IDA.
        """
        global _instance_running
        global _open_proxies
        global _port

        if _instance_running:
            raise ValueError('IDA instance already started!')

        if not os.path.exists(self.input_path):
            raise ValueError('Unable to find: {}'.format(self.input_path))

        if self._open_in_ida():
            raise ValueError(
                'Another process has {} open in IDA. '
                'Please close the other process and/or cleanup the internal runtime files.'.format(
                    self.input_path))

        # Start log listener (if not already started)
        if not logutil.listen_port:
            kordesii.setup_logging()
            assert logutil.listen_port

        # Start up IDA server.
        ida_exe = kordesii.find_ida(kordesii.is_64_bit(self.input_path))
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_server.py')
        port_path = self._make_port_file()
        command = [
            ida_exe, '-A',
            '-S"\"{}\" {} {} {}"'.format(
                script_path, logging.root.getEffectiveLevel(), logutil.listen_port, port_path),
            # '-L"{}.log"'.format(self.input_path),   # Uncomment if debugging ida_server.py
            '"{}"'.format(self.input_path),
        ]
        command = ' '.join(command)
        logger.debug('Running command: {}'.format(command))

        env = dict(os.environ)
        env['PYTHONPATH'] = ""
        process = subprocess.Popen(command, env=env, shell=sys.platform != 'win32')

        thread = threading.Thread(target=communicate, args=(process,))
        thread.daemon = True
        thread.start()

        try:
            # Wait for port to arrive then retrieve it.
            logger.debug('Retrieving port...')
            _port = self._get_port(port_path)
            if os.path.exists(port_path):
                os.unlink(port_path)
            logger.debug('IDA Server setup on port {}'.format(_port))

            # Pull main proxy.
            main_proxy = Pyro4.Proxy('PYRO:main@localhost:{}'.format(_port))
            assert main_proxy.ping()  # Safety check
        except Exception:
            process.kill()
            thread.join()
            self._cleanup_files()
            raise

        _open_proxies['main'] = main_proxy
        self._process = process
        self._thread = thread
        self._orig_path = list(sys.path)
        self._orig_modules = dict(sys.modules)
        self._orig_meta_path = list(sys.meta_path)

        # Hook import paths to use proxy for internal ida module.
        sys.path.append(os.path.join(os.path.dirname(ida_exe), 'python'))
        sys.modules["__main__"].IDAPYTHON_COMPAT_695_API = False
        sys.meta_path.append(IDAFinder())

        _instance_running = True
        self._started = True

    def _stop_server(self):
        """Stop the IDA server."""
        # The first open proxy is our main proxy containing the stop_daemon() function we need to call.
        main_proxy = _open_proxies['main']
        main_proxy.stop_daemon()

    def _cleanup_files(self):
        """Cleans up any remaining IDA files."""
        extensions = self._internal_extensions[:]
        if not self.keep_idb:
            extensions += ['.idb', '.i64']
        for extension in extensions:
            file_path = self.input_path + extension
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    logger.warning('Failed to remove {} with error: {}'.format(file_path, e))

    def stop(self):
        """Stops IDA proxy server and removes import hooks."""
        global _open_proxies
        global _instance_running

        if not self._started:
            return

        try:
            # Restore import paths.
            sys.path = self._orig_path
            sys.modules = self._orig_modules
            sys.meta_path = self._orig_meta_path

            # Stop the proxies
            self._stop_server()
            for proxy in _open_proxies.values():
                proxy._pyroRelease()
                # Bug in Pyro4 teardown causes a warning on gc if
                # this attribute still exists.
                delattr(proxy, '_pyroConnection')
            _open_proxies = {}

            # Stop thread
            self._thread.join(5)
            if self._thread.is_alive():
                self._process.kill()
                self._thread.join(5)

            _instance_running = False
            self._started = False
        finally:
            # Ensure any remaining IDA files are removed.
            self._cleanup_files()
