"""
IDA logging utility.
"""
import errno
import inspect
import logging
import logging.config
import logging.handlers
import multiprocessing as mp
import os
import struct
import sys
import threading
import warnings

import yaml
from six.moves import socketserver, cPickle as pickle

import kordesii
import kordesii.config as kordesii_config


class LevelCharFilter(logging.Filter):
    """Logging filter used to add a 'level_char' format variable."""

    def filter(self, record):
        if record.levelno >= logging.ERROR:
            record.level_char = '!'
        elif record.levelno >= logging.WARN:
            record.level_char = '-'
        elif record.levelno >= logging.INFO:
            record.level_char = '+'
        elif record.levelno >= logging.DEBUG:
            record.level_char = '*'
        else:
            record.level_char = ' '
        return True


class MPRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    Handle the uncommon case of the log attempting to roll over when
    another process has the log open. This only happens on Windows, and
    the log ends up being a handful of KBs greater than 1024. Entries
    are still written, and the rollover happens if/when the MainProcess is
    the only process with the log file open.
    """

    def __init__(self, filename, **kwargs):
        # Expand and variables and home directories and make path if it doesn't exist.
        filename = os.path.expandvars(os.path.expanduser(filename))
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)
        super(MPRotatingFileHandler, self).__init__(filename, **kwargs)

    def doRollover(self):
        """
        Attempt to roll over to the next log file. If the current file
        is locked (Windows issue), keep writing to the original file until
        it is unlocked.

        :return:
        """
        try:
            super(MPRotatingFileHandler, self).doRollover()
        except OSError as e:
            if not (sys.platform == 'win32' and e.errno == errno.EACCES):
                raise


class LogRecordStreamHandler(socketserver.StreamRequestHandler):
    """Handler for a streaming logging request.

    This basically logs the record using whatever logging policy is
    configured locally.
    """

    def handle(self):
        """
        Handle multiple requests - each expected to be a 4-byte length,
        followed by the LogRecord in pickle format. Logs the record
        according to whatever policy is configured locally.
        """
        while True:
            chunk = self.connection.recv(4)
            if len(chunk) < 4:
                break
            slen = struct.unpack('>L', chunk)[0]
            chunk = self.connection.recv(slen)
            while len(chunk) < slen:
                chunk = chunk + self.connection.recv(slen - len(chunk))
            obj = self.unpickle(chunk)
            record = logging.makeLogRecord(obj)
            self.handle_log_record(record)

    def unpickle(self, data):
        return pickle.loads(data)

    def handle_log_record(self, record):
        # if a name is specified, we use the named logger rather than the one
        # implied by the record.
        if self.server.logname is not None:
            name = self.server.logname
        else:
            name = record.name
        logger = logging.getLogger(name)
        # TODO: Make sure we still filter on other end to save network bandwidth!
        if logger.isEnabledFor(record.levelno):
            logger.handle(record)


class LogRecordSocketReceiver(socketserver.ThreadingTCPServer):
    """
    Simple TCP socket-based logging receiver suitable for testing.
    """

    allow_reuse_address = 1

    def __init__(self, host='localhost',
                 port=logging.handlers.DEFAULT_TCP_LOGGING_PORT,
                 handler=LogRecordStreamHandler):
        socketserver.ThreadingTCPServer.__init__(self, (host, port), handler)
        self.abort = 0
        self.timeout = 1
        self.logname = None

    def serve_until_stopped(self):
        import select
        abort = 0
        while not abort:
            rd, wr, ex = select.select(
                [self.socket.fileno()], [], [], self.timeout)
            if rd:
                self.handle_request()
            abort = self.abort


_started_listener = False


def start_listener():
    """Start the listener thread for socket-based logging."""
    global _started_listener
    if mp.current_process().name != 'MainProcess' or _started_listener:
        return

    def _listener():
        tcp_server = LogRecordSocketReceiver()
        tcp_server.serve_until_stopped()

    listener_thread = threading.Thread(target=_listener)
    listener_thread.daemon = True
    listener_thread.start()
    # Make sure we only start this once.
    _started_listener = True


_setup_logging = False


def setup_logging(default_level=logging.INFO):
    """
    Sets up logging using default log config file or log config file set by 'KORDESII_LOG_CFG'

    :param default_level: Default log level to set to if config file fails.
    :param queue: Queue used to pass logs to.
    """
    if kordesii.in_ida:
        if kordesii.called_from_framework:
            # If we are in IDA and part of a framework call, setup up socket handler that will
            # get received by the framework.
            # TODO: Somehow pass the set logging level over here so we don't send over everything.
            logging.root.setLevel(logging.DEBUG)
            socket_handler = logging.handlers.SocketHandler(
                'localhost', logging.handlers.DEFAULT_TCP_LOGGING_PORT)
            logging.root.addHandler(socket_handler)
        else:
            # If running decoder from IDA interface, send simple logs to output window only.
            global _setup_logging
            if not _setup_logging:
                stream_handler = logging.StreamHandler()  # IDA redirects sys.stderr to output window.
                logging.root.addHandler(stream_handler)
                stream_handler.addFilter(LevelCharFilter())
                stream_handler.setFormatter(logging.Formatter("[%(level_char)s] %(message)s"))

            # Make sure we only setup once to avoid duplicate log messages.
            _setup_logging = True
    else:
        # Allow setting log configuration using 'KORDESII_LOG_CFG' environment variable.
        log_config = os.getenv('KORDESII_LOG_CFG', kordesii_config.LOG_CONFIG_PATH)
        try:
            with open(log_config, 'rt') as f:
                config = yaml.safe_load(f.read())
            logging.config.dictConfig(config)
        except IOError as e:
            warnings.warn('Unable to set log config file: {} with error: {}'.format(log_config, e))
            logging.basicConfig(level=default_level)

        # Receive decoder logs passed though the socket.
        start_listener()


def get_logger(call_level=1):
    """
    Helper function for getting the correctly named logger for decoders.
    This function is necessary because all decoder modules's __name__ attribute
    will be "__main__" when run in IDA.

    :param int call_level: Call level to pull module name from.
        (defaults to 1 which is the caller of this function)

    Add the following to the top of your decoder:

        import kordesii

        logger = kordesii.get_logger()

    :return: logging.Logger object
    """
    frame, file_path, _, _, _, _ = inspect.stack()[call_level]
    caller_name = frame.f_locals.get('__name__', '__main__')
    if caller_name == '__main__':
        # Manually construct module path based on file locations.
        module_path = os.path.relpath(file_path, os.path.dirname(kordesii.__file__))
        module_path = ['kordesii'] + filter(None, list(os.path.split(module_path)))
        module_path[-1] = os.path.splitext(module_path[-1])[0]  # remove extension
        caller_name = '.'.join(module_path)

    return logging.getLogger(caller_name)
