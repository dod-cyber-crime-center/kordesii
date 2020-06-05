"""
IDA logging utility.
"""

import copy
import errno
import inspect
import logging
import logging.config
import logging.handlers
import os
import struct
import sys
import threading
import traceback
import warnings
from collections import deque

import kordesii
import kordesii.config as kordesii_config
import yaml
from six.moves import socketserver, cPickle as pickle


class LevelCharFilter(logging.Filter):
    """Logging filter used to add a 'level_char' format variable."""

    def filter(self, record):
        if record.levelno >= logging.ERROR:
            record.level_char = "!"
        elif record.levelno >= logging.WARN:
            record.level_char = "-"
        elif record.levelno >= logging.INFO:
            record.level_char = "+"
        elif record.levelno >= logging.DEBUG:
            record.level_char = "*"
        else:
            record.level_char = " "
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
            if not (sys.platform == "win32" and e.errno == errno.EACCES):
                raise


class ListHandler(logging.Handler):
    """
    Log to a list, with an optional maximum number of records to store.

    Full records are available with the `records` property, and messages (i.e.
    the text of the log entry) at available with the `messages` property.
    """

    def __init__(self, entries=None):
        """
        Behaves essentially identical to any other handler.

        The only option is max_entries, to specify the max number of log
        entries kept. By default, no limit.

        :param int entries: Maximum number of records to store.
        """
        super(ListHandler, self).__init__()

        self._deque = deque(maxlen=entries)

    def __copy__(self):
        new_handler = ListHandler()
        # Actually copy the deque, otherwise we'll get double entries
        new_handler._deque = copy.copy(self._deque)
        return new_handler

    def emit(self, record):
        msg = self.format(record)
        record.formatted_msg = msg
        self._deque.append(record)

    def clear(self):
        return self._deque.clear()

    @property
    def records(self):
        """
        List of the last `max_entries` records logged.
        """
        return list(self._deque)

    @property
    def messages(self):
        """
        List of the last `max_entries` formatted messages logged.
        """
        return [record.formatted_msg for record in self._deque]


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
            slen = struct.unpack(">L", chunk)[0]
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
    Simple TCP socket-based logging receiver.
    """

    allow_reuse_address = 1

    def __init__(self):
        # Since this is all local, we are using port 0 to let the system pick a random open port for us.
        socketserver.ThreadingTCPServer.__init__(self, ("localhost", 0), LogRecordStreamHandler)
        self.abort = 0
        self.timeout = 1
        self.logname = None

    def serve_until_stopped(self):
        import select

        abort = 0
        while not abort:
            rd, wr, ex = select.select([self.socket.fileno()], [], [], self.timeout)
            if rd:
                self.handle_request()
            abort = self.abort


_started_listener = False
# Port being used to listen to logs.
listen_port = None


def start_listener():
    """Start the listener thread for socket-based logging."""
    global _started_listener
    global listen_port

    if _started_listener:
        return

    tcp_server = LogRecordSocketReceiver()
    _, listen_port = tcp_server.server_address

    listener_thread = threading.Thread(target=tcp_server.serve_until_stopped)
    listener_thread.daemon = True
    listener_thread.start()
    # Make sure we only start this once.
    _started_listener = True


_setup_logging = False


def setup_logging(level=None):
    """
    Sets up logging using default log config file or log config file set by 'KORDESII_LOG_CFG'

    :param level: Log level to set.
        If not provided, level will be based on what is currently set in the root logger.
    """
    if kordesii.in_ida:
        if kordesii.called_from_framework:
            # If we are in IDA and part of a framework call, setup up socket handler that will
            # get received by the framework.
            # (log level and port will passed in as the 1st and 2nd command line argument)
            import idc

            log_level = int(idc.ARGV[1])
            log_port = int(idc.ARGV[2])

            logging.root.setLevel(log_level)
            socket_handler = logging.handlers.SocketHandler("localhost", log_port)
            logging.root.addHandler(socket_handler)
        else:
            # If running decoder from IDA interface, send simple logs to output window only.
            global _setup_logging
            if not _setup_logging:
                stream_handler = logging.StreamHandler()  # IDA redirects sys.stderr to output window.
                logging.root.addHandler(stream_handler)
                stream_handler.addFilter(LevelCharFilter())
                stream_handler.setFormatter(logging.Formatter("[%(level_char)s] %(module)-15s : %(message)s"))

                if level:
                    logging.root.setLevel(level)
                # Use INFO level if log level wasn't set by user.
                elif logging.root.getEffectiveLevel() == logging.NOTSET:
                    logging.root.setLevel(logging.INFO)

            # Make sure we only setup once to avoid duplicate log messages.
            _setup_logging = True
    else:
        # Allow setting log configuration using 'KORDESII_LOG_CFG' environment variable.
        log_config = os.getenv("KORDESII_LOG_CFG", kordesii_config.LOG_CONFIG_PATH)
        try:
            with open(log_config, "rt") as f:
                config = yaml.safe_load(f.read())
            logging.config.dictConfig(config)
        except IOError as e:
            warnings.warn("Unable to set log config file: {} with error: {}".format(log_config, e))
            logging.basicConfig(level=level or logging.INFO)

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
    try:
        frame, file_path, _, _, _, _ = inspect.stack(0)[call_level]
        caller_name = frame.f_locals.get("__name__", "__main__")
    except TypeError:
        f = sys._getframe().f_back
        stack = traceback.StackSummary.extract(traceback.walk_stack(f), limit=call_level + 1, capture_locals=True)
        stack.reverse()
        frame = stack[call_level]
        caller_name = frame.locals.get("__name__", "__main__")
        file_path = frame.filename
    if caller_name == "__main__":
        # Manually construct module path based on file locations.
        module_path = os.path.relpath(file_path, os.path.dirname(kordesii.__file__))
        module_path = ["kordesii"] + list(filter(None, list(os.path.split(module_path))))
        module_path[-1] = os.path.splitext(module_path[-1])[0]  # remove extension
        caller_name = ".".join(module_path)

    if os.sep in caller_name:
        caller_name = "kordesii." + caller_name.rpartition(os.sep)[2]

    return logging.getLogger(caller_name)
