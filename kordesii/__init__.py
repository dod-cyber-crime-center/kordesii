
# Expose kordesii API
from .core import *
from .logutil import setup_logging, get_logger
from .reporter import Reporter
from .tester import Tester

# Add do nothing logger for when Kordesii is used as a library.
import logging
logging.getLogger('kordesii').addHandler(logging.NullHandler())
