
# Expose kordesii API
from .core import *
from .processors import *
from .logutil import setup_logging, get_logger
from .serialization import get_serializer
from .reporter import Reporter
from .tester import Tester
from .registry import (
    register_entry_points, register_decoder_directory, register_decoder_package,
    iter_decoders, get_decoder_descriptions, set_default_source, clear_default_source,
    get_sources)
from .ida_client import IDA, run_in_ida

# Add do nothing logger for when Kordesii is used as a library.
import logging

logging.getLogger('kordesii').addHandler(logging.NullHandler())
