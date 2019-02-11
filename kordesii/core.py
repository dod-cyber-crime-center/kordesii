"""
Core components that will be integrated as part of the root "kordesii" module.

NOTE: Importing "kordesii" is safe to do outside of IDA. Other modules, not so much.
"""
import atexit
import glob
import inspect
import os
import logging
import re
import shutil
import subprocess
import sys
import threading

import pefile
from elftools.common.exceptions import ELFError
from elftools.elf import elffile

from kordesii import logutil

try:
    import idc
    in_ida = True
except ImportError:
    idc = None
    in_ida = False

from kordesii.logutil import setup_logging


logger = logging.getLogger(__name__)


__all__ = ['decoder_entry', 'called_from_framework', 'in_ida', 'find_ida',
           'run_ida', 'is_64_bit', 'append_string', 'write_unique_file']


# Determines if the code was called from framework or directly from IDA
# TODO: Determine better way to do this.
called_from_framework = in_ida and 'exit' in idc.ARGV


IDA_LOG_FILE = "ida_log.txt"
IDA_STRINGS_FILE = "ida_strings.txt"
DECODER_OUTPUT_DIR = "decoder_output_files"
RETURN_CODE_TIMEOUT = 20


def decoder_entry(main_func):
    """
    Main entry code that will trigger IDA script execution.

    Decorate your main function like so:

        @kordesii.script_entry
        def main():
            # ....

    WARNING: The decorated function MUST be at the end of the module.

    :param main_func: function to call
    """
    decoder_locals = inspect.stack()[1][0].f_locals
    if decoder_locals.get('__name__') == '__main__':
        if in_ida:
            # Setup logging.
            setup_logging()
            if called_from_framework:
                log_level = int(idc.ARGV[1])
                logging.root.setLevel(log_level)
            elif logging.root.getEffectiveLevel() == logging.NOTSET:
                logging.root.setLevel(logging.INFO)

            # Run main()
            idc.auto_wait()
            try:
                main_func()
            except Exception as e:
                # Catch all exceptions, otherwise we have to go fish it out of ida_log.txt
                logger.exception(e)
            finally:
                # Exit if called from framework
                if called_from_framework:
                    idc.qexit(0)
        else:
            sys.exit('Script must be called from IDA or kordesii.')
            # TODO: We could possibly call run_ida() if outside.

    return main_func


def find_ida(is_64_bit=False):
    """
    Description:
        Find the highest version of IDA installed on the current (windows) system.

    Input:
        is_64_bit - Will return the path to the 64 bit IDA if True. Default False.

    Output:
        Return the absolute path to the highest version of IDA installed at the default location
        on the current windows system.

    Raises:
        IOError: If no installation of IDA could be found.
    """
    # Find installed IDA paths.
    ida_dirs = glob.glob(r'C:\Program Files*\IDA *')

    # Sort by highest version.
    get_version = lambda path: path.rpartition(' ')[2]
    ida_dirs.sort(key=get_version, reverse=True)

    ida_exe_re = re.compile('idaq?64\.exe' if is_64_bit else 'idaq?\.exe')

    # Find highest version with a ida.exe or idaq.exe in the directory.
    for ida_dir in ida_dirs:
        for filename in os.listdir(ida_dir):
            if ida_exe_re.match(filename):
                return os.path.abspath(os.path.join(ida_dir, filename))

    raise IOError('Unable to find IDA installation or executable. Please ensure IDA is installed.')


def is_64_bit(input_file):
    """
    Description:
        Do a quick check to see if it is an IDB/I64. Otherwise, attempt to determine if the
        file is 64bit based on the pe header. Note that the pe.close() prevents an mmap'd file from
        being left open indefinitely as the PE object doesn't seem to get garbage collected.
        Forcing garbage collection also corrects that issue.

    Input:
        input_file - The full path to the file in question

    Output:
        True if it is 64 bit. False if it is not or if pefile couldn't parse the header.
    """
    if input_file.endswith('.i64'):
        return True
    elif input_file.endswith('.idb'):
        return False

    # Get first bytes of file to check the file magic
    with open(input_file, 'rb') as f:
        first_bytes = f.read(8)

    if first_bytes[0:2] == "\x4D\x5A":
        # PE file type
        try:
            pe = pefile.PE(input_file, fast_load=True)
            result = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
            pe.close()
        except:
            result = False
    elif first_bytes[1:4] == "\x45\x4C\x46":
        # elf file type
        try:
            with open(input_file, 'rb') as f:
                elf = elffile.ELFFile(f)
                result = elf.get_machine_arch() == "x64"
        except ELFError:
            result = False
    elif first_bytes[0:4] == "\xCE\xFA\xED\xFE":
        # 32 bit MACH-O executable
        result = False
    elif first_bytes[0:4] == "\xCF\xFA\xED\xFE":
        # 64 bit MACH-O executable
        result = True
    else:
        result = False

    return result


def run_ida(reporter,
            script_path,
            input_file,
            autonomous=True,
            ida_path=None,
            timeout=3600,
            log=False,
            cleanup_txt_files=True,
            cleanup_output_files=False,
            cleanup_idb_files=False):
    """
    Description:
        Call IDA given an input file and IDA script to run.

    Input:
        reporter - Kordesii reporter object
        script_path - Path to the IDA script (e.g. ida_configdumper.py).
        input_file - Path to the file for which an IDB should be built and analyzed.
        autonomous - When set to True, IDA will not display dialog boxes. Setting to False
                     is useful in debugging errors as the IDB will remain open barring an
                     explicit idc.qexit().
        ida_path - Full path to idaq.exe file to run IDA. If None, use find_ida() function to
                   determine the path.
        timeout - run_ida will wait <timeout> seconds before killing the process. Setting
                  timeout to 0 will disable the timeout. This is mostly useful for automation.
        log - Get IDA log contents. The output is equivalent to the IDA console output.
        cleanup_txt_files - Cleanup standard text files upon running ida like the log, strings, and debug files.
        cleanup_output_files - Cleanup any output files uniquely produced by the IDA script.
        cleanup_idbs - Cleanup any IDB and any IDB component files ('.til', '.nam', '.id0', '.id1', '.id2', '.id3')

    Output:
        Information will be added to the reporter object.
        Output files will exist after execution based on the cleanup parameters and the script itself.
    """
    # First find IDA executable to run
    ida_path = ida_path if ida_path else find_ida(is_64_bit(input_file))
    if ida_path is None:
        return

    # Setup some variables for files that may be output by the decoder and IDA
    base_dir = reporter.filedir()
    log_file_path = os.path.join(base_dir, IDA_LOG_FILE)
    strings_file_path = os.path.join(base_dir, IDA_STRINGS_FILE)
    output_dir_path = os.path.join(base_dir, DECODER_OUTPUT_DIR)

    # Cleanup any preexisting standard files to avoid overlap with previous decoder runs
    if os.path.exists(log_file_path):
        os.remove(log_file_path)
    if os.path.exists(strings_file_path):
        os.remove(strings_file_path)

    # Setup the process to run the IDA decoder script
    log_level = logging.root.getEffectiveLevel()
    command = [ida_path, '-P', '-OMANA:MANA', '-S"\"{}\" {} exit"'.format(script_path, log_level)]
    if autonomous:
        command.append('-A')
    if log:
        command.append('-L"{}"'.format(log_file_path))

    command.append('"{}"'.format(input_file))
    command = ' '.join(command)  # Doesn't work unless we convert to string!

    logger.debug('Running command: {}'.format(command))
    process = subprocess.Popen(command)

    atexit.register(process.kill)

    # Wrap the call in a thread so we can time it out.
    thread = threading.Thread(target=process.communicate)
    thread.start()
    thread.join(timeout if timeout and timeout > 0 else None)  # Block on timeout of 0
    if thread.is_alive():  # This will only be true if timeout != 0
        reporter.debug('Killing IDA process: exceeded timeout of ' + str(timeout))
        process.kill()
        thread.join()
        return

    # IDA script completed
    # Make a note of the return code to have the information
    if process.returncode == 0:
        reporter.debug("IDA return code = {}".format(process.returncode))
    else:
        reporter.error("IDA return code = {}".format(process.returncode))

    # Ingest any debug information output by the script
    if log and os.path.isfile(log_file_path):
        with open(log_file_path, "r") as f:
            reporter.set_ida_log(f.read())

    # Ingest any strings output by the script
    if os.path.isfile(strings_file_path):
        with open(strings_file_path, "r") as f:
            for line in f:
                try:
                    reporter.add_string(line.rstrip("\r\n").decode("unicode-escape"))
                except:
                    reporter.error("Bad string: {}".format(line))

    # Ingest the IDB produced by the script
    if is_64_bit(input_file):
        idb_path = os.path.splitext(input_file)[0] + '.i64'
    else:
        idb_path = os.path.splitext(input_file)[0] + '.idb'
    if os.path.isfile(idb_path):
        reporter.set_idb(idb_path)

    # Ingest any files output by the script
    if os.path.exists(output_dir_path):
        for root, dirs, files in os.walk(output_dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as fo:
                    file_data = fo.read()
                reporter.add_output_file(file, file_data)

    # Perform cleanup as specified in the parameters
    if cleanup_txt_files:
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
        if os.path.exists(strings_file_path):
            os.remove(strings_file_path)
    if cleanup_output_files:
        if os.path.exists(output_dir_path):
            shutil.rmtree(output_dir_path)
    if cleanup_idb_files:
        _remove_idbs(input_file)


def _remove_idbs(input_file):
    """
    Description:
        Remove all IDB/I64 files and their components from the specified directory.
        Assumes the files aren't still open somewhere.

    Input:
        input_file - The file used to create the IDB we want to remove or the IDB itself.
    """
    input_file_name = os.path.splitext(input_file)[0]

    try:
        if os.path.exists(input_file_name + '.idb'):
            os.remove(input_file_name + '.idb')
        elif os.path.exists(input_file_name + '.i64'):
            os.remove(input_file_name + '.i64')
    except:
        print 'Error: Unable to remove ' + input_file

    # The order of the extensions here is important.
    for ext in ('.til', '.nam', '.id0', '.id1', '.id2', '.id3'):
        try:
            os.remove(input_file_name + ext)
        except OSError:
            break  # The file didn't exist. Since the extensions are ordered, we can assume none
            # of the others do either.


def append_string(string):
    """
    Append decoded string to file for access outside of IDA.

    :raises ValueError: If run outside of IDA.
    """
    if not in_ida:
        raise ValueError("This function can only be run within IDA.")

    try:
        # Make sure string is unicode escaped before writing!
        if not isinstance(string, unicode):
            string = string.decode('unicode-escape')
        string = string.encode('unicode-escape')
        with open(IDA_STRINGS_FILE, 'ab') as f:
            f.write(b''.join([string, b'\n']))
    except Exception as e:
        print("Error writing string to %s: %s" % (IDA_STRINGS_FILE, str(e)))


def write_unique_file(filename, data):
    """
    Some IDA scripts will output files in addition to strings and debug messages.
    This function will append the provided data to the specified file name in
    a designated directory for access later.

    :raises ValueError: If run outside of IDA.
    """
    if not in_ida:
        raise ValueError("This funciton can only run within IDA.")

    if not os.path.exists(DECODER_OUTPUT_DIR):
        os.makedirs(DECODER_OUTPUT_DIR)

    filepath = os.path.join(DECODER_OUTPUT_DIR, filename)

    try:
        with open(filepath, 'wb') as f:
            f.write(data)
        logger.info('Wrote file: {}'.format(filepath))
    except Exception as e:
        print("Error writing data to %s: %s" % (filepath, str(e)))
