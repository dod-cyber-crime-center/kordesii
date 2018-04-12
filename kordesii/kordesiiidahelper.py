import os
import subprocess
import threading
import pefile
import shutil
import elftools.elf.elffile as elffile
import elftools.common.exceptions as elfexceptions

# Output files
IDA_LOG_FILE = "ida_log.txt"
IDA_DEBUG_FILE = "ida_debug.txt"
IDA_STRINGS_FILE = "ida_strings.txt"

# Directory for decoder specific output files
DECODER_OUTPUT_DIR = "decoder_output_files"

# Return codes
RETURN_CODE_TIMEOUT = 20

LOG_TOKEN = '[*] '


def find_ida(is_64_bit=False):
    """
    Description:
        Find the highest version of IDA installed on the current (windows) system.

    Input:
        is_64_bit - Will return the path to the 64 bit IDA if True. Default False.

    Output:
        Return the absolute path to the highest version of IDA installed at the default location
        on the current windows system or None if idaq.exe couldn't be found.
    """
    # Find path to directory the IDA installer defaults to (i.e. decide which Program Files).
    dir_ = [dir_ for dir_ in os.walk('C:\\').next()[1] if 'Program Files' in dir_]
    if len(dir_) > 1:
        dir_ = 'C:\\Program Files (x86)'
    elif dir_:
        dir_ = 'C:\\' + dir_[0]
    else:
        return

    # Find potential IDA install directories
    ida_dirs = [os.path.join(dir_, ida) for ida in os.walk(dir_).next()[1] if 'IDA' in ida]

    # Find highest IDA version with idaq.exe or idaq64.exe in the directory
    ida_exe = 'idaq64.exe' if is_64_bit else 'idaq.exe'
    ida_dirs.sort(reverse=True)
    for ida_dir in ida_dirs:
        if ida_exe in os.walk(ida_dir).next()[2]:
            return os.path.join(ida_dir, ida_exe)


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
        except elfexceptions.ELFError:
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
                     explicit idc.exit().
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
    debug_file_path = os.path.join(base_dir, IDA_DEBUG_FILE)
    strings_file_path = os.path.join(base_dir, IDA_STRINGS_FILE)
    output_dir_path = os.path.join(base_dir, DECODER_OUTPUT_DIR)

    # Cleanup any preexisting standard files to avoid overlap with previous decoder runs
    if os.path.exists(log_file_path):
        os.remove(log_file_path)
    if os.path.exists(debug_file_path):
        os.remove(debug_file_path)
    if os.path.exists(strings_file_path):
        os.remove(strings_file_path)

        # Configure command line flags based on parameters
    autonomous = '-A' if autonomous else ''
    log = ('-L' + log_file_path) if log else ''

    # Setup the process to run the IDA decoder script
    command = '"%s" %s -P %s -OMANA:MANA -S"\"%s\" exit" "%s"' % (ida_path, autonomous, log, script_path, input_file)
    process = subprocess.Popen(command)

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

    # Ingest any debug information output by the script
    if os.path.isfile(debug_file_path):
        with open(debug_file_path, "r") as f:
            for line in f:
                reporter.debug("ida_debug: %s" % (line.rstrip("\r\n")))

    # Ingest any strings output by the script
    if os.path.isfile(strings_file_path):
        with open(strings_file_path, "r") as f:
            for line in f:
                try:
                    reporter.add_string(line.rstrip("\r\n").decode("string-escape"))
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
                file_data = open(file_path, 'rb').read()
                reporter.add_output_file(file, file_data)

    # Perform cleanup as specified in the parameters
    if cleanup_txt_files:
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
        if os.path.exists(debug_file_path):
            os.remove(debug_file_path)
        if os.path.exists(strings_file_path):
            os.remove(strings_file_path)
    if cleanup_output_files:
        if os.path.exists(output_dir_path):
            shutil.rmtree(output_dir_path)
    if cleanup_idb_files:
        remove_idbs(input_file)


def remove_idbs(input_file):
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


def append_debug(message, log_token=LOG_TOKEN):
    """
    Append debug message to file for access outside of IDA.
    """
    message = log_token + message
    try:
        print message
        with open(IDA_DEBUG_FILE, 'ab') as f:
            f.write("%s\n" % message)
    except Exception as e:
        print("Error writing debug message to %s: %s" % (IDA_DEBUG_FILE, str(e)))


def append_string(string):
    """
    Append decoded string to file for access outside of IDA.
    """
    try:
        with open(IDA_STRINGS_FILE, 'ab') as f:
            f.write("%s\n" % string)
    except Exception as e:
        print("Error writing string to %s: %s" % (IDA_STRINGS_FILE, str(e)))


def remove_string(string, remove_all=False):
    """
    Remove the first instance of a string from the file. Opposite of append_string.
    """
    try:
        with open(IDA_STRINGS_FILE, 'rb') as f:
            current = f.read()

        if '\n%s\n' % string in current or current.startswith('%s\n' % string):
            with open(IDA_STRINGS_FILE, 'wb') as f:
                f.write(current.replace('%s\n' % string, '',
                                        (1 if not remove_all else None)))  # None is default for remove all
                # else quietly succeed if string wasn't present
    except Exception as e:
        print("Error removing string from %s: %s" % (IDA_STRINGS_FILE, str(e)))


def write_unique_file(filename, data):
    """
    Some IDA scripts will output files in addition to strings and debug messages.
    This function will append the provided data to the specified file name in
    a designated directory for access later.
    """
    if not os.path.exists(DECODER_OUTPUT_DIR):
        os.makedirs(DECODER_OUTPUT_DIR)

    filepath = os.path.join(DECODER_OUTPUT_DIR, filename)

    try:
        with open(filepath, 'wb') as f:
            f.write(data)
        append_debug('Wrote file: ' + filepath)
    except Exception as e:
        print("Error writing data to %s: %s" % (filepath, str(e)))
