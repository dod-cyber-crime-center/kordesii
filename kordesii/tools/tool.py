
from __future__ import print_function

import logging
import optparse
import os
import json
import pkgutil
import sys
import traceback
import tempfile

import tabulate

import kordesii
from kordesii.reporter import Reporter

USAGE = 'Usage: kordesii.py [options] INPUT_FILE' + \
        '\n\tDECODER may either be the path to the file or the name of the family.' + \
        '\n\tPlease use full paths for best results!'
DECODER_POSTFIX = '_StringDecode'


def make_opt_parser():
    """
    create a option parser to handle command line inputs
    """
    usage_str = 'usage:  %s [options] FILE' % (os.path.basename(sys.argv[0]))
    description = "DC3-Kordesii Framework: utility for executing string decoder modules"
    opt_parser = optparse.OptionParser(usage_str, description=description)

    opt_parser.add_option('-a', '--autonomous',
                          action='store_false',
                          default=True,
                          dest='autonomous',
                          help='Launch IDA without autonomous mode so IDA GUI appears.')
    opt_parser.add_option('-p',
                          '--decoder',
                          action='store',
                          type='string',
                          default='',
                          dest='decoder',
                          help='string decoder to call')
    opt_parser.add_option('-e',
                          '--enableidalog',
                          action="store_true",
                          default=False,
                          dest='enableidalog',
                          help='include the log contents produced by IDA in the results')

    opt_parser.add_option("--no-debug", "-c", "--hidedebug",
                          action="store_true",
                          default=False,
                          dest="hidedebug",
                          help="Hide debug messages in output.")
    opt_parser.add_option("--debug",
                          action="store_true",
                          default=False,
                          dest="debug",
                          help="Turn on all debugging messages. (WARNING: This WILL spam the console)")

    opt_parser.add_option('-f',
                          '--includefileinfo',
                          action='store_true',
                          default=False,
                          dest='includefilename',
                          help='include input file information such as filename, hashes, and compile time in '
                               'parser output')
    opt_parser.add_option('-g',
                          '--disabletempcleanup',
                          action='store_true',
                          default=False,
                          dest='disabletempcleanup',
                          help='Disable cleanup of framework created temp files including managed tempdir')
    opt_parser.add_option('-j',
                          '--jsonoutput',
                          action='store_true',
                          default=False,
                          dest='jsonoutput',
                          help='Enable json output for parser reports (instead of formatted text)')
    opt_parser.add_option('-l',
                          '--list',
                          action="store_true",
                          default=False,
                          dest='list',
                          help='list all kordesii string decoders')
    opt_parser.add_option('-m',
                          '--tempdir',
                          action='store',
                          type='string',
                          metavar='DIR',
                          default=tempfile.gettempdir(),
                          dest='tempdir',
                          help='temp directory' + ' [default: %default]')
    opt_parser.add_option('-d',
                          '--decoderdir',
                          action='store',
                          type='string',
                          metavar='DIR',
                          default=None,
                          dest='decoderdir',
                          help='Optional extra decoder directory')
    opt_parser.add_option("--decodersource",
                        metavar="SOURCE_NAME",
                        default=None,
                        dest="decodersource",
                        help="Set a default decoder source to use. "
                             "If not provided parsers from all sources will be available.")
    opt_parser.add_option('-t', '--timeout',
                          action='store',
                          type=int,
                          default=10,
                          dest='timeout',
                          help='Timeout for running IDA (default = %default). A timeout of 0 disables ' +
                               'the timeout.')
    opt_parser.add_option('-x',
                          '--disabletxtcleanup',
                          action='store_true',
                          default=False,
                          dest='disabletxtcleanup',
                          help='Disable cleanup of txt files generated by IDA (ida_strings.txt, ida_log.txt,'
                               ' ida_debug.txt)')
    opt_parser.add_option('-y',
                          '--enableidbcleanup',
                          action='store_true',
                          default=False,
                          dest='enableidbcleanup',
                          help='Enable cleanup of IDB files and any IDA component files')
    opt_parser.add_option('-z',
                          '--enableoutputfilecleanup',
                          action='store_true',
                          default=False,
                          dest='enableoutputfilecleanup',
                          help='Enable any cleanup of unique output files generated by a decoder')

    return opt_parser


def _print_decoders(json_output=False):
    """Prints out list of registered decoders."""
    descriptions = kordesii.get_decoder_descriptions()
    if json_output:
        print(json.dumps(descriptions, indent=4))
    else:
        print(tabulate.tabulate(descriptions, headers=['NAME', 'SOURCE', 'AUTHOR', 'DESCRIPTION']))


def main():
    """
    Takes args from the command line, runs IDA, and returns with IDA's returncode on success or a message
    on failure.
    """
    opt_parse = make_opt_parser()
    options, args = opt_parse.parse_args()

    # Setup logging
    kordesii.setup_logging()
    if options.hidedebug:
        logging.root.setLevel(logging.ERROR)
    elif options.debug:
        logging.root.setLevel(logging.DEBUG)
    else:
        logging.root.setLevel(logging.INFO)

    # Register decoders
    kordesii.register_entry_points()
    if options.decoderdir:
        kordesii.register_decoder_directory(options.decoderdir)
    if options.decodersource:
        kordesii.set_default_source(options.decodersource)

    # List out decoder names and exit
    if options.list:
        _print_decoders(json_output=options.jsonoutput)
        sys.exit(0)

    # Currently only allow one file to be passed in
    if not args or len(args) != 1:
        opt_parse.print_help()
        return

    # If we can not create reporter object there is very little we can do. Just die immediately.
    try:
        reporter = Reporter(
            tempdir=options.tempdir,
            disabletempcleanup=options.disabletempcleanup,
            disabledebug=options.hidedebug,
        )
    except Exception as e:
        error_message = "Error loading DC3-Kordesii reporter object, please check installation: %s" % (
            traceback.format_exc())
        if options.jsonoutput:
            print('{"errors": ["%s"]}' % error_message)
        else:
            print(error_message)
        sys.exit(1)

    # Run decoder
    if options.decoder:
        # Grab file from arguments
        input_file = os.path.abspath(args[0])

        # Run the decoder
        reporter.run_decoder(options.decoder,
                             input_file,
                             timeout=options.timeout,
                             autonomous=options.autonomous,
                             log=options.enableidalog,
                             cleanup_txt_files=not options.disabletxtcleanup,
                             cleanup_output_files=options.enableoutputfilecleanup,
                             cleanup_idb_files=options.enableidbcleanup)

        # Output results
        if options.jsonoutput:
            output = reporter.metadata
            if reporter.errors:
                output["errors"] = reporter.errors
            if reporter.ida_log:
                output["ida_log"] = reporter.ida_log
            print(json.dumps(output, indent=4))
        else:
            reporter.print_report()


if __name__ == '__main__':
    main()
