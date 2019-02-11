
import logging
import optparse
import os
import pkgutil
import sys
import traceback
import tempfile

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

    default_decoderdir = ''

    # create reporter to get default paths, ignore if this fails
    try:
        default_reporter = Reporter()
        default_decoderdir = default_reporter.decoderdir
    except Exception as e:
        traceback.print_exc()

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
                          default=default_decoderdir,
                          dest='decoderdir',
                          help='decoders directory' + ' [default: %default]')
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

    # If we can not create reporter object there is very little we can do. Just die immediately.
    try:
        reporter = Reporter(decoderdir=options.decoderdir,
                            tempdir=options.tempdir,
                            disabletempcleanup=options.disabletempcleanup,
                            disabledebug=options.hidedebug,
                            enableidalog=options.enableidalog)
    except Exception as e:
        error_message = "Error loading DC3-MWCP reporter object, please check installation: %s" % (
            traceback.format_exc())
        if options.jsonoutput:
            print('{"errors": ["%s"]}' % error_message)
        else:
            print(error_message)
        sys.exit(1)

    # List out decoder names and exit
    if options.list:
        decoders = reporter.list_decoders()

        if options.jsonoutput:
            if reporter.errors:
                decoders.append({"errors": reporter.errors})
            print reporter.pprint(decoders)
        else:
            for name in decoders:
                print(name)
            if reporter.errors:
                print("")
                print("Errors:")
                for error in reporter.errors:
                    print("    %s" % error)
        return

    # Currently only allow one file to be passed in
    if not args or len(args) != 1:
        opt_parse.print_help()
        return

    # Run decoder
    if options.decoder:
        # Grab file from arguments
        input_file = os.path.abspath(args[0])

        # Verify provided decoder name is valid
        decoder = options.decoder
        try:
            decoder_path = reporter.get_decoder_path(decoder)
        except ValueError as e:
            print "Error: {}".format(e)
            return

        # IDA doesn't like backslashes in it's argv.
        input_file = input_file.replace('\\', '/').strip()
        decoder_path = decoder_path.replace('\\', '/').strip()

        # Run the decoder
        reporter.run_decoder(decoder,
                             input_file,
                             timeout=options.timeout,
                             autonomous=options.autonomous,
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
            print reporter.pprint(output)
        else:
            reporter.output_text()


if __name__ == '__main__':
    main()
