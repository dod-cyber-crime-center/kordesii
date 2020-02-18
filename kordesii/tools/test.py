#!/usr/bin/env python
"""
DC3-Kordesii Framework test case tool
"""
from __future__ import print_function, division

# Standard imports
import argparse
import datetime
import logging
import sys
import timeit

# DC3-kordesii framework imports
import kordesii
from kordesii.reporter import Reporter
from kordesii.tester import DEFAULT_EXCLUDE_FIELDS
from kordesii.tester import Tester


def _median(data):
    """
    'Borrowed' from Py3's statistics library.

    :param data: Data to get median of
    :return: Median as a float or int
    :rtype: float or int
    """
    data = sorted(data)
    length = len(data)
    if length == 0:
        raise ValueError('No median for empty data.')
    elif length % 2 == 1:
        return data[length // 2]
    else:
        i = length // 2
        return (data[i - 1] + data[i]) / 2


def get_arg_parser():
    """ Define command line arguments and return argument decoder. """

    description = """DC3-kordesii Framework: testing utility to create test cases and execute them.

Common usages:

$ kordesii-test.py -taf                                 Run all test cases and only show failed cases 
$ kordesii-test.py -p decoder -tf                       Run test cases for single decoder 
$ kordesii-test.py -p decoder -u                        Update existing test cases for a decoder 
$ kordesii-test.py -p decoder -i file_paths_file        Add new test cases for a decoder 
$ kordesii-test.py -p decoder -i file_paths_file -d     Delete test cases for a decoder 
"""
    decoder = argparse.ArgumentParser(description=description,
                                      formatter_class=argparse.RawDescriptionHelpFormatter,
                                      usage='%(prog)s [options]')

    # Required arguments
    # TODO: dynamically pull tests based on source.
    decoder.add_argument("-o",
                         default=None,
                         type=str,
                         dest="test_case_dir",
                         help="Directory containing JSON test case files. Defaults to a 'tests' folder in the"
                              "root of your decoders directory"),
    decoder.add_argument('--decoderdir',
                         action='store',
                         metavar='DIR',
                         default=None,
                         dest='decoderdir',
                         help='Optional extra decoder directory')
    decoder.add_argument("--decodersource",
                         metavar="SOURCE_NAME",
                         default=None,
                         dest="decodersource",
                         help="Set a default decoder source to use. "
                              "If not provided decoders from all sources will be available.")

    # Arguments used to run test cases
    decoder.add_argument("-t",
                         default=False,
                         dest="run_tests",
                         action="store_true",
                         help="Run test cases.")
    decoder.add_argument("-p",
                         type=str,
                         dest="decoder_name",
                         default="",
                         help="Decoder name.")
    decoder.add_argument("-k",
                         type=str,
                         dest="field_names",
                         default="",
                         help="Fields (csv) to compare results for.")
    decoder.add_argument("-x",
                         type=str,
                         dest="exclude_field_names",
                         default=",".join(DEFAULT_EXCLUDE_FIELDS),
                         help="Fields (csv) excluded from test cases/comparisons. default: %(default)s")
    decoder.add_argument("-n",
                         type=int,
                         dest="nprocs",
                         default=None,
                         help="Number of test cases to run simultaneously. Default: 3/4 * logical CPU cores.")
    decoder.add_argument("--debug",
                         action="store_true",
                         default=False,
                         dest="debug",
                         help="Turn on all debugging messages. (WARNING: This WILL spam the console)")

    # Arguments used to generate and update test cases
    decoder.add_argument("-i",
                         dest="input_file",
                         type=str,
                         default=None,
                         help="Input text file with one file path per line. The file paths will be used to create "
                              "or delete test cases depending on other arguments.")
    decoder.add_argument("-u",
                         default=False,
                         dest="update",
                         action="store_true",
                         help="Update all stored test cases with newly produced results.")
    decoder.add_argument("-a",
                         default=False,
                         dest="all_tests",
                         action="store_true",
                         help="Select all available decoders, used with -t to test all decoders.")
    decoder.add_argument("-d",
                         default=False,
                         dest="delete",
                         action="store_true",
                         help="Delete file(s) from test cases")
    parser.add_argument("--force",
                        default=False,
                        dest="force",
                        action="store_true",
                        help="Force test case add/update when errors are encountered.")

    # Arguments to configure console output
    decoder.add_argument("-f",
                         default=False,
                         action="store_true",
                         dest="only_failed_tests",
                         help="Display only failed test case details.")
    decoder.add_argument("-j",
                         default=False,
                         action="store_true",
                         dest="json",
                         help="JSON formatted output.")
    decoder.add_argument("-s",
                         default=False,
                         action="store_true",
                         dest="silent",
                         help="Limit output to statement saying whether all tests passed or not.")

    decoder.add_argument("--fail-fast",
                         default=False,
                         action='store_true',
                         help="Stop tests after the first failure.")

    return decoder


def main():
    """ Run tool. """

    print('')

    # Get command line arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # Setup logging
    kordesii.setup_logging()
    if args.debug:
        logging.root.setLevel(logging.DEBUG)
    else:
        logging.root.setLevel(logging.ERROR)  # By default, ignore all warning, info, and debug messages.

    # Register decoders
    kordesii.register_entry_points()
    if args.decoderdir:
        kordesii.register_decoder_directory(args.decoderdir)
    if args.decodersource:
        kordesii.set_default_source(args.decodersource)

    # Configure reporter based on args
    reporter = Reporter()

    # Configure test object
    if args.all_tests or not args.decoder_name:
        decoders = [None]
    else:
        decoders = [args.decoder_name]

    tester = Tester(
        reporter,
        results_dir=args.test_case_dir,
        decoder_names=decoders,
        nprocs=args.nprocs,
        field_names=filter(None, args.field_names.split(",")),
        ignore_field_names=filter(None, args.exclude_field_names.split(","))
    )

    # Gather all our input files
    input_files = []
    if args.input_file:
        input_files = read_input_list(args.input_file)

    # Add/Delete
    if args.delete or args.update:
        if not args.decoder_name:
            sys.exit('Decoder must be provided when adding or deleting a file from a test case.')
        for input_file in input_files:
            if args.delete:
                tester.remove_test(input_file)
            else:
                tester.add_test(input_file, args.force)

    # Update
    elif args.update:
        if not args.decoder_name:
            sys.exit('Decoder must be provided when updating a test case.')
        tester.update_tests(args.force)

    # Default is to run test cases
    else:
        _run_tests(tester, silent=args.silent, show_passed=not args.only_failed_tests)


def _run_tests(tester, silent=False, show_passed=False):
    print("Running test cases. May take a while...")

    start_time = timeit.default_timer()
    test_results = []
    all_passed = True
    total = tester.total
    failed = []

    # Generate format string.
    digits = len(str(total))
    if not tester.test_cases:
        decoder_len = 10
        filename_len = 10
    else:
        decoder_len = max(len(test_case.decoder_name) for test_case in tester.test_cases)
        filename_len = max(len(test_case.filename) for test_case in tester.test_cases)
    msg_format = "{{decoder:{0}}} {{filename:{1}}} {{run_time:.4f}}s".format(decoder_len, filename_len)

    format_str = "{{count:> {0}d}}/{{total:0{0}d}} - ".format(digits) + msg_format

    # Run tests and output progress results.
    for count, test_result in enumerate(tester, start=1):
        all_passed &= test_result.passed
        if not test_result.passed:
            failed.append((count, test_result.decoder_name, test_result.filename))

        if test_result.run_time:  # Ignore missing tests from stat summary.
            test_results.append(test_result)

        if not silent:
            message = format_str.format(
                count=count,
                total=total,
                decoder=test_result.decoder_name,
                filename=test_result.filename,
                run_time=test_result.run_time
            )
            # Skip print() to immediately flush stdout buffer (issue in Docker containers)
            sys.stdout.write(message + '\n')
            sys.stdout.flush()
            if not test_result.passed or show_passed:
                test_result.print()

    end_time = timeit.default_timer()

    # Present test statistics
    if not silent and test_results:
        print('\nTest stats:')
        print('\nTop 10 Slowest Test Cases:')

        format_str = "{index:2}. " + msg_format

        # Cases sorted slowest first
        sorted_cases = sorted(test_results, key=lambda x: x.run_time, reverse=True)
        for i, test_result in enumerate(sorted_cases[:10], start=1):
            print(format_str.format(
                index=i,
                decoder=test_result.decoder_name,
                filename=test_result.filename,
                run_time=test_result.run_time
            ))

        print('\nTop 10 Fastest Test Cases:')
        for i, test_result in enumerate(list(reversed(sorted_cases))[:10], start=1):
            print(format_str.format(
                index=i,
                decoder=test_result.decoder_name,
                filename=test_result.filename,
                run_time=test_result.run_time
            ))

        run_times = [test_result.run_time for test_result in test_results]
        print('\nMean Running Time: {:.4f}s'.format(
            sum(run_times) / len(test_results)
        ))
        print('Median Running Time: {:.4f}s'.format(
            _median(run_times)
        ))
        print('Cumulative Running Time: {}'.format(datetime.timedelta(seconds=sum(run_times))))
        print()

    print("Total Running Time: {}".format(datetime.timedelta(seconds=end_time - start_time)))

    if failed:
        print()
        print("Failed tests:")
        for test_info in failed:
            print("#{} - {}\t{}".format(*test_info))
        print()

    print("All Passed = {0}\n".format(all_passed))
    exit(0 if all_passed else 1)


def read_input_list(filename):
    inputfilelist = []
    if filename:
        if filename == "-":
            inputfilelist = [line.rstrip() for line in sys.stdin]
        else:
            with open(filename, "rb") as f:
                inputfilelist = [line.rstrip() for line in f]

    return inputfilelist


if __name__ == "__main__":
    main()
