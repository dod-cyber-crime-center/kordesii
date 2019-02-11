#!/usr/bin/env python
"""
DC3-Kordesii Framework test case tool
"""
from __future__ import print_function, division

# Standard imports
import argparse
import datetime
import json
import logging
import os
import locale
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
    decoder.add_argument("-o",
                         default=os.path.join(os.path.dirname(kordesii.__file__), "decodertests"),
                         type=str,
                         dest="test_case_dir",
                         help="Directory containing JSON test case files.")

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

    # Configure reporter based on args
    reporter = Reporter(enableidalog=True)

    # Configure test object
    tester = Tester(reporter=reporter, results_dir=args.test_case_dir)

    valid_decoder_names = reporter.list_decoders()

    decoders = []
    if args.decoder_name:
        if args.decoder_name in valid_decoder_names:
            decoders = [args.decoder_name]
        else:
            print("Error: Invalid decoder name(s) specified. decoder names are case sensitive.")
            exit(1)
    if args.all_tests:
        decoders = valid_decoder_names

    if not decoders:
        print("You must specify the decoder to test (or test all decoders)")
        exit(2)

    if args.decoder_name:
        results_file_path = tester.get_results_filepath(args.decoder_name)

    # Gather all our input files
    input_files = []
    if args.input_file:
        input_files = read_input_list(args.input_file)

    # Default is to run test cases
    if args.run_tests:
        print("Running test cases. May take a while...")
        start_time = timeit.default_timer()
        test_infos = []
        json_list = []
        all_passed = True
        for passed, test_result, test_info in tester.run_tests(
                decoders, filter(None, args.field_names.split(",")),
                ignore_field_names=filter(None, args.exclude_field_names.split(",")),
                nprocs=args.nprocs):
            test_infos.append(test_info)
            if not passed:
                all_passed = False
            if not args.silent:
                sys.stdout.write(
                    "{finished}/{total} - {decoder} {filename} {run_time:.4f}s\n".format(**test_info)
                )
                sys.stdout.flush()
                if not passed or not args.only_failed_tests:
                    # TODO: Refactor support for json.
                    if args.json:
                        json_list.append(tester.format_test_result(test_result, json_format=True))
                    else:
                        display = tester.format_test_result(test_result)
                        print(display.encode(locale.getpreferredencoding(), 'replace'))

        if args.json:
            print(json.dumps(json_list))

        # Don't count calculating the stats and printing them as test running time
        end_time = timeit.default_timer()

        if not args.silent:
            print('\nTest stats:')
            print('\nTop 10 Slowest Test Cases:')
            # Cases sorted slowest first
            sorted_cases = sorted(test_infos, key=lambda x: x['run_time'], reverse=True)
            for i, info in enumerate(sorted_cases[:10]):
                print('{:2}. {} {} {:.4f}s'.format(i + 1, info['decoder'], info['filename'], info['run_time']))

            print('\nTop 10 Fastest Test Cases:')
            for i, info in enumerate(list(reversed(sorted_cases))[:10]):
                print('{:2}. {} {} {:.4f}s'.format(i + 1, info['decoder'], info['filename'], info['run_time']))

            run_times = [info['run_time'] for info in test_infos]
            print('\nMean Running Time: {:.4}s'.format(
                sum(run_times) / len(test_infos)
            ))
            print('Median Running Time: {:.4f}s'.format(
                _median(run_times)
            ))
            print()

        print("Total Running Time: {}".format(datetime.timedelta(seconds=end_time - start_time)))
        print("All Passed = {0}\n".format(all_passed))
        exit(0 if all_passed else 1)

    # add files to test cases
    elif args.decoder_name and args.delete:
        removed_files = tester.remove_test_results(args.decoder_name, input_files)
        for filename in removed_files:
            print("Removing results for %s in %s" % (filename, results_file_path))
    elif args.decoder_name and (args.update or (not args.delete and input_files)):
        if args.update:
            input_files.extend(tester.list_test_files(args.decoder_name))

        for input_file in input_files:
            tester.gen_results(decoder_name=args.decoder_name, input_file_path=input_file)

            if len(reporter.metadata) > 1 and len(reporter.errors) == 0:
                print("Updating results for %s in %s" % (input_file, results_file_path))
                tester.update_test_results(results_file_path=results_file_path,
                                           results_data=reporter.metadata,
                                           replace=True)
            elif len(reporter.metadata) > 1 and len(reporter.errors) > 0:
                print("Error occurred for %s in %s, not updating: " % (input_file, results_file_path))
                print("\n".join(reporter.get_debug()))
                print("\n".join(reporter.errors))
            else:
                print("Empty results for %s in %s, not updating" % (input_file, results_file_path))
    else:
        argparser.print_help()


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
