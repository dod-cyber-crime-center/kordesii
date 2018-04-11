#!/usr/bin/env python
'''
DC3-Kordesii Framework test case tool
'''

# Standard imports
import argparse
import os
import sys

# DC3-kordesii framework imports
import kordesii
from kordesii.kordesiitester import kordesiitester
from kordesii.kordesiireporter import kordesiireporter
from kordesii.kordesiitester import DEFAULT_EXCLUDE_FIELDS
from kordesii.kordesiitester import DEFAULT_INCLUDE_FIELDS


def get_arg_parser():
    ''' Define command line arguments and return argument decoder. '''

    description = '''DC3-kordesii Framework: testing utility to create test cases and execute them.

Common usages:

$ kordesii-test.py -taf                                 Run all test cases and only show failed cases 
$ kordesii-test.py -p decoder -tf                       Run test cases for single decoder 
$ kordesii-test.py -p decoder -u                        Update existing test cases for a decoder 
$ kordesii-test.py -p decoder -i file_paths_file        Add new test cases for a decoder 
$ kordesii-test.py -p decoder -i file_paths_file -d     Delete test cases for a decoder 
'''
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

    # Arguments used to generate and update test cases
    decoder.add_argument("-i",
                         dest="input_file",
                         type=str,
                         default=None,
                         help="Input text file with one file path per line. The file paths will be used to create or delete test cases depending on other arguments.")
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
    ''' Run tool. '''

    print ''

    # Get command line arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # Configure reporter based on args
    reporter = kordesiireporter(enableidalog=True)

    # Configure test object
    tester = kordesiitester(reporter=reporter, results_dir=args.test_case_dir)

    valid_decoder_names = reporter.list_decoders()

    decoders = []
    if args.decoder_name:
        if args.decoder_name in valid_decoder_names:
            decoders = [args.decoder_name]
        else:
            print "Error: Invalid decoder name(s) specified. decoder names are case sensitive."
            exit(1)
    if args.all_tests:
        decoders = valid_decoder_names

    if not decoders:
        print "You must specify the decoder to test (or test all decoders)"
        exit(2)

    if args.decoder_name:
        results_file_path = tester.get_results_filepath(args.decoder_name)

    # Gather all our input files
    input_files = []
    if args.input_file:
        input_files = read_input_list(args.input_file)

    # Default is to run test cases
    if args.run_tests:
        print "Running test cases. May take a while..."
        all_passed, test_results = tester.run_tests(decoders, filter(None, args.field_names.split(",")),
                                                    ignore_field_names=filter(None,
                                                                              args.exclude_field_names.split(",")))
        print "All Passed = {0}\n".format(all_passed)
        if not args.silent:
            if args.only_failed_tests:
                tester.print_test_results(test_results,
                                          failed_tests=True,
                                          passed_tests=False,
                                          json_format=args.json)
            else:
                tester.print_test_results(test_results,
                                          failed_tests=True,
                                          passed_tests=True,
                                          json_format=args.json)
        if all_passed:
            exit(0)
        else:
            exit(1)

    # add files to test cases
    elif args.delete:
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
                print("Error occurred for %s in %s, not updating" % (input_file, results_file_path))
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