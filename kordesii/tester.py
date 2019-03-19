"""
Test case support for DC3-Kordesii. Decoder output is stored in a json file per decoder. To run test cases,
decoder is re-run and compared to previous results.
"""
from __future__ import print_function

from io import open

import json
import multiprocessing as mp

# Standard imports
import os
import logging
from timeit import default_timer

import kordesii.reporter
from kordesii import registry

logger = logging.getLogger(__name__)


FIELD_LAST_UPDATE = "last_update"

# Constants
INPUT_FILE_PATH = "input_file"
FILE_EXTENSION = ".json"
DECODER = "decoder"
RESULTS = "results"
PASSED = "passed"
ERRORS = "errors"
DEBUG = "debug"
IDA_LOG = "ida_log"
RUN_TIME = "run_time"


DEFAULT_EXCLUDE_FIELDS = [
    kordesii.reporter.FIELD_DEBUG,
    'idb',  # Legacy field that should no longer exists. TODO: remove in future version.
    FIELD_LAST_UPDATE
]

DEFAULT_INCLUDE_FIELDS = [
    kordesii.reporter.FIELD_STRINGS,
    kordesii.reporter.FIELD_FILES
]


def multiproc_test_wrapper(args):
    """Wrapper function for running tests in multiple processes."""
    test_case = args[0]
    try:
        return test_case.run(*args[1:])
    except KeyboardInterrupt:
        return


def multiproc_initializer(level, decoder_sources, default_source):
    """Multiproc initializer used to pass along log level and registry information."""
    registry._sources = decoder_sources
    registry._default_source = default_source
    logging.root.setLevel(level)


class Tester(object):
    """
    DC3-Kordesii Tester class
    """

    def __init__(self, reporter, results_dir=None, decoder_names=None, nprocs=None,
                 field_names=None, ignore_field_names=DEFAULT_EXCLUDE_FIELDS):
        """
        Run tests and compare produced results to expected results.

        :param kordesii.Reporter reporter: Kordesii reporter object
        :param str results_dir: Directory of json test cases
                (defaults to dynamically pulling from a "tests" folder within parser's directory.)
        :param [str] decoder_names:
                A list of decoder names to run tests for. If the list is empty (default),
                then test cases for all parsers will be run.
        :param [str] field_names:
                A restricted list of fields (metadata key values) that should be compared
                during testing. If the list is empty (default), then all fields, except those in
                ignore_field_names will be compared.
        :param int nprocs: Number of processes to use. (defaults to (3*num_cores)/4)
        """
        self.reporter = reporter
        self.results_dir = results_dir
        self.decoder_names = decoder_names or [None]
        self.field_names = field_names or []
        self.ignore_field_names = ignore_field_names
        self._test_cases = None
        self._results = []  # Cached results.
        self._processed = False
        self._nprocs = nprocs or (3 * mp.cpu_count()) // 4

    def __iter__(self):
        return self._iter_results()

    def _iter_results(self):
        # First yield any cached results.
        for result in self._results:
            yield result

        # Run tests in multiprocessing pool (if not already run)
        if not self._processed:
            self._processed = True
            log_level = logging.root.getEffectiveLevel()
            pool = mp.Pool(
                processes=self._nprocs, initializer=multiproc_initializer,
                initargs=(log_level, registry._sources, registry._default_source))
            test_iter = pool.imap_unordered(
                multiproc_test_wrapper, [(test_case,) for test_case in self.test_cases])
            pool.close()

            try:
                for result in test_iter:
                    self._results.append(result)
                    yield result
            except KeyboardInterrupt:
                pool.terminate()
                raise

    @property
    def test_cases(self):
        """Returns test cases."""
        if self._test_cases is not None:
            return self._test_cases

        self._test_cases = []
        for decoder_name in self.decoder_names:
            # We want to iterate decoders in cases decoder_name represents a set of decoders from
            # different sources.
            found = False
            for decoder in kordesii.iter_decoders(decoder_name):
                found = True
                results_file_path = self.get_results_filepath(decoder.full_name)
                if os.path.isfile(results_file_path):
                    for expected_results in self.parse_results_file(results_file_path):
                        # Add results_file_path for relative paths.
                        # NOTE: os.path.join will ignore the prefix we add if the second is not relative.
                        input_file_path = expected_results[INPUT_FILE_PATH]
                        input_file_path = os.path.join(os.path.dirname(results_file_path), input_file_path)
                        input_file_path = os.path.abspath(input_file_path)
                        expected_results[INPUT_FILE_PATH] = input_file_path

                        self._test_cases.append(TestCase(
                            self.reporter, decoder.full_name, expected_results,
                            field_names=self.field_names, ignore_field_names=self.ignore_field_names))
                else:
                    logger.warning('Test case file not found: {}'.format(results_file_path))

            if not found and decoder_name:
                # Add a failed result if we have an orphan test.
                self._results.append(TestResult(
                    decoder_name=decoder_name,
                    passed=False,
                    errors=['Decoder not found.']
                ))
        return self._test_cases

    @property
    def total(self):
        """Returns total number of results."""
        return len(self._results) + len(self.test_cases)

    def gen_results(self, decoder_name, input_file_path):
        """
        Generate JSON results for the given file using the given decoder name.
        """
        # Read in data so we avoid placing idb files in the malware repo.
        with open(input_file_path, 'rb') as f:
            data = f.read()
        self.reporter.run_decoder(decoder_name, data=data, log=True)
        self.reporter.metadata[INPUT_FILE_PATH] = input_file_path
        return self.reporter.metadata

    def get_results_filepath(self, decoder_name):
        """
        Get a results file path based on the decoder name provided and the
        previously specified output directory.
        """
        for decoder in kordesii.iter_decoders(decoder_name):
            file_name = decoder.name + FILE_EXTENSION
            # Use hardcoded results dir if requested.
            if self.results_dir:
                return os.path.join(self.results_dir, file_name)

            # Assume there is a "tests" folder within the source path.
            test_dir = os.path.join(decoder.source.path, 'tests')
            return os.path.normpath(os.path.join(test_dir, file_name))

        raise ValueError('Invalid parser: {}'.format(decoder_name))

    def parse_results_file(self, results_file_path):
        """
        Parse the the JSON results file and return the parsed data.
        """

        with open(results_file_path) as results_file:
            data = json.load(results_file)

        # The results file data is expected to be a list of metadata dictionaries
        if not isinstance(data, list) or not all(isinstance(a, dict) for a in data):
            raise ValueError('Results file is invalid: {}'.format(results_file_path))

        return data

    def update_tests(self):
        """
        Updates existing test cases by rerunning parsers.
        """
        orig_level = logging.root.level
        logging.root.setLevel(logging.INFO)  # Force info level logs so test cases stay consistent.
        try:
            for decoder_name in self.decoder_names:
                for decoder in kordesii.iter_decoders(decoder_name):
                    results_file_path = self.get_results_filepath(decoder.full_name)
                    if not os.path.isfile(results_file_path):
                        logger.warning('No test case file found for parser: {}')
                        continue
                    for results in self.parse_results_file(results_file_path):
                        input_file = results[INPUT_FILE_PATH]
                        metadata = self.gen_results(decoder.full_name, input_file)
                        if not metadata:
                            logger.warning('Empty results for {} in {}, not updating.'.format(input_file, results_file_path))
                        if not self.reporter.errors:
                            logger.info('Updating results for {} in {}'.format(input_file, results_file_path))
                            self._update_test_results(results_file_path, metadata, replace=True)
        finally:
            logging.root.setLevel(orig_level)

    def add_test(self, file_path):
        """Adds test case for given file path."""
        orig_level = logging.root.level
        logging.root.setLevel(logging.INFO)  # Force info level logs so test cases stay consistent.
        try:
            for decoder_name in self.decoder_names:
                for decoder in kordesii.iter_decoders(decoder_name):
                    results_file_path = self.get_results_filepath(decoder.full_name)
                    metadata = self.gen_results(decoder.full_name, file_path)
                    if not metadata:
                        logger.warning('Empty results for {} in {}, not adding.'.format(file_path, results_file_path))
                    if not self.reporter.errors:
                        logger.info('Adding results for {} in {}'.format(file_path, results_file_path))
                        self._update_test_results(results_file_path, metadata, replace=True)
        finally:
            logging.root.setLevel(orig_level)

    def remove_test(self, file_path):
        """Removes test case for given file path."""
        for decoder_name in self.decoder_names:
            for decoder in kordesii.iter_decoders(decoder_name):
                results_file_path = self.get_results_filepath(decoder.full_name)
                results_file_data = []
                for metadata in self.parse_results_file(results_file_path):
                    if metadata[INPUT_FILE_PATH] == file_path:
                        logger.info('Removed results for {} in {}'.format(file_path, results_file_path))
                    else:
                        results_file_data.append(metadata)

                with open(results_file_path, 'w', encoding='utf8') as results_file:
                    results_file.write(str(json.dumps(results_file_data, results_file, indent=4, sort_keys=True)))

    def _update_test_results(self, results_file_path, results_data, replace=True):
        """
        Update results in the results file with the passed in results data. If the
        file path for the results data matches a file path that is already found in
        the passed in results file, then the replace argument comes into play to
        determine if the record should be replaced.
        """
        # The results data is expected to be a dictionary representing results
        # for a single file
        assert isinstance(results_data, dict)

        if os.path.isfile(results_file_path):
            results_file_data = self.parse_results_file(results_file_path)

            # Check if there is a duplicate file path already in the results
            # path
            for index, metadata in enumerate(results_file_data):
                if metadata[INPUT_FILE_PATH] == results_data[INPUT_FILE_PATH]:
                    if replace:
                        results_file_data[index] = results_data
                    break
            else:
                # If no duplicate found, then append the passed in results data to
                # existing results
                results_file_data.append(results_data)
        else:
            # Results file should be a list of metadata dictionaries
            results_file_data = [results_data]

        # Write updated data to results file
        # NOTE: We need to use dumps instead of dump to avoid TypeError.
        with open(results_file_path, 'w', encoding='utf8') as results_file:
            results_file.write(str(json.dumps(results_file_data, results_file, indent=4, sort_keys=True)))


class TestCase(object):

    def __init__(self, reporter, decoder_name, expected_results, field_names=None, ignore_field_names=None):
        self._reporter = reporter
        self.decoder_name = decoder_name
        self.expected_results = expected_results
        self.input_file_path = expected_results['input_file']
        self.filename = os.path.basename(self.input_file_path)
        self._field_names = field_names or []
        if ignore_field_names is None:
            ignore_field_names = DEFAULT_EXCLUDE_FIELDS
        self._ignore_field_names = ignore_field_names

    def run(self):
        """Run test case."""
        start_time = default_timer()

        # Read in data so we avoid placing idb files in the malware repo.
        with open(self.input_file_path, 'rb') as f:
            data = f.read()
        self._reporter.run_decoder(self.decoder_name, data=data, log=True)
        self._reporter.metadata[INPUT_FILE_PATH] = self.input_file_path
        results = self._reporter.metadata

        comparer_results = self._compare_results(self.expected_results, results)
        passed = all(comparer.passed for comparer in comparer_results)

        done_time = default_timer()
        run_time = done_time - start_time

        return TestResult(
            decoder_name=self.decoder_name,
            passed=passed,
            input_file_path=self.input_file_path,
            errors=self._reporter.errors,
            debug=self._reporter.metadata.get('debug', None),
            ida_log=self._reporter.ida_log,
            results=comparer_results,
            run_time=run_time,
        )

    def _compare_results(self, results_a, results_b):
        """
        Compare two result sets. If the field names list is not empty,
        then only the fields (metadata key values) in the list will be compared.
        ignore_field_names fields are not compared unless included in field_names.
        """
        results = []

        # Cursory check to remove FILE_INPUT_PATH key from results since it is
        # a custom added field for test cases
        if INPUT_FILE_PATH in results_a:
            results_a = dict(results_a)
            del results_a[INPUT_FILE_PATH]
        if INPUT_FILE_PATH in results_b:
            results_b = dict(results_b)
            del results_b[INPUT_FILE_PATH]

        # Begin comparing results
        if self._field_names:
            for field_name in self._field_names:
                try:
                    comparer = self._compare_results_field(results_a, results_b, field_name)
                except Exception as e:
                    comparer = ResultComparison(field_name)
                    logger.exception(e)
                results.append(comparer)

        else:
            for ignore_field in self._ignore_field_names:
                results_a.pop(ignore_field, None)
                results_b.pop(ignore_field, None)
            all_field_names = set(results_a.keys()).union(list(results_b.keys()))
            for field_name in all_field_names:
                try:
                    comparer = self._compare_results_field(results_a, results_b, field_name)
                except Exception as e:
                    comparer = ResultComparison(field_name)
                    logger.exception(e)
                results.append(comparer)

        return results

    def _compare_results_field(self, results_a, results_b, field_name):
        """
        Compare the values for a single results field in the two passed in results.
        """
        assert isinstance(results_a, dict) and isinstance(results_b, dict)
        comparer = ResultComparison(field_name)

        # Confirm key is found in at least one of the passed in result sets
        if field_name not in results_a and field_name not in results_b:
            return comparer

        # Compare results and return result
        result_a = results_a.get(field_name, [])
        result_b = results_b.get(field_name, [])

        # Compare results and return result
        comparer.compare(result_a, result_b)
        return comparer


class TestResult(object):

    def __init__(self, decoder_name, passed,
                 input_file_path=None, errors=None, debug=None, ida_log=None, results=None, run_time=None):
        self.decoder_name = decoder_name
        self.input_file_path = input_file_path or 'N/A'
        self.filename = os.path.basename(input_file_path) if input_file_path else 'N/A'
        self.passed = passed
        self.errors = errors or []
        self.debug = debug or []
        self.ida_log = ida_log or []
        self.results = results or []
        self.run_time = run_time or 0

    def print(self):
        """
        print test result based on provided parameters.
        """
        filtered_output = u""
        filtered_output += u"decoder: {}\n".format(self.decoder_name)
        filtered_output += u"input_file: {}\n".format(self.input_file_path)
        filtered_output += u"passed: {}\n".format(self.passed)
        # Add logs if failed.
        if not self.passed:
            filtered_output += u"errors: {}".format("\n" if self.errors else "None\n")
            if self.errors:
                for entry in self.errors:
                    filtered_output += u"\t{}\n".format(entry)
            filtered_output += u"debug: {}".format("\n" if self.debug else "None\n")
            if self.debug:
                for entry in self.debug:
                    filtered_output += u"\t{}\n".format(entry)
            if self.results:
                filtered_output += u"results:\n"
                for result in self.results:
                    if not result.passed:
                        filtered_output += u"{}\n".format(result)
            if self.errors:
                filtered_output += u"ida_log:\n{}\n".format(self.ida_log)
        filtered_output += u"\n"

        print(filtered_output)


class ResultComparison(object):

    def __init__(self, field):
        self.field = field
        self.passed = False
        self.missing = []  # Entries found in test case but not new results
        self.unexpected = []  # Entries found in new results but not test case

    def compare(self, test_case_results, new_results):
        """Compare two result sets and document any differences."""
        self.missing = []
        self.unexpected = []

        for item in test_case_results:
            if len(item) > 0 and item not in new_results:
                self.missing.append(item)

        for item in new_results:
            if len(item) > 0 and item not in test_case_results:
                self.unexpected.append(item)

        self.passed = not bool(self.missing or self.unexpected)

    def get_report(self, json=False, tabs=1):
        """
        If json parameter is False, get report as a string.
        If json parameter is True, get report as a dictionary.
        """
        if json:
            return self.__dict__
        else:
            tab = tabs * "\t"
            tab_1 = tab + "\t"
            tab_2 = tab_1 + "\t"
            report = tab + "{}:\n".format(self.field)
            report += tab_1 + "Passed: {}\n".format(self.passed)
            if self.missing:
                report += tab_1 + "Missing:\n"
                for item in self.missing:
                    report += tab_2 + "{!r}\n".format(item)
            if self.unexpected:
                report += tab_1 + "Unexpected:\n"
                for item in self.unexpected:
                    report += tab_2 + "{!r}\n".format(item)

            return report.rstrip()

    def __str__(self):
        return self.get_report()

    def __repr__(self):
        return self.__str__()


class MyEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__
