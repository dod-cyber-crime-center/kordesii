"""
DC3-Kordesii framework command line tool.

Used for running and testing decoders.
"""

import datetime
import glob
import hashlib
import json
import logging
import os
import shutil
import sys
import timeit
import traceback

import click
import kordesii
import tabulate
from kordesii.tester import Tester

logger = logging.getLogger("kordesii")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-d", "--debug", is_flag=True, help="Enables DEBUG level logs.")
@click.option("-v", "--verbose", is_flag=True, help="Enables INFO level logs.")
@click.option(
    "--decoder-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Optional extra decoder directory.",
    envvar="KORDESII_DECODER_DIR",
    show_envvar=True,
)
@click.option(
    "--decoder-source",
    help="Set a default decoder source to use. " "If not, registered decoders from all sources will be available.",
    envvar="KORDESII_DECODER_SOURCE",
    show_envvar=True,
)
def main(debug, verbose, decoder_dir, decoder_source):
    # Setup logging
    kordesii.setup_logging()
    if debug:
        logging.root.setLevel(logging.DEBUG)
    elif verbose:
        logging.root.setLevel(logging.INFO)
    # else let log_config.yaml set log level.

    # Register parsers
    kordesii.register_entry_points()
    if decoder_dir:
        kordesii.register_decoder_directory(decoder_dir)

    if decoder_source:
        kordesii.set_default_source(decoder_source)


@main.command("list")
@click.option("-j", "--json", "json_", is_flag=True, help="Display as JSON output.")
def list_(json_):
    """Lists registered decoders."""
    descriptions = kordesii.get_decoder_descriptions()
    if json_:
        print(json.dumps(descriptions, indent=4))
    else:
        print(tabulate.tabulate(descriptions, headers=["NAME", "SOURCE", "AUTHOR", "DESCRIPTION"]))


@main.command()
@click.argument("decoder", required=True)
@click.argument("input", nargs=-1, type=click.Path())
@click.option("-j", "--json", "json_", is_flag=True, help="Display as JSON output.")
# TODO: We can't allow user to change decoder output directory until a bit more refactoring is done.
# @click.option('-o', '--output-dir', type=click.Path(exists=True, file_okay=False),
#               help='Output directory.')
@click.option(
    "--output-files/--no-output-files", default=True, show_default=True, help="Whether to output files to filesystem."
)
@click.option(
    "--cleanup/--no-cleanup", default=False, show_default=True, help="Whether to cleanup supplemental files after parsing."
)
@click.option(
    "-m",
    "--tempdir",
    type=click.Path(file_okay=False),
    help="Custom directory to store temporary files. Useful if you combine this with --no-cleanup.",
)
# Disassembler specific options:
@click.option("-e", "--enable-ida-log", is_flag=True, help="Include the log contents produced by IDA in the results.")
@click.option(
    "-t",
    "--timeout",
    type=int,
    default=0,
    show_default=True,
    help="Timeout for running IDA. A timeout of 0 disables the timeout.",
)
@click.option(
    "--64bit/--32bit",
    "is_64bit",
    default=None,
    help="Identifies if input file is 64 bit or 32 bit, which is used to determine whether to run ida64 or ida. "
         "If not provided, bitness is automatically determined by examining the input file."
)
def parse(decoder, input, json_, output_files, cleanup, tempdir, enable_ida_log, timeout, is_64bit):
    """
    Parses given input with given parser.

    \b
    DECODER: Name of decoder to run.
    INPUT: One or more input file paths. (Wildcards are allowed).

    \b
    Common usages::
        kordesii parse foo ./malware.bin                         - Run foo decoder on ./malware.bin
        kordesii parse foo ./repo/*                              - Run foo decoder on files found in repo directory.
        kordesii parse --json foo ./malware.bin                  - Run foo decoder and display results as json.
    """
    # Python won't process wildcards when used through Windows command prompt.
    if any("*" in path for path in input):
        new_input = []
        for path in input:
            if "*" in path:
                new_input.extend(glob.glob(path))
            else:
                new_input.append(path)
        input = new_input

    input_files = list(filter(os.path.isfile, input))
    if not input_files:
        sys.exit("Unable to find any input files.")

    # Run Kordesii
    try:
        reporter = kordesii.Reporter(tempdir=tempdir, disabletempcleanup=not cleanup)
        results = []
        for path in input_files:
            logger.info("Parsing: {}".format(path))
            input_file = os.path.abspath(path)
            reporter.run_decoder(
                decoder,
                input_file,
                timeout=timeout,
                log=enable_ida_log,
                cleanup_txt_files=cleanup,
                cleanup_idb_files=cleanup,
                cleanup_output_files=not output_files,
                is_64bit=is_64bit,
            )
            # TODO: Pull errors and ida logs from logger?
            result = reporter.metadata
            if reporter.errors:
                result["errors"] = reporter.errors
            if reporter.ida_log:
                result["ida_log"] = reporter.ida_log
            results.append(result)
            if not json_:
                reporter.print_report()

        if json_:
            print(json.dumps(results, indent=4))

    except Exception as e:
        error_message = "Error running DC3-Kordesii: {}".format(e)
        traceback.print_exc()
        if format == "json":
            print(json.dumps({"errors": [error_message]}))
        else:
            print(error_message)
        sys.exit(1)


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
        raise ValueError("No median for empty data.")
    elif length % 2 == 1:
        return data[length // 2]
    else:
        i = length // 2
        return (data[i - 1] + data[i]) / 2


def _run_tests(tester, silent=False, show_passed=False):
    print("Running test cases. May take a while...")

    start_time = timeit.default_timer()
    test_results = []
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
                run_time=test_result.run_time,
            )
            # Skip print() to immediately flush stdout buffer (issue in Docker containers)
            sys.stdout.write(message + "\n")
            sys.stdout.flush()
            if not test_result.passed or show_passed:
                test_result.print()

    end_time = timeit.default_timer()

    # Present test statistics
    if not silent and test_results:
        print("\nTest stats:")
        print("\nTop 10 Slowest Test Cases:")

        format_str = "{index:2}. " + msg_format

        # Cases sorted slowest first
        sorted_cases = sorted(test_results, key=lambda x: x.run_time, reverse=True)
        for i, test_result in enumerate(sorted_cases[:10], start=1):
            print(
                format_str.format(
                    index=i,
                    decoder=test_result.decoder_name,
                    filename=test_result.filename,
                    run_time=test_result.run_time,
                )
            )

        print("\nTop 10 Fastest Test Cases:")
        for i, test_result in enumerate(list(reversed(sorted_cases))[:10], start=1):
            print(
                format_str.format(
                    index=i,
                    decoder=test_result.decoder_name,
                    filename=test_result.filename,
                    run_time=test_result.run_time,
                )
            )

        run_times = [test_result.run_time for test_result in test_results]
        print("\nMean Running Time: {:.4f}s".format(sum(run_times) / len(test_results)))
        print("Median Running Time: {:.4f}s".format(_median(run_times)))
        print("Cumulative Running Time: {}".format(datetime.timedelta(seconds=sum(run_times))))
        print()

    print("Total Running Time: {}".format(datetime.timedelta(seconds=end_time - start_time)))

    if failed:
        print()
        print("Failed tests:")
        for test_info in failed:
            print("#{} - {}\t{}".format(*test_info))
        print()

    print("All Passed = {0}\n".format(not failed))
    exit(0 if not failed else 1)


def _get_malware_repo_path(file_path, malware_repo):
    """
    Gets file path for a file in the malware_repo based on the md5 of the given file_path.
    """
    with open(file_path, "rb") as fo:
        md5 = hashlib.md5(fo.read()).hexdigest()
    return os.path.join(malware_repo, md5[0:4], md5)


def _add_to_malware_repo(file_path, malware_repo):
    """
    Adds the given file path to the malware repo.
    Returns resulting destination path.
    """
    dest_path = _get_malware_repo_path(file_path, malware_repo)
    dest_dir = os.path.dirname(dest_path)

    if os.path.isfile(dest_path):
        click.echo("File already exists: {}".format(dest_path))
        return dest_path

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    click.echo("Copying {} to {}".format(file_path, dest_path))
    shutil.copy(file_path, dest_path)
    return dest_path


@main.command()
@click.option(
    "-t",
    "--testcase-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Directory containing JSON test case files. (defaults to a "
    '"tests" directory located within the root of the decoders directory)',
    envvar="KORDESII_TESTCASE_DIR",
    show_envvar=True,
)
@click.option(
    "-m",
    "--malware-repo",
    type=click.Path(file_okay=False),
    help="Directory containing malware samples used for testing.",
    envvar="KORDESII_MALWARE_REPO",
    show_envvar=True,
)
# Arguments used for run test cases.
@click.option(
    "-n", "--nprocs", type=int, help="Number of test cases to run simultaneously. [default: 3/4 * logical CPU cores]"
)
# Arguments used to generate and update test cases
@click.option("-u", "--update", is_flag=True, help="Update all stored test cases with newly produced results.")
@click.option(
    "-a",
    "--add",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Adds given file to the test case. (Will first copy file to malware repo if provided.)",
)
@click.option(
    "-i",
    "--add-filelist",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Adds a file of file paths separated by newlines to the test case.",
)
@click.option(
    "-x",
    "--delete",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Deletes given file from the test case. "
    "(Note, this does not delete the test file if placed in a malware repo.)",
)
@click.option("-y", "--yes", is_flag=True, help="Auto confirm questions.")
@click.option("--force", is_flag=True, help="Force test case add/update when errors are encountered.")
# Arguments to configure console output
@click.option(
    "-f",
    "--show-passed",
    is_flag=True,
    help="Display tests case details for passed tests as well." "By default only failed tests are shown.",
)
@click.option("-s", "--silent", is_flag=True, help="Limit output to statement saying whether all tests passed or not.")
# Decoder to process.
@click.argument("decoder", nargs=-1, required=False)
def test(
    testcase_dir, malware_repo, nprocs, update, add, add_filelist, delete, yes, force, show_passed, silent, decoder
):
    """
    Testing utility to create and execute decoder test cases.

    \b
    DECODER: Decoders to test. Test all decoders if not provided.

    \b
    Common usages::
        kordesii test                                             - Run all tests cases.
        kordesii test foo                                         - Run test cases for foo decoder.
        kordesii test foo -u                                      - Update existing test cases for foo decoder.
        kordesii test -u                                          - Update existing test cases for all decoders.
        kordesii test foo --add=./malware.bin                     - Add test case for malware.bin sample for foo parser.
        kordesii test foo --add-filelist=./paths.txt              - Add tests cases for foo decoder using text file of paths.
        kordesii test foo --delete=./malware.bin                  - Delete test case for malware.bin sample for foo parser.
    """
    # Configure test object
    reporter = kordesii.Reporter()
    tester = Tester(
        reporter,
        results_dir=testcase_dir,
        decoder_names=decoder or [None],
        nprocs=nprocs,
        malware_repo=malware_repo,
    )

    # Add/Delete
    if add or add_filelist or delete:
        if not decoder:
            # Don't allow adding a file to ALL test cases.
            raise click.BadParameter("DECODER must be provided when adding or deleting a file from a test case.")

        # Cast tuple to list so we can manipulate.
        add = list(add)
        for filelist in add_filelist:
            with open(filelist, "r") as f:
                for file_path in f.readlines():
                    add.append(file_path.rstrip("\n"))

        for file_path in add:
            click.echo("Adding new test cases. May take a while...")
            if malware_repo:
                file_path = _add_to_malware_repo(file_path, malware_repo)
            tester.add_test(file_path, force)

        for file_path in delete:
            if malware_repo:
                file_path = _get_malware_repo_path(file_path, malware_repo)
            tester.remove_test(file_path)

    # Update
    elif update:
        if not decoder and not yes:
            click.confirm("WARNING: About to update test cases for ALL decoders. Continue?", abort=True)
        click.echo("Updating test cases. May take a while...")
        tester.update_tests(force)

    # Run tests
    else:
        if not decoder and not yes:
            click.confirm("DECODER argument not provided. Run tests for ALL decoders?", default=True, abort=True)
        # Force ERROR level logs so we don't spam the console.
        logging.root.setLevel(logging.ERROR)
        _run_tests(tester, silent, show_passed)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="The interface to bind to.")
@click.option("--port", default=8081, show_default=True, help="The port to bind to.")
@click.option(
    "--debug", is_flag=True, help="Show the interactive debugger if errors occur, and auto-reload on code changes."
)
def serve(host, port, debug):
    """Run a server to handle parsing requests."""
    from kordesii.tools import server

    if debug:
        os.environ["FLASK_ENV"] = "development"

    app = server.create_app()
    app.run(host=host, port=port, use_reloader=False)


if __name__ == "__main__":
    main(sys.argv[1:])
