#!/usr/bin/env python
"""
DC3-Kordesii server--simple REST API using bottle framework. Can be used as a standalone server or in a wsgi server.

Requires bottle to be installed which can be done by putting bottle.py in the same directory as this file.
"""

import os
import sys
import traceback
import json
import logging
import hashlib
import subprocess
import tempfile
import shutil

local_path = os.path.dirname(__file__)
if local_path not in sys.path:
    sys.path.append(local_path)

from kordesii.kordesiireporter import kordesiireporter
from kordesii import decoders
from bottle import Bottle, run, request, response

logger = logging.getLogger("kordesii-server")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

DECODER_DIR = os.path.dirname(decoders.__file__)

DEFAULT_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html>
        <head>
            <title>DC3-Kordesii Service</title>
        </head>
        <body>
            <h2>DC3-Kordesii Service</h2>
            <br />
            <a href="descriptions">Module Descriptions</a>
        </body>
    </html>"""

app = Bottle()


@app.get('/git_hash')
def git_hash():
    """
    Run git status on repo.
    """
    return __run_git_command("rev-parse HEAD")


@app.get('/git_update')
def git_update():
    """
    Update master branch of repo.
    """
    __run_git_command("checkout master")
    return __run_git_command("pull")


def __run_git_command(command):
    """
    Command should be a string of basic git options to use.
    Examples:
        status
        rev-parse HEAD
    The function will run the provided git command and specify the repository
    based on this server files location.
    """
    git_work_dir = os.path.dirname(os.path.realpath(__file__))
    options = command.split(" ")
    args = ['git', '-C', git_work_dir] + options

    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        errors = []
        if len(error) > 0:
            errors.append(error)
        return {"output": output.strip(), "errors": errors}
    except:
        return {"output": None, "errors": [traceback.format_exc()]}


@app.post('/run_decoder/<decoder>')
def run_decoder(decoder):
    """
    Execute a decoder

    decoder (url component): kordesii decoder to use
    data (form file submission): data on which decoder operates
    """
    output = {}
    datafile = request.files.get('input_file')
    if datafile:
        data = datafile.file.read()
        logger.info("run_decoder %s %s %s" % (decoder, datafile.filename, hashlib.md5(data).hexdigest()))
        return __run_decoder(decoder, data=data, filename=datafile.filename)
    else:
        logger.error("run_decoder %s no input file" % (decoder))
    return {'error': 'No input file provided'}


@app.get('/')
def default():
    return DEFAULT_PAGE


@app.get('/descriptions')
def descriptions():
    """
    List descriptions of decoder modules
    """
    try:
        response.content_type = "application/json"
        reporter = kordesiireporter(decoderdir=DECODER_DIR, base64outputfiles=True)
        output = {}
        output["decoders"] = reporter.list_decoders()
        return reporter.pprint(output)
    except Exception as e:
        output = {}
        output['error'] = traceback.format_exc()
        logger.error("descriptions %s" % (traceback.format_exc()))
        return output


def __run_decoder(name, data, filename, append_output_text=True):
    output = {}
    logger.info("__run_decoder %s %s %s" % (name, filename, hashlib.md5(data).hexdigest()))
    try:
        reporter = kordesiireporter(decoderdir=DECODER_DIR, base64outputfiles=True)

        # Since we want the marked up IDB returned using the original filename, we
        # want to pass in a file to the reporter instead of data.
        tempdir = tempfile.mkdtemp(prefix="kordesii-server_tempdir-")
        file_path = os.path.join(tempdir, filename)
        with open(file_path, "wb") as f:
            f.write(data)

        # Run decoder
        reporter.run_decoder(name, filename=file_path)

        # Since we used our own temp directory to pass in a file, we have to
        # clean it up manually.
        try:
            shutil.rmtree(tempdir, ignore_errors=True)
        except Exception as e:
            reporter.debug("Failed to purge server temp dir: %s, %s" % (tempdir, str(e)))

        # Format and return results
        output = reporter.metadata
        if reporter.errors:
            output["error"] = str(reporter.errors)
            for error in reporter.errors:
                logger.error("__run_decoder %s %s %s" % (name, filename, error))
        if append_output_text:
            output["output_text"] = reporter.get_output_text()

        return output

    except Exception as e:
        output = {}
        output['error'] = traceback.format_exc()
        logger.error("__run_decoder %s %s %s" % (name, filename, traceback.format_exc()))
        return output


def main():
    global DECODER_DIR
    import argparse
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--decoderdir', help='Decoder directory to use.')
    options = argparser.parse_args()

    if options.decoderdir:
        if not os.path.isdir(options.decoderdir):
            raise IOError('Unable to find decoder dir: {}'.format(options.decoderdir))
        DECODER_DIR = options.decoderdir
    run(app, server='auto', host='localhost', port=8081)


if __name__ == '__main__':
    main()
else:
    application = app
