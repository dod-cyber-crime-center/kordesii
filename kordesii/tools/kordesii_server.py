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

from bottle import Bottle, run, request, response

import kordesii

logger = logging.getLogger("kordesii-server")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


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
        return _run_decoder(decoder, data=data, filename=datafile.filename)
    else:
        logger.error("run_decoder %s no input file" % decoder)
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
        # NOTE: Only presenting name for backwards compatibility.
        output = {"decoders": [decoder.name for decoder in kordesii.iter_decoders()]}
        return json.dumps(output, indent=4)
    except Exception as e:
        output = {'error': traceback.format_exc()}
        logger.error("descriptions %s" % (traceback.format_exc()))
        return output


def _run_decoder(name, data, filename, append_output_text=True):
    logger.info("_run_decoder %s %s %s" % (name, filename, hashlib.md5(data).hexdigest()))
    try:
        reporter = kordesii.Reporter(base64outputfiles=True)

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
            logger.debug("Failed to purge server temp dir: %s, %s" % (tempdir, str(e)))

        # Format and return results
        output = reporter.metadata
        if reporter.errors:
            output["error"] = str(reporter.errors)
            for error in reporter.errors:
                logger.error("_run_decoder %s %s %s" % (name, filename, error))
        if append_output_text:
            output["output_text"] = reporter.get_output_text()

        return output

    except Exception as e:
        output = {'error': traceback.format_exc()}
        logger.error("_run_decoder %s %s %s" % (name, filename, traceback.format_exc()))
        return output


def main():
    kordesii.register_entry_points()
    run(app, server='auto', host='localhost', port=8081)


if __name__ == '__main__':
    main()
else:
    kordesii.register_entry_points()
    application = app
