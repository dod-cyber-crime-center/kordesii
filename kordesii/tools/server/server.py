#!/usr/bin/env python
"""
DC3-Kordesii server--simple REST API using bottle framework. Can be used as a standalone server or in a wsgi server.

Requires bottle to be installed which can be done by putting bottle.py in the same directory as this file.
"""

import base64
import copy
import hashlib
import io
import json
import logging
import os
import shutil
import tempfile
import zipfile
from contextlib import contextmanager

import flask as f
import pygments
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.data import JsonLexer
from pygments.lexers.special import TextLexer
from werkzeug.utils import secure_filename

import kordesii
from kordesii import logutil

bp = f.Blueprint("kordesii", __name__)


def init_app(app):
    kordesii.register_entry_points()


@bp.route("/run_decoder/<decoder>", methods=["POST"], strict_slashes=False)
@bp.route("/run_decoder", methods=["POST"], strict_slashes=False)
def run_decoder(decoder=None):
    """
    Execute a decoder and return the results.

    The file should be uploaded in the field "input_file". For forward compatibility
    purposes, the file may also be in the "data" field. In the future, the "data" field
    will be the required field.

    The decoder must be specified in the `decoder` field, parameter, or in the resource name.

    The field `output` may be set to `zip` to download a ZIP
    file of the results and extracted components. By default the
    output is JSON.

    The field  or parameter `highlight` may also be set to return
    a formatted HTML page with the results.

    All fields (except `data`) may be set as URL parameters as well.

    :param str decoder: The name of the decoder to run
    """
    if "input_file" not in f.request.files:
        upload_name = "data"
    else:
        upload_name = "input_file"
    return _build_decoder_response(decoder, upload_name)


@bp.route("/decoders")
def decoders_list():
    """
    List of configured decoders with names, sources, authors, and descriptions.

    Normally an HTML table, but if `application/json` is the best mimetype set
    in the `Accept` header, the response will be in JSON.
    """
    name_filter = f.request.args.get("name", type=str)
    source_filter = f.request.args.get("source", type=str)

    headers = ("Name", "Source", "Description")
    decoders_info = kordesii.iter_decoders(name=name_filter, source=source_filter)
    decoder_list = [
        {
            "name": decoder_info.name,
            "source": decoder_info.source.name,
            "description": decoder_info.description,
        }
        for decoder_info in decoders_info
    ]

    if f.request.accept_mimetypes.best == "application/json":
        return f.jsonify({"decoders": decoder_list})

    f.g.title = "Decoders"
    return f.render_template("decoders.html", headers=headers, decoders=decoder_list)


@bp.route("/upload")
def upload():
    """Upload page"""
    f.g.title = "Upload"
    decoders_info = kordesii.iter_decoders()
    return f.render_template("upload.html", decoders=decoders_info)


@bp.route("/descriptions")
def descriptions():
    """
    List descriptions of decoder modules.
    This is for backwards compatibility purposes.
    Always a JSON response.
    """
    try:
        # NOTE: Only presenting name for backwards compatibility.
        output = {"decoders": [decoder.name for decoder in kordesii.iter_decoders()]}
    except Exception as e:
        output = {"error": str(e)}
        f.current_app.logger.exception("Error running descriptions: {}".format(e))

    return f.jsonify(output)


@bp.route("/logs")
def logs():
    """
    Endpoint for all logs from the current session.

    Always a JSON response.

    This can be disabled with the ``DISABLE_LOGS_ENDPOINT`` key
    in the app config.
    """
    if f.current_app.config.get("DISABLE_LOGS_ENDPOINT"):
        return (
            f.jsonify({"error": ["Logs endpoint has been disabled by configuration"]}),
            403,
        )

    handler = _get_existing_handler()
    if not handler:
        return (
            f.jsonify(
                {"error": ["No 'kordesii_server' handler defined on root logger."]}
            ),
            500,
        )
    return f.jsonify({"logs": handler.messages})


@bp.route("/")
def default():
    return f.render_template("base.html")


def _get_existing_handler(handler_name="kordesii_server"):
    """
    Retrieve an existing ListHandler by name from the root logger.
    """
    for handler in logging.root.handlers:
        if handler.name == handler_name and isinstance(handler, logutil.ListHandler):
            return handler


def _get_log_handler(handler_name="kordesii_server"):
    """
    Get the handler for the parser running.

    Attempts to get 'kordesii_server' handler from the root logger, and create
    a clean copy, keeping any formatters and level settings.

    If the handler does not exist, create a default handler.
    """
    handler = _get_existing_handler(handler_name)
    if handler:
        if isinstance(handler, logutil.ListHandler):
            new_handler = copy.copy(handler)
            new_handler.clear()
            return new_handler
        f.current_app.logger.warning(
            "Root handler '{}' is not a ListHandler.".format(handler_name)
        )

    f.current_app.logger.info(
        "No '{}' handler defined on root logger. Using default.".format(handler_name)
    )
    list_handler = logutil.ListHandler()
    list_handler.setFormatter(
        logging.Formatter("[%(level_char)s] (%(name)s): %(message)s")
    )
    list_handler.addFilter(logutil.LevelCharFilter())

    return list_handler


def _highlight(data, is_json=True):
    """
    Render an HTML page with a highlighted JSON string or plain text.

    :param data: Data to highlight, should be a string or JSON-able object
    :param is_json: If the data is a JSON string or can be converted into such
    :return: Response object with rendered template with highlighted data
    """
    if is_json and not isinstance(data, (str, bytes)):
        data = json.dumps(data, indent=2)

    # Pygments highlighting
    lexer = JsonLexer() if is_json else TextLexer()
    formatter = HtmlFormatter()
    highlight = pygments.highlight(data, lexer, formatter)

    return f.render_template(
        "results.html", highlight=highlight, extra_css=formatter.get_style_defs()
    )


@contextmanager
def _make_temp_folder(*args, **kwargs):
    tempdir = tempfile.mkdtemp(*args, **kwargs)

    yield tempdir

    try:
        shutil.rmtree(tempdir, ignore_errors=True)
    except Exception as e:
        f.current_app.logger.debug(
            "Failed to purge server temp dir: {}, {}".format(tempdir, str(e))
        )


def _build_zip(parser_results):
    """
    Build a ZIP file containing the results and artifacts of a parser run.

    Expects the **full** parser results, including ``output_text`` and ``files`` keys.

    The folder structure looks like this:

    .. code_block::

        kordesii_output.zip
        |
        |-results.json
        |-results.txt (this is ``output_text``)
        |
        |---files
            |
            |- ExtractedComponent1.exe
            |- ExtractedComponent2.dll


    :param parser_results:
    :return: A BytesIO buffer containing a ZIP file
    :rtype: io.BytesIO
    """
    zip_buf = io.BytesIO()

    encoded_files = parser_results.pop("files", [])
    output_text = parser_results.pop("output_text", "")

    zf = zipfile.ZipFile(
        zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
    )
    with zf:
        for file_obj in encoded_files:
            filename = file_obj[0]
            base64_data = file_obj[3]
            file_data = base64.b64decode(base64_data)
            zf.writestr(os.path.join("files", filename), file_data)

        zf.writestr("results.json", json.dumps(parser_results, indent=2))

        if not isinstance(output_text, bytes):
            output_text = output_text.encode("ascii", "backslashreplace")
        zf.writestr("results.txt", output_text)

    zip_buf.seek(0)
    return zip_buf


def _build_decoder_response(decoder=None, upload_name="input_file", **kwargs):
    """
    Build the response object for a decoder request.
    This function handles the form fields and/or URL parameters and
    returns an appropriate response object. This can be overridden
    (e.g. by specific endpoints) as a parameter.

    :param str decoder: The name of the decoder to run. Pulled from `decoder`
        URL parameter or form field if not specified.
    :return: Flask response object
    """
    output = kwargs.get("output", "") or f.request.values.get("output", "json")
    output = output.lower()
    if output not in ("json", "text", "zip"):
        f.current_app.logger.warning(
            "Unknown output type received: '{}'".format(output)
        )
        output = "json"
    highlight = kwargs.get("highlight") or f.request.values.get("highlight")

    if not highlight:
        json_response = f.jsonify
    else:
        json_response = _highlight

    parser_results, response_code = _run_decoder_request(decoder, upload_name)

    if response_code != 200:
        return json_response(parser_results), response_code

    # A ZIP returns both JSON and plain text, and has no highlighting
    if output == "zip":
        filename = secure_filename(f.request.files.get(upload_name).filename)
        zip_buf = _build_zip(parser_results)
        return f.send_file(
            zip_buf, "application/zip", True, "{}_kordesii_output.zip".format(filename)
        )

    if highlight:
        parser_results.pop("files", [])
        output_text = parser_results.pop("output_text", "")
        if output == "text":
            return _highlight(output_text, False)

    return json_response(parser_results)


def _run_decoder_request(decoder=None, upload_name="input_file", output_text=True):
    """
    Run a decoder based on the data in the current request.

    This function handles getting the file from the form field, as well as
    the decoder from either a form field or url parameter if not explicitly set.

    The results from the decoder run (a ``dict``) is returned as well as an
    appropriate HTTP status code. Specifically, a 2XX if the decoder ran
    successfully, a 4XX if there is a problem with the request (e.g no
    file) or a 5XX if there was a problem with running the decoder.

    :param str decoder: The name of the decoder to run. Pulled from `decoder`
        URL parameter or form field if not specified.
    :param str upload_name: The name of the field of the uploaded sample
    :param bool output_text: If the `output_text` key should be included in the output
    :return: The results from the decoder run and/or errors and an appropriate status code
    :rtype: (dict, int)
    """
    errors = []

    decoder = decoder or f.request.values.get("decoder")
    if not decoder:
        errors.append("No decoder specified")

    uploaded_file = f.request.files.get(upload_name)
    if not uploaded_file:
        f.current_app.logger.error(
            "Error running decoder '{}' no input file".format(decoder)
        )
        errors.append("No input file provided")

    # Client errors
    if errors:
        return {"error": errors}, 400

    data = uploaded_file.read()
    f.current_app.logger.info(
        "Request for decoder '%s' on '%s' %s",
        decoder,
        secure_filename(uploaded_file.filename),
        hashlib.md5(data).hexdigest(),
    )
    decoder_results = _run_decoder(
        decoder,
        data=data,
        filename=uploaded_file.filename,
        append_output_text=output_text,
    )

    return decoder_results, 500 if decoder_results.get("error") else 200


def _run_decoder(name, data, filename, append_output_text=True):
    output = {}
    kordesii_logger = logging.getLogger()
    list_handler = _get_log_handler()
    try:
        kordesii_logger.addHandler(list_handler)
        reporter = kordesii.Reporter(base64outputfiles=True)

        with _make_temp_folder(prefix="kordesii-server_tempdir-") as tempdir:

            # Since we want the marked up IDB returned using the original filename, we
            # want to pass in a file to the reporter instead of data.
            file_path = os.path.join(tempdir, filename)
            with open(file_path, "wb") as fp:
                fp.write(data)

            # Run decoder
            reporter.run_decoder(name, filename=file_path)

        # Format and return results
        output = reporter.metadata

        output["debug"] = [msg for msg in list_handler.messages]
        # To stay consistent with the current major version API, "error" is singular.
        output["error"] = reporter.errors

        if append_output_text:
            output["output_text"] = reporter.get_output_text()

    except Exception as e:
        output = {"error": [str(e)]}
        if f.has_app_context():
            f.current_app.logger.exception(
                "Error running decoder '{}': {}".format(name, str(e))
            )
    finally:
        return output
