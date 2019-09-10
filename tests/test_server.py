import io
import logging

import pytest

import kordesii
from kordesii.tools.server import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app()
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="module")
def decoders():
    return list(kordesii.iter_decoders())


@pytest.fixture
def sample_file_pointer(strings_exe):
    with io.open(str(strings_exe), "rb") as f:
        yield f


@pytest.fixture
def expected_results():
    return {
        u"debug": [
            u"[+] (kordesii.decoders.sample): Found XOR encrypt function at: 0x401000",
            u"[+] (kordesii.core): IDA return code = 0",
        ],
        u"error": [],
        u"output_text": (
            u"----Decoded Strings----\n\n"
            u"Hello World!\n"
            u"Test string with key 0x02\n"
            u"The quick brown fox jumps over the lazy dog.\n"
            u"Oak is strong and also gives shade.\n"
            u"Acid burns holes in wool cloth.\n"
            u"Cats and dogs each hate the other.\n"
            u"Open the crate but don't break the glass.\n"
            u"There the flood mark is ten inches.\n"
            u"1234567890\n"
            u"CreateProcessA\n"
            u"StrCat\n"
            u"ASP.NET\n"
            u"kdjsfjf0j24r0j240r2j09j222\n"
            u"32897412389471982470\n"
            u"The past will look brighter tomorrow.\n"
            u"Cars and busses stalled in sand drifts.\n"
            u"The jacket hung on the back of the wide chair.\n"
            u"32908741328907498134712304814879837483274809123748913251236598123056231895712\n\n"
            u"----Debug----\n\n"
            u"[+] (kordesii.decoders.sample): Found XOR encrypt function at: 0x401000\n"
            u"[+] (kordesii.core): IDA return code = 0\n"
        ),
        u"strings": [
            u"Hello World!",
            u"Test string with key 0x02",
            u"The quick brown fox jumps over the lazy dog.",
            u"Oak is strong and also gives shade.",
            u"Acid burns holes in wool cloth.",
            u"Cats and dogs each hate the other.",
            u"Open the crate but don't break the glass.",
            u"There the flood mark is ten inches.",
            u"1234567890",
            u"CreateProcessA",
            u"StrCat",
            u"ASP.NET",
            u"kdjsfjf0j24r0j240r2j09j222",
            u"32897412389471982470",
            u"The past will look brighter tomorrow.",
            u"Cars and busses stalled in sand drifts.",
            u"The jacket hung on the back of the wide chair.",
            u"32908741328907498134712304814879837483274809123748913251236598123056231895712",
        ],
    }


@pytest.fixture(scope="module")
def make_test_buffer():
    # The client closes the file-object when it's completed its request
    # so we need to be able to generate a new one when needed
    def _make_test_buffer():
        return io.BytesIO(b"This is a test file!\n")

    return _make_test_buffer


def test_homepage(client):
    """Test the homepage is accessible"""
    rv = client.get("/")
    assert rv.status_code == 200
    assert b"DC3-kordesii Service" in rv.data


def test_menu(client):
    """Test menu items can be added"""
    # Menu links can be created via adding to the config
    client.application.config["MENU_LINKS"].append(
        {"name": "Example", "url": "http://example.com"}
    )
    rv = client.get("/")
    assert b'<li><a href="/">Home</a></li>' in rv.data
    assert b'<li><a href="http://example.com">Example</a></li>' in rv.data


def test_log_endpoint(client):
    from kordesii import logutil

    rv = client.get("/logs")

    assert {
        "error": ["No 'kordesii_server' handler defined on root logger."]
    } == rv.json
    assert rv.status_code == 500

    list_handler = logutil.ListHandler()
    list_handler.name = "kordesii_server"
    logging.root.addHandler(list_handler)

    rv = client.get("/logs")
    assert rv.status_code == 200
    assert isinstance(rv.json, dict)
    assert "logs" in rv.json
    logging.root.removeHandler(list_handler)

    client.application.config["DISABLE_LOGS_ENDPOINT"] = True
    rv = client.get("/logs")
    assert rv.status_code == 403
    assert {"error": ["Logs endpoint has been disabled by configuration"]} == rv.json


@pytest.mark.in_ida
def test_decoder_strings(client, expected_results, sample_file_pointer):
    """Test decoder strings output"""
    rv = client.post(
        "/run_decoder",
        data={"decoder": "sample", "input_file": (sample_file_pointer, "strings.exe")},
    )
    assert rv.json["strings"] == expected_results["strings"]


def test_upload_options(client, decoders):
    """Test the upload page lists all decoders"""
    rv = client.get("/upload")

    option_str = '<option value="{name}">{name}</option>'

    for decoder in decoders:
        assert option_str.format(name=decoder.name).encode() in rv.data


def test_decoders(client, decoders):
    """Test the HTML decoders page lists the decoders"""
    import flask

    rv = client.get("/decoders")

    example_row = """\
            <tr>
                
                    <td>{name}</td>
                
                    <td>{source}</td>
                
                    <td>{description}</td>
                
            </tr>"""

    for decoder in decoders:
        # Each string must be escaped, this is esp. for descriptions
        escaped_info = {
            "name": flask.escape(decoder.name),
            "source": flask.escape(decoder.source.name),
            "description": flask.escape(decoder.description),
        }
        row = example_row.format(**escaped_info).encode()
        assert row in rv.data


def test_decoders_json(client, decoders):
    """Test the JSON decoders response lists all decoders"""
    rv = client.get("/decoders", headers={"Accept": "application/json"})

    assert rv.content_type == "application/json"
    assert isinstance(rv.json, dict)
    assert "decoders" in rv.json

    decoders_json = rv.json["decoders"]

    assert len(decoders_json) == len(decoders)

    for decoder in decoders:
        decoder_info = {
            "name": decoder.name,
            "source": decoder.source.name,
            "description": decoder.description,
        }
        assert decoder_info in decoders_json


def test_descriptions(client, decoders):
    """Test the legacy descriptions endpoint lists all decoders"""
    rv = client.get("/descriptions")
    assert "decoders" in rv.json
    decoders_descriptions = rv.json["decoders"]
    assert decoders_descriptions
    assert isinstance(decoders_descriptions, list)
    assert len(decoders_descriptions) == len(decoders)

    for idx, decoder in enumerate(decoders):
        assert decoders_descriptions[idx] == decoder.name
