"""
Example (and functional) interface (in this case CLI) that submits files to kordesii-server.
"""

import base64
import httplib
import json
import optparse
import os
import sys
import urllib2
import uuid
import warnings

USAGE = 'USAGE: kordesii-client [options] DECODER INPUT_FILE'


def make_opt_parser():
    opt_parse = optparse.OptionParser(USAGE)
    opt_parse.add_option('-o', '--out',
                         action='store',
                         default='',
                         dest='output_dir',
                         help='The directory the output file(s) will be written in.')
    opt_parse.add_option('-H', '--host',
                         action='store',
                         type='string',
                         metavar='HOST',
                         default='localhost:8081',
                         dest='host',
                         help='kordesii-server host [default: %default]')
    opt_parse.add_option('-l', '--list',
                         action='store_true',
                         default=False,
                         dest='list',
                         help='List all string decoders')
    opt_parse.add_option('-i', '--idb',
                         action='store_true',
                         default=False,
                         dest='save_idb',
                         help='Save the patched IDB')
    return opt_parse


def post_file(host, resource, input_file):
    """
    Does an HTTP POST of the decoder family name and the entire input_file and returns the server's response.
    """
    base_boundary = '--------kordesii-client-----%s---------' % (uuid.uuid4())
    content_type = 'multipart/form-data; boundary=%s' % base_boundary
    body = encode_multipart(input_file, base_boundary)
    headers = {"Content-Type": content_type, "Content-Length": str(len(body))}
    conn = httplib.HTTPConnection(host)
    conn.request('POST', resource, body, headers)
    return conn.getresponse().read()


def encode_multipart(input_file, base_boundary):
    """
    Combines multiple components into the HTTP message body and returns the generated body.
    """
    with open(input_file, 'rb') as f:
        data = f.read()
    body = '--%s\r\n' % base_boundary
    body += 'Content-Disposition: form-data; name="filename"\r\n\r\n%s\r\n' % os.path.basename(input_file)
    body += '--%s\r\n' % base_boundary
    body += 'Content-Disposition: form-data; name="input_file"; filename="%s"\r\n' % os.path.basename(input_file)
    body += 'Content-Type: application/octet-stream\r\n\r\n%s\r\n' % data
    body += '--%s--\r\n\r\n' % base_boundary
    return body


def main():
    """
    The main client.
     - Call post_file with the command line arguments.
     - Extract the strings returned by the server into a file strings.txt.
     - Optionally extract, decode, and write out the generated IDB.
     - List the written files to the console.
    """
    warnings.warn('kordesii-client is deprecated.', DeprecationWarning)
    optparser = make_opt_parser()
    options, args = optparser.parse_args()

    if options.list:
        print '\n'.join(json.loads(urllib2.urlopen('http://%s/descriptions' % options.host).read())['decoders'])
        sys.exit(0)

    if len(args) < 2:
        optparser.print_help()
        sys.exit(1)

    response = post_file(options.host, '/run_decoder/' + args[0], args[1])
    try:
        response_object = json.loads(response)
    except:
        print response
        raise
    outputs = ''
    strings_file = os.path.join(options.output_dir, 'strings.txt')
    with open(strings_file, 'w') as strings:
        outputs += strings_file + '\n'
        if 'strings' in response_object:
            strings.write('\r\n'.join(response_object['strings']))

    if options.save_idb:
        idb_file = os.path.join(options.output_dir, response_object['idb']['name'])
        with open(idb_file, 'wb') as idb:
            outputs += idb_file + '\n'
            if 'idb' in response_object and 'data' in response_object['idb']:
                idb.write(base64.b64decode(response_object['idb']['data']))

    print outputs[:-1]  # Strip trailing \n


if __name__ == '__main__':
    main()
