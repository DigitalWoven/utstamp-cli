#!/usr/bin/env python3

# python modules
import argparse
from datetime import datetime
import hashlib
import json
import os
import time

# external modules
import requests
from tqdm import tqdm
from deepdiff import DeepDiff


# https://gist.github.com/rji/b38c7238128edf53a181#file-sha256-py
def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


# payload should be dict
# if success returns 0
# if collision returns 1
# otherwise returns 2
def verify_response(payload, checksum):
    success_payload = {
        'submit_data': {
            'response': { }
        }
    }

    collision_payload = {
        "submit_data": {
            "response": {
                "error": [
                    { "failed_hash_key": checksum }
                ]
            }
        }
    }


    if DeepDiff(payload, success_payload):
        if DeepDiff(payload, collision_payload):
            return 2
        return 1
    return 0


# if success returns 0
# if collision returns 1
# otherwise returns 2
def stamp(path, file, args):

    relpath = os.path.join(path, file)
    checksum = sha256_checksum(relpath)
    inner_payload = { 'hash_key': checksum }

    if args.include_path:
        inner_payload['customer_tag'] = ''.join(
            [ 'file://',
              os.uname().nodename,
              os.path.abspath(relpath)])

    if args.user:
        inner_payload['user_id'] = args.user


    payload = {
        'submit_data': {
            'request': {
                'submit_data': [
                    inner_payload
                ]
            }
        }
    }

    for i in range(args.retries):
        r = requests.post(args.endpoint, data=json.dumps(payload))
        veracity = verify_response(r.json(), checksum)

        if veracity < 2:
            return veracity

    return 2


def resolveFiles(paths, recursive, hidden_files, depth):

    files = []
    for path in paths:
        if os.path.isfile(path):
            files.extend([os.path.split(path)])

        elif os.path.isdir(path):
            if recursive:

                curdepth = 0
                for root, dirs, curfiles in os.walk(path):
                    for file in curfiles:
                        files.extend([(root, file)])

                    curdepth = curdepth + 1
                    if curdepth >= depth and depth != 0:
                        break

            else:
                raise ValueError(
                    "Can't process directory {0} with -r flag.".format(path))

        else:
            raise ValueError("Can't find {0}".format(path))


    if not hidden_files:
        files = list(filter(lambda pathfile: pathfile[1][0] != '.', files))

    return files

def check_positive(value):
    ivalue = int(value)
    if ivalue <= 0:
         raise argparse.ArgumentTypeError(
            "{0} is an invalid positive int value".format(value))
    return ivalue


def main():

    parser = argparse.ArgumentParser(description="Uploads files to utstamp.")
    parser.add_argument('-r', action='store_true', default=False,
                help="whether to recursively upload files from subdirectories")
    parser.add_argument('-d', type=check_positive, default=0,
        help="how deep to recurse (the lowest value of 1 does not step into any subdirectories)")
    parser.add_argument('--hidden-files', action='store_true',
                default=False, help="includes files starting with . (only has an effect when used with -r)")
    parser.add_argument('--include-path', action='store_true', default=False,
                help="include path to file and file name in submission")
    parser.add_argument('--user',
                help="user_id for submission")
    parser.add_argument('--endpoint', default='https://api.utstamp.com/submit',
                help="defaults to https://api.utstamp.com/submit")
    parser.add_argument('--retries', type=check_positive, default=3,
                help="defaults to 3")
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()


    print("Scanning files... ", end='')
    try:
        files = resolveFiles(args.paths, args.r, args.hidden_files, args.d)
    except ValueError as err:
        print(err)
        return
    print("Found {0} files.".format(len(files)))


    print("Uploading files...")
    for path, file in tqdm(files):
        res = stamp(path, file, args)

        if res == 1:
            tqdm.write("collision: {0}".format(os.path.join(path, file)))
        elif res == 2:
            tqdm.write("failure: {0}".format(os.path.join(path, file)))


if __name__ == '__main__':
    main()