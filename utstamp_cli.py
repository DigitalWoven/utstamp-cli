#!/usr/bin/env python3

# python modules
import argparse
import hashlib
import json
import os

# external modules
import requests
from tqdm import tqdm
from deepdiff import DeepDiff

SUCCESS = 'success'
ERROR = 'error'
COLLISION = 'collision'


class UTStampCLI(object):

    def __init__(self, cli_args):
        self.cli_args = cli_args

    def stamp(self):
        if self.cli_args.s:
            self.stamp_string()
        else:
            self.stamp_files()

    def stamp_files(self):
        print("Scanning files... ", end='')
        try:
            files = self.resolve_files()
        except ValueError as err:
            print(err)
            return
        print("Found {0} files.".format(len(files)))

        print("Uploading files...")
        for path, file in tqdm(files):
            res = self.submit_files(path, file)

            if res == COLLISION:
                tqdm.write("collision: {0}".format(os.path.join(path, file)))
            elif res == ERROR:
                tqdm.write("failure: {0}".format(os.path.join(path, file)))

    def stamp_string(self):
        args = self.cli_args

        # use paths[0] to hold string
        content = args.paths[0]
        hex_dig = self.sha256_checksum4text(content)
        print(hex_dig)

        payload = {
            'submit_data': {
                'request': {
                    'submit_data': [
                        {'hash_key': hex_dig}
                    ]
                }
            }
        }

        r = requests.post(args.endpoint, data=json.dumps(payload))
        veracity = self.verify_response(r.json(), hex_dig)
        if veracity == SUCCESS:
            print("success.")
        elif veracity == COLLISION:
            print("the text has already been stamped. You can query the status now.")
        else:
            print("error")

        return

    def query_hash(self):
        args = self.cli_args
        payload = {
            "data_query": {
                "request": {
                    "token_id": args.hash
                }
            }
        }

        r = requests.post(args.endpoint, data=json.dumps(payload))
        print(json.dumps(r.json(), indent=2))

    def resolve_files(self):
        paths, recursive, \
        depth, hidden_files = \
            self.cli_args.paths, self.cli_args.r, \
            self.cli_args.d, self.cli_args.hidden_files

        files = []
        recursive_files = []
        for path in paths:
            if os.path.isfile(path):
                files.extend([os.path.split(path)])

            elif os.path.isdir(path):
                if recursive:

                    curdepth = 0
                    for root, dirs, curfiles in os.walk(path):
                        for file in curfiles:
                            recursive_files.extend([(root, file)])

                        curdepth = curdepth + 1
                        if curdepth >= depth and depth != 0:
                            break

                else:
                    raise ValueError(
                        "Can't process directory {0} with -r flag.".format(path))

            else:
                raise ValueError("Can't find {0}".format(path))

        if not hidden_files:
            recursive_files = list(
                filter(lambda pathfile: pathfile[1][0] != '.', recursive_files))

        return files + recursive_files

    def submit_files(self, path, file):
        args = self.cli_args

        relpath = os.path.join(path, file)
        checksum = self.sha256_checksum4file(relpath)
        inner_payload = {'hash_key': checksum}

        if args.include_path:
            inner_payload['customer_tag'] = ''.join(
                ['file://',
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
            # output hash val to user, otherwise they do not know how to query
            print(relpath + ' | hash: ' + checksum)
            veracity = self.verify_response(r.json(), checksum)

            if veracity in {SUCCESS, COLLISION}:
                return veracity

        return ERROR

    # https://gist.github.com/rji/b38c7238128edf53a181#file-sha256-py
    @staticmethod
    def sha256_checksum4file(filename, block_size=65536):
        sha256 = hashlib.sha256()
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                sha256.update(block)
        return sha256.hexdigest()

    @staticmethod
    def sha256_checksum4text(text):
        data = text.encode('utf-8')
        hash_object = hashlib.sha256(data)
        hex_dig = hash_object.hexdigest()

        return hex_dig

    @staticmethod
    def verify_response(payload, checksum):
        success_payload = {
            'submit_data': {
                'response': {}
            }
        }

        collision_payload = {
            "submit_data": {
                "response": {
                    "error": [
                        {"failed_hash_key": checksum}
                    ]
                }
            }
        }

        # when two items are the same, deepdiff returns {}, i.e., false!
        if DeepDiff(payload, success_payload):
            if DeepDiff(payload, collision_payload):
                return ERROR
            return COLLISION
        return SUCCESS

    # Checks value is positive integer
    @staticmethod
    def check_positive(value):
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(
                "{0} is an invalid positive int value".format(value))
        return ivalue


# Handler for stamp subcommand
def stamp(cli):
    cli.stamp()


# Handler for query subcommand
def query(cli):
    cli.query_hash()


def init_parser():

    parser = argparse.ArgumentParser(description="UTStamp command line tool")
    parser.add_argument('--endpoint', default='https://api.utstamp.com/submit',
                        help="defaults to https://api.utstamp.com/submit")
    parser.add_argument('--retries', type=UTStampCLI.check_positive, default=3,
                        help="defaults to 3")

    subparsers = parser.add_subparsers(
                help="run -h with subcommand for additional help")

    stamp_subparser = subparsers.add_parser('stamp', help='stamps files')
    stamp_subparser.set_defaults(func=stamp)
    stamp_subparser.add_argument('paths', nargs='+')
    stamp_subparser.add_argument('-s', action='store_true', default=False,
                                 help="stamp string instead of files")
    stamp_subparser.add_argument('-r', action='store_true', default=False,
                help="whether to recursively upload files from subdirectories")
    stamp_subparser.add_argument('-d', type=UTStampCLI.check_positive, default=0,
                help="how deep to recurse (the lowest value of 1 does not step into any subdirectories)")
    stamp_subparser.add_argument('--hidden-files', action='store_true',
                default=False, help="includes files starting with . (only has an effect when used with -r)")
    stamp_subparser.add_argument('--include-path', action='store_true', default=False,
                help="include path to file and file name in submission")
    stamp_subparser.add_argument('--user',
                help="user_id for submission")

    query_subparser = subparsers.add_parser('query', help='query for stamps')
    query_subparser.set_defaults(func=query)
    query_subparser.add_argument('hash',
                help="queries a hash/string instead of stamping files")

    args = parser.parse_args()

    cli = UTStampCLI(args)

    if 'func' in args:
        args.func(cli)
    else:
        parser.print_help()


if __name__ == '__main__':
    init_parser()
