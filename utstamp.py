#!/usr/bin/env python3

# python modules
import datetime
import argparse
import hashlib
import json
import os
from enum import Enum
from urllib.parse import urljoin

# external modules
import requests
from tqdm import tqdm

LICENSE_KEY_HEADER = 'license_key'


class UTStampResult(Enum):
    """
    UTStampResult is the result of a UTStamp API call.
    """
    SUCCESS = 1
    ERROR = 2
    COLLISION = 3
    SOME_COLLISION = 4
    FORBIDDEN = 5

    def human_readable(self) -> str:
        """
        Get a human-readable string for the result.

        Returns:
            str: The human-readable string.

        """
        if self == UTStampResult.SUCCESS:
            return "Success! You can query the status later."
        elif self == UTStampResult.ERROR:
            return "Unknown error. Please try again later."
        elif self == UTStampResult.COLLISION:
            return "All submissions have already been processed. You can query the status now."
        elif self == UTStampResult.SOME_COLLISION:
            return "Some submissions have already been processed, but others are still ongoing. You can check their status now."
        elif self == UTStampResult.FORBIDDEN:
            return "Forbidden! Please check your license key."


class UTStampCLI(object):
    """
    UTStampCLI is the command line interface for the UTStamp API.
    """

    def __init__(self, cli_args: argparse.Namespace):
        self.cli_args = cli_args

    def call_stamp(self, hash_list: list) -> UTStampResult:
        """
        Stamp the given hash list.

        Args:
            hash_list (list): The hash list to stamp.

        Returns:
            UTStampResult: The result of the stamp.
        """
        payload: dict = {"entries": [{"hash": hash} for hash in hash_list]}

        endpoint: str = self.cli_args.endpoint
        url: str = urljoin(endpoint, "submissions")
        license_key: str = self.cli_args.license_key

        for _ in range(self.cli_args.retries):
            # retry if the server returns an error
            try:
                if len(license_key) > 0:
                    headers: dict = {LICENSE_KEY_HEADER: license_key}
                    r: requests.Response = requests.post(
                        url, data=json.dumps(payload), headers=headers
                    )
                else:
                    r = requests.post(url, data=json.dumps(payload))
                r_json = r.json()
                if r.status_code == 403:
                  return UTStampResult.FORBIDDEN
                if r.status_code == 200 and r_json['message'] == 'success' and r_json['all_success']:
                  return UTStampResult.SUCCESS
                if r.status_code == 200 and len(r_json['failed_chunks']) > 0 and not r_json['all_success']:
                  failed_hash = []
                  for chunk in r_json['failed_chunks']:
                    for hash in chunk:
                      failed_hash.append(hash)
                  if len(failed_hash) == len(hash_list):
                    return UTStampResult.COLLISION
                  else:
                    return UTStampResult.SOME_COLLISION
                return UTStampResult.ERROR
            except Exception as e:
                tqdm.write(f"Error stamping {payload}: {e}, retrying...")
                continue
        message = f"Unable to stamp {payload} after {self.cli_args.retries} retries"
        raise ConnectionAbortedError(message)

    def call_query(self, hash_key) -> str:
        payload: dict = {"hash": hash_key}
        endpoint: str = self.cli_args.endpoint
        url: str = urljoin(endpoint, "submission/query")

        for _ in range(self.cli_args.retries):
            # retry if the server returns an error
            try:
                r = requests.get(url, params=payload)
                r_json = r.json()
                if r.status_code == 200:
                  return r.text
                elif r.status_code == 404:
                    return "submission is not exists"
                elif r.status_code == 408:
                    time = datetime.datetime.fromtimestamp(float(r_json["message"])/1000.0)
                    return f"submission is stamped at {time.isoformat()}"
                return UTStampResult.ERROR.human_readable()
            except Exception as e:
                tqdm.write(f"Error stamping {payload}: {e}, retrying...")
                continue
        message = f"Unable to query {hash_key} after {self.cli_args.retries} retries"
        raise ConnectionAbortedError(message)

    def stamp(self):
        if self.cli_args.s:
            self.stamp_string()
        else:
            self.stamp_files()

    def stamp_files(self):
        tqdm.write("Scanning files... ", end='')
        try:
            files = self.resolve_files()
        except ValueError as err:
            tqdm.write(err)
            return
        tqdm.write("Found {0} files.".format(len(files)))

        hash_list = []
        for path, file in tqdm(files):
          relpath = os.path.join(path, file)
          checksum = self.sha256_checksum4file(relpath)
          tqdm.write(f"Stamping {relpath} | hash: {checksum}")
          hash_list.append(checksum)

        tqdm.write("Submitting file hash list...")
        res = self.call_stamp(hash_list)
        tqdm.write(res.human_readable())

    def stamp_string(self):
        args = self.cli_args

        hash_list = []
        for path in tqdm(args.paths):
          hex_dig = self.sha256_checksum4text(path)
          tqdm.write(f"Stamping {path} | hash: {hex_dig}")
          hash_list.append(hex_dig)
        # write messages according to the result
        res = self.call_stamp(hash_list)
        tqdm.write(res.human_readable())

    def query_hash(self):
        args = self.cli_args
        result = self.call_query(args.hash)
        tqdm.write(result)

    def resolve_files(self):
        paths, recursive, depth, hidden_files = \
            self.cli_args.paths, self.cli_args.r, self.cli_args.d, self.cli_args.hidden_files

        files = [os.path.split(path) for path in paths if os.path.isfile(path)]
        recursive_files = []

        for path in paths:
            if os.path.isdir(path):
                if not recursive:
                    raise ValueError(
                        "Can't process directory {0} without -r flag.".format(path))

                current_depth = 0
                for root, dirs, current_files in os.walk(path):
                    recursive_files.extend([(root, file) for file in current_files])
                    current_depth += 1
                    if (current_depth >= depth) and depth != 0:
                        break

        if not hidden_files:
            recursive_files = [pathfile for pathfile in recursive_files if pathfile[1][0] != '.']

        return files + recursive_files

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

    # Checks value is positive integer
    @staticmethod
    def check_positive(value):
        int_value = int(value)
        if int_value <= 0:
            raise argparse.ArgumentTypeError(
                "{0} is an invalid positive int value".format(value))
        return int_value


# Handler for stamp subcommand
def stamp_handler(cli):
    cli.stamp()


# Handler for query subcommand
def query_handler(cli):
    cli.query_hash()


def init_parser():
    parser = argparse.ArgumentParser(description="UTStamp command line tool")
    parser.add_argument('--endpoint', default='https://api.utstamp.com/submit',
                        help="defaults to https://api.utstamp.com/submit")
    parser.add_argument('--license_key', default='',
                        help="defaults to be empty")
    parser.add_argument('--retries', type=UTStampCLI.check_positive, default=3,
                        help="defaults to 3")

    subparsers = parser.add_subparsers(
        help="run -h with subcommand for additional help")

    stamp_subparser = subparsers.add_parser('stamp', help='stamps files')
    stamp_subparser.set_defaults(func=stamp_handler)
    stamp_subparser.add_argument('paths', nargs='+')
    stamp_subparser.add_argument('-s', action='store_true', default=False,
                                 help="stamp string instead of files")
    stamp_subparser.add_argument('-r', action='store_true', default=False,
                                 help="whether to recursively upload files from subdirectories")
    stamp_subparser.add_argument('-d', type=UTStampCLI.check_positive, default=0,
                                 help="how deep to recurse (the lowest value of 1 does not step into any "
                                      "subdirectories)")
    stamp_subparser.add_argument('--hidden-files', action='store_true',
                                 default=False,
                                 help="includes files starting with . (only has an effect when used with -r)")

    query_subparser = subparsers.add_parser('query', help='query for stamps')
    query_subparser.set_defaults(func=query_handler)
    query_subparser.add_argument('hash',
                                 help="queries a SHA256 hash instead of stamping files")

    args = parser.parse_args()

    cli = UTStampCLI(args)

    if 'func' in args:
        args.func(cli)
    else:
        parser.print_help()


if __name__ == '__main__':
    init_parser()
