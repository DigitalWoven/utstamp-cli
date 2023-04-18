This document provides instructions on how to use a command line tool for timestamping files using the UTStamp service. For a web interface, please visit https://utstamp.com.

## Requirements:

1. Python >=3.5
2. Pip
3. Pip packages listed in requirements.txt (install using the command: `pip install -r requirements.txt`)

## Usage instructions:

The main script is utstamp.py. Execute the script by running `./utstamp.py [options]`. To view help, run `./utstamp.py -h`.

The utstamp.py script supports two subcommands: stamp and query.

### Stamp

First, obtain the license key from your [portal](https://www.utstamp.com/portal), which is a UUID string.

1. Stamp text: `./utstamp.py --license_key 00000000-0000-0000-0000-000000000000 stamp -s "i am the text."`  
2. Stamp a given file: `./utstamp.py --license_key 00000000-0000-0000-0000-000000000000 stamp FILE`  
3. Stamp all files in the directory: `./utstamp.py --license_key 00000000-0000-0000-0000-000000000000 stamp -r DIRECTORY`  

For additional options, view help with `./ustamp.py stamp -h`.

### Query

Query hash:  `./utstamp.py query HASH`  
For additional options, view help with `./ustamp.py query -h`.
