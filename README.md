This is a command line tool for timestamping files using the utstamp service.
See https://utstamp.com to view our web interface.

### Requirements:

* Python >=3.5
* Pip
* Pip packages in requirements.txt. Install using `pip install -r requirements.txt`.

### Usage instructions:

utstamp.py:
Stamps a file or directory.
Run with `./utstamp.py [options]`.
To see help, run `./utstamp.py -h`.

There are two subcommands supported by the utstamp.py script, stamp and submit.

Running `./utstamp.py stamp -h FILE` will stamp the given file,
and running `./utstamp.py stamp -r DIRECTORY` will stamp all files in the directory.
For additional options, view help with `./ustamp.py stamp -h`.

Running `./utstamp.py query HASH` will query for a stamp with the given HASH.
For additional options, view help with `./ustamp.py query -h`.

### Testing instructions:

generate.py:
Generates a random file structure for demo purposes.
You can change parameters within the file to change generation behavior.
Run with `python generate.py`
