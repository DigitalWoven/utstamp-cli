This is a command line tool for timestamping files using the utstamp service.
See https://utstamp.com to view our web interface.

### Requirements:

* Python >=3.5
* Pip
* Pip packages in requirements.txt. Install using `pip install -r requirements.txt`.

### Usage instructions:

The main script is utstamp.py.  
Run with `./utstamp.py [options]`.  
To see help, run `./utstamp.py -h`. 

There are two subcommands supported by the utstamp.py script, `stamp` and `query`.

* Stamp

Stamp text: `./utstamp.py stamp -s "i am the text."`  
Stamp a given file: `./utstamp.py stamp FILE`  
Stamp all files in the directory: `./utstamp.py stamp -r DIRECTORY`  

For additional options, view help with `./ustamp.py stamp -h`.

* Query

Query hash:  `./utstamp.py query HASH`  
For additional options, view help with `./ustamp.py query -h`.

### Testing instructions:

#### generate.py:
Generates a random file structure for testing purposes.
You can change parameters within the file to change generation behavior.
Run with `python generate.py`.
