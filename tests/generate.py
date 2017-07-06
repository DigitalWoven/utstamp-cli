# Script for generating random directory structure with random files

from contextlib import contextmanager
import os
import random
import string
import uuid

MAX_DEPTH = 5
MAX_BRANCH = 5
DIRECTORY_CREATION_PROBABILITY = 0.4

FILES_PER_DIRECTORY = 5
FILE_SIZE = (512, 2048) #bytes

def random_extension():
    return ''.join(random.choice(string.ascii_lowercase) for i in range(3))

def random_name():
    return uuid.uuid4().hex

def random_file_name():
    return '.'.join([random_name(), random_extension()])

# https://stackoverflow.com/questions/431684/how-do-i-cd-in-python/24176022
@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)

def generate(depth):

    # generate files
    for i in range(FILES_PER_DIRECTORY):
        with open(random_file_name(), 'wb+') as fout:
            fout.write(os.urandom(random.randint(FILE_SIZE[0], FILE_SIZE[1])))

    if depth >= MAX_DEPTH:
        return

    # generate directories
    for i in range(MAX_BRANCH):
        if random.random() < DIRECTORY_CREATION_PROBABILITY:
            dir_name = random_name()
            os.mkdir(dir_name)
            with cd(dir_name):
                generate(depth + 1)


def main():
    generate(1)

if __name__ == "__main__":
    main()
