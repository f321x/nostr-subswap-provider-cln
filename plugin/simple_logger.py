# simple logger to print messages to stderr for CLN plugin

import sys

class Logger:
    def __init__(self, filename: str):
       self.filename = filename

    def warning(self, message):
        print(f"WARNING in {self.filename}: {message}", file=sys.stderr)

    def info(self, message):
        print(f"INFO in {self.filename}: {message}", file=sys.stderr)

    def error(self, message):
        print(f"ERROR in {self.filename}: {message}", file=sys.stderr)

    def debug(self, message):
        print(f"DEBUG in {self.filename}: {message}", file=sys.stderr)


def get_logger():
    return Logger()
