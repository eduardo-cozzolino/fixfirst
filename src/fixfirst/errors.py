"""Exceptions raised by fixfirst."""


class InputError(Exception):
    """A report or inventory file cannot be read or is not valid.

    This is the only exception the CLI maps to exit code 2. Its message is for display only, and no
    code may branch on its text.
    """
