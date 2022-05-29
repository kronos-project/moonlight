"""Shared utilities for cli commands"""

from functools import wraps
from pathlib import Path
import click


def message_def_dir_arg(fun):
    """Require message definition directory

    Wraps `click.argument` to require wizard101 message definitions in a
    command. Arg type is an existing `pathlib.Path` to a directory.

    Args:
        fun(function): decorating function
    """

    @wraps(fun)
    @click.argument(
        "message_def_dir",
        type=click.Path(exists=True, dir_okay=True, resolve_path=True, path_type=Path),
    )
    def _with_message_defs(*args, **kwargs):
        return fun(*args, **kwargs)

    return _with_message_defs


def typedef_option(fun):
    """Require wizwalker typedef

    Wraps `click.option` to request a wizwalker typedef file in a command.
    Option type is an existing `pathlib.Path` to a file.

    Args:
        fun(function): decorating function
    """

    @wraps(fun)
    @click.option(
        "-t",
        "--typedefs",
        default=None,
        type=click.Path(file_okay=True, exists=True, resolve_path=True, path_type=Path),
    )
    def _with_typedefs(*args, **kwargs):
        return fun(*args, **kwargs)

    return _with_typedefs
