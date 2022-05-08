"""
Moonlight's CLI command registry. Load commands into a group with `register`.
"""

import click as _click

# from .analyze import analyze as _analyze
from .decode import decode as _decode
from .pcap import pcap as _pcap


def register(group: _click.Group):
    """
    register adds the moonlight cli commands to a click group

    Args:
        group (click.Group): `click` cli command group
    """
    # _analyze.register(group)
    _decode.register(group)
    _pcap.register(group)
