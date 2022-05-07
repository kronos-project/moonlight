from pathlib import Path
import logging
import sys
import base64
from typing import OrderedDict
import json

import click
import yaml
import yamlloader

from moonlight.net import PacketReader
from moonlight.util import SerdeJSONEncoder, bytes_to_pretty_str

logger = logging.getLogger(__name__)


@click.group()
def analyze():
    """
    Analyzing decoded data

    Decoding individual messages and wireshark PCAP files into a human-readable
    format.
    """


@click.command()
@click.argument(
    "message_def_dir",
    type=click.Path(exists=True, dir_okay=True, resolve_path=True, path_type=Path),
)
@click.option(
    "-i",
    "--input",
    default=None,
    help="Instead of reading from stdin, use this value as the input",
)
@click.option(
    "-t",
    "--typedefs",
    default=None,
    type=click.Path(file_okay=True, exists=True, resolve_path=True, path_type=Path),
    help="Path to wizwalker typedef json",
)
@click.option(
    "-F",
    "--in-fmt",
    default="raw",
    show_default=True,
    type=click.Choice(["base64", "raw", "hex"]),
    help="Format of the input packet data",
)
@click.option(
    "--out-fmt",
    default="yaml",
    show_default=True,
    type=click.Choice(["yaml"]),
    help="Format of the output human representation",
)
@click.option(
    "-c",
    "--compact",
    is_flag=True,
    default=False,
    help="Reduces the amount of information in output",
)
def packet(  # pylint: disable=too-many-arguments
    message_def_dir: Path,
    input: str,
    typedefs: Path,
    in_fmt: str,
    out_fmt: str,
    compact: bool,
):
    """
    Decodes packet from stdin

    Takes a variety of encoding formats of KI packets and converts them into
    a supported human-readable format.

    MSG_DEF_DIR: Directory holding KI DML definitions
    """

    if input is None:
        input = sys.stdin.buffer.read()


decode.add_command(pcap)
decode.add_command(packet)


def register(group: click.Group):
    group.add_command(decode)
