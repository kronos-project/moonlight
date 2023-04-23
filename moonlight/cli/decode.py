"""Decoding still packed network traffic"""


import base64
import json
import logging
import sys
from pathlib import Path

import click

from moonlight.net import PacketReader, Message, KeepAliveMessage
from moonlight.util import SerdeJSONEncoder, bytes_to_pretty_str

from ._util import message_def_dir_arg, typedef_option

logger = logging.getLogger(__name__)


@click.group()
def decode():
    """Decoding messages and captures

    Decoding individual messages and wireshark PCAP files into a human-readable
    format.
    """


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


@decode.command()
@click.argument(
    "message_def_dir",
    type=click.Path(exists=True, dir_okay=True, resolve_path=True, path_type=Path),
)
@click.option(
    "--no-keep-alive",
    is_flag=True,
    default=False,
    help="don't print keep alive messages",
)
@click.option(
    "--show-service",
    is_flag=True,
    default=False,
    help="include service and order in the output json",
)
# @typedef_option
# @click.option(
#     "--filter-str",
#     type=str,
#     default="tcp port 1337",
#     help="wireshark traffic filter string",
#     show_default=True,
# )
# @click.option(
#     "--iface",
#     type=str,
#     default="lo0",
#     help="sniffing interface name",
#     show_default=True,
# )
def live(
    message_def_dir: Path,
    no_keep_alive: bool,
    show_service: bool,
    # typedefs: Path,
    # filter_str: str,
    # iface: str
):
    """Decode live traffic to a JSON representation

    `moonlight decode live` sniffs live traffic containing
    unencrypted KI packets into a representation intended
    to be easily read by a human.

    A packet is naively considered to be of the KI protocol if it starts with
    the \\x0D\\xF0 magic (little endian F00D). This may be improved in the future.
    Additionally, only traffic matching the provided filter is attempted to be
    decoded.

    MSG_DEF_DIR: Directory holding KI DML definitions
    """

    # lazy load since scapy is kinda heavy
    # pylint: disable=import-outside-toplevel
    from moonlight.net.scapy import (
        LiveSniffer,
    )

    from scapy.packet import Packet

    # pylint: enable=import-outside-toplevel

    serde_encoder = SerdeJSONEncoder(show_service=show_service, indent=2)

    def echo_packet(msg: Message, pkt: Packet):
        if isinstance(msg, KeepAliveMessage) and no_keep_alive:
            return
        click.echo(serde_encoder.encode(msg))
        click.echo("\n// " + ("~" * 15) + "\n")

    rdr = LiveSniffer(
        callback=echo_packet,
        client_port=1337,
        # typedef_path=typedefs,
        msg_def_folder=message_def_dir,
        filter_str=None,
        silence_decode_errors=False,
    )
    rdr.open_livestream()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


@decode.command()
@click.argument(
    "message_def_dir",
    type=click.Path(exists=True, dir_okay=True, resolve_path=True, path_type=Path),
)
@click.option(
    "-i",
    "--input-str",
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
    "--dml-only",
    is_flag=True,
    default=False,
    help="Interpret the information as a DML frame, skipping the control info",
)
def packet(  # pylint: disable=too-many-arguments
    message_def_dir: Path,
    input_str: str,
    typedefs: Path,
    in_fmt: str,
    dml_only: bool,
):
    """Decodes packet from stdin

    Takes a variety of encoding formats of KI packets and converts them into
    a supported human-readable format.

    MSG_DEF_DIR: Directory holding KI DML definitions
    """

    if input_str is None:
        input_str = sys.stdin.buffer.read()

    if in_fmt == "base64":
        input_str = base64.b64decode(input_str)
    elif in_fmt == "hex":
        input_str = bytes.fromhex(input_str.replace(" ", "").replace("\n", ""))

    rdr = PacketReader(
        typedef_path=typedefs,
        msg_def_folder=message_def_dir,
    )

    if dml_only:
        msg = rdr.dml_protocol.decode_packet(input_str, has_ki_header=False)
    else:
        msg = rdr.decode_ki_packet(input_str)

    click.echo()
    if msg is None:
        click.echo(
            json.dumps(
                obj={"error": "failed to decode packet"}, cls=SerdeJSONEncoder, indent=2
            )
        )
    else:
        click.echo(SerdeJSONEncoder(show_service=True, indent=2).encode(msg))


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def register(group: click.Group):
    """Adds decode commands to the given click group

    Args:
        group (click.Group): group to add commands to
    """
    group.add_command(decode)
