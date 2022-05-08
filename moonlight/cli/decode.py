"""
Decoding still packed network traffic
"""
import base64
import json
import logging
import sys
from pathlib import Path

import click

from moonlight.net import PacketReader
from moonlight.util import SerdeJSONEncoder, bytes_to_pretty_str

from ._util import message_def_dir_arg, typedef_option

logger = logging.getLogger(__name__)


@click.group()
def decode():
    """
    Decoding messages and captures

    Decoding individual messages and wireshark PCAP files into a human-readable
    format.
    """


@decode.command()
@message_def_dir_arg
@click.argument(
    "input_f",
    type=click.Path(exists=True, file_okay=True, resolve_path=True, path_type=Path),
)
@click.argument(
    "output_f",
    type=click.Path(file_okay=True, resolve_path=True, path_type=Path),
)
@typedef_option
def pcap(
    message_def_dir: Path,
    input_f: Path,
    output_f: Path,
    typedefs: Path,
):
    """
    Decode pcap to a JSON representation

    `moonlight decode pcap` takes a compatible packet capture file (wireshark) and converts all
    unencrypted KI packets within it into a representation intended
    to be easily read by another computer or human.

    A packet is naively considered to be of the KI protocol if it starts with
    the \\x0D\\xF0 magic (little endian F00D). This may be improved in the future.

    MSG_DEF_DIR: Directory holding KI DML definitions

    INPUT_F: A valid packet capture file containing KI network traffic

    OUTPUT_F: File to write filtered capture to
    """

    # lazy load since scapy is kinda heavy
    from moonlight.net.scapy import (
        PcapReader,
    )  # pylint: disable=import-outside-toplevel

    from scapy.layers.inet import TCP

    rdr = PcapReader(
        pcap_path=input_f,
        typedef_path=typedefs,
        msg_def_folder=message_def_dir,
        silence_decode_errors=False,
    )
    with open(output_f, "w", encoding="utf8") as writer:
        messages = []
        i = 1
        while True:
            try:
                messages.append(next(rdr))
            except ValueError as err:
                messages.append(
                    {
                        "error": {
                            "message": str(err),
                            "raw": bytes_to_pretty_str(
                                bytes(rdr.last_decoded_raw[TCP].payload)
                            ),
                        }
                    }
                )
                continue
            except StopIteration:
                break
            finally:
                i += 1
            if i % 100 == 0:
                logger.info("Progress: completed %d so far", i)

        logger.info("Progress: Dumping to file")
        json.dump(obj=messages, fp=writer, cls=SerdeJSONEncoder, indent=2)
    rdr.close()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


@decode.command()
@click.argument(
    "message_def_dir",
    type=click.Path(exists=True, dir_okay=True, resolve_path=True, path_type=Path),
)
@click.option(
    "-i",
    "--input_",
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
def packet(  # pylint: disable=too-many-arguments
    message_def_dir: Path,
    input_: str,
    typedefs: Path,
    in_fmt: str,
):
    """
    Decodes packet from stdin

    Takes a variety of encoding formats of KI packets and converts them into
    a supported human-readable format.

    MSG_DEF_DIR: Directory holding KI DML definitions
    """

    if input_ is None:
        input_ = sys.stdin.buffer.read()

    if in_fmt == "base64":
        input_ = base64.b64decode(input)
    elif in_fmt == "hex":
        input_ = bytes.fromhex(input.replace(" ", "").replace("\n", ""))

    rdr = PacketReader(
        typedef_path=typedefs,
        msg_def_folder=message_def_dir,
    )
    msg = rdr.decode_ki_packet(input)
    click.echo()
    if msg is None:
        click.echo(
            json.dumps(
                obj={"error": "failed to decode packet"}, cls=SerdeJSONEncoder, indent=2
            )
        )
    else:
        click.echo(json.dumps(obj=msg, cls=SerdeJSONEncoder, indent=2))


def register(group: click.Group):
    """
    register adds decode commands to the given click group

    Args:
        group (click.Group): group to add commands to
    """
    group.add_command(decode)
