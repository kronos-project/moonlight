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
def decode():
    """
    Decoding messages and captures

    Decoding individual messages and wireshark PCAP files into a human-readable
    format.
    """


def dump_anydict_as_map(anydict):
    yaml.add_representer(anydict, _represent_dictorder)


def _represent_dictorder(self, data):
    return self.represent_mapping("tag:yaml.org,2002:map", data.items())


@click.command()
@click.argument(
    "message_def_dir",
    type=click.Path(exists=True, dir_okay=True, resolve_path=True, path_type=Path),
)
@click.argument(
    "input_f",
    type=click.Path(exists=True, file_okay=True, resolve_path=True, path_type=Path),
)
@click.argument(
    "output_f",
    type=click.Path(file_okay=True, resolve_path=True, path_type=Path),
)
@click.option(
    "-t",
    "--typedefs",
    default=None,
    type=click.Path(file_okay=True, exists=True, resolve_path=True, path_type=Path),
)
def pcap(
    message_def_dir: Path,
    input_f: Path,
    output_f: Path,
    typedefs: Path,
):
    """
    Decode pcap to human-readable YAML

    `moonlight decode pcap` takes a compatible packet capture file (wireshark) and converts all
    unencrypted KI packets within it into a representation intended
    to be easily read by a human. By default, this is YAML.

    A packet is naively considered to be of the KI protocol if it starts with
    the \\x0D\\xF0 magic (little endian F00D). This may be improved in the future.

    MSG_DEF_DIR: Directory holding KI DML definitions

    INPUT_F: A valid packet capture file containing KI network traffic

    OUTPUT_F: File to write filtered capture to
    """

    # lazy load since scapy is kinda heavy
    from moonlight.net.scapy import (  # pylint: disable=import-outside-toplevel
        PcapReader,
    )

    dump_anydict_as_map(OrderedDict)

    from scapy.layers.inet import TCP

    rdr = PcapReader(
        pcap_path=input_f,
        typedef_path=typedefs,
        msg_def_folder=message_def_dir,
        silence_decode_errors=False,
    )
    with open(output_f, "w", encoding="utf8") as writer:
        # TODO: write metadata
        i = 1
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

    if in_fmt == "base64":
        input = base64.b64decode(input)
    elif in_fmt == "hex":
        input = bytes.fromhex(input.replace(" ", "").replace("\n", ""))

    rdr = PacketReader(
        typedef_path=typedefs,
        msg_def_folder=message_def_dir,
    )
    # TODO: write metadata
    msg = rdr.decode_packet(input)
    print()
    if msg is None:
        yaml.dump({"error": "failed to decode packet"}, sys.stdout)
    else:
        yaml.dump(
            msg.as_human_dict(compact=compact),
            sys.stdout,
            default_flow_style=False,
            sort_keys=False,
            Dumper=yamlloader.ordereddict.CDumper,
        )


decode.add_command(pcap)
decode.add_command(packet)


def register(group: click.Group):
    group.add_command(decode)
