from pathlib import Path

import click
import yaml


@click.group()
def decode():
    """
    Decoding messages and captures

    Decoding individual messages and wireshark PCAP files into a human-readable
      format.
    """


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
def human(
    message_def_dir: Path,
    input_f: Path,
    output_f: Path,
    typedefs: Path,
):
    """
    Filter content of pcap files

    Filter takes compatible packet capture files (wireshark) and removes all
      packets that aren't part of the KI network protocol, greatly reducing the
      size of packet captures. Optionally compresses output files as well.
    A packet is naively considered to be of the KI protocol if it starts with
      the \\x0D\\xF0 magic (little endian F00D). This may be improved in the future.

    INPUT_F: A valid packet capture file containing KI network traffic

    OUTPUT_F: File to write filtered capture to
    """

    # lazy load since scapy is kinda heavy
    from moonlight.net import PcapReader  # pylint: disable=import-outside-toplevel

    rdr = PcapReader(
        pcap_path=input_f, typedef_path=typedefs, msg_def_folder=message_def_dir
    )
    with open(output_f, "w+t", encoding="utf8") as writer:
        # TODO: write metadata
        for msg in rdr:
            writer.write("---\n")
            yaml.dump(
                msg.to_human_dict(), writer, default_flow_style=False, sort_keys=False
            )
            writer.write("\n")
    rdr.close()


decode.add_command(human)


def register(group: click.Group):
    group.add_command(decode)
