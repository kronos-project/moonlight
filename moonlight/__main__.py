from os import PathLike
from typing import PathLike
from os.path import join, dirname

import click

from moonlight.ki.capture import KIPacketSniffer


@click.group()
def cli():
    pass

@click.command(name="open-stream")
@click.option('--file', '-f', type=PathLike, help="PCAP file of a previous capture. Must be unencrypted.")
#@click.option('--live' '-l', type=str, help="Capture via sniffing for live packets from the given ip range")
@click.option('--types', '-t', default=None, type=click.File("r"), help="WizWalker typedef manifest JSON file")
@click.option('--messages', '-m', default=join(dirname(__file__)), type=PathLike, help="Directory holding game message definitions. These may be straight from the root wad, however property objects won't be decoded from a 'vanilla' message definition file. For further information, read the package documentation. Loads the package's internal definitions by default.")
@click.argument("file", type=PathLike, default=None, help="PCAP file of a previous capture. Must be unencrypted.")
def open_stream():
    rdr = KIPacketSniffer(dml_def_folder=path.join())


@click.command()
@click.option('--count', default=1, help='Number of greetings.')
@click.option('--name', prompt='Your name',
              help='The person to greet.')
def hello(count, name):
    """Simple program that greets NAME for a total of COUNT times."""
    for x in range(count):
        click.echo(f"Hello {name}!")

if __name__ == '__main__':
    hello()
