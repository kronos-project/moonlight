"""Moonlight's CLI command"""

import logging
import click

# from .analyze import analyze as _analyze
from .decode import decode
from .pcap import pcap

STANDARD_LOG_FMT = "%(levelname)-8s %(message)s"
STANDARD_LOG_LVL = logging.INFO
VERBOSE_LOG_FMT = "%(asctime)s [%(levelname)s::%(module)s:%(lineno)d] %(message)s"
VERBOSE_LOG_LVL = logging.DEBUG
SILENT_LOG_LVL = 60

LOGGER_LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "SILENT": SILENT_LOG_LVL,
}


@click.group()
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Log debug information with detailed formatting. --silent takes priority if both specified.",
)
@click.option(
    "-s", "--silent", is_flag=True, default=False, help="Disable logging output."
)
@click.option(
    "--log-level",
    default=None,
    type=click.Choice(["debug", "info", "warning", "error", "critical", "silent"]),
    help="Sets the logging level. Overrides any other specified verbosity flag's level including --silent (not formatting). Silent disables logging.",
)
def cli_cmd(verbose, silent: bool, log_level: str):
    """
    Decodes Wizard101 traffic from unencrypted wireshark packet captures
    """

    logging.addLevelName(level=LOGGER_LEVEL_MAP["SILENT"], levelName="SILENT")

    log_level_int = STANDARD_LOG_LVL
    log_fmt = STANDARD_LOG_FMT

    if verbose:
        log_level_int = VERBOSE_LOG_LVL
        log_fmt = VERBOSE_LOG_FMT
    if silent:
        log_level_int = SILENT_LOG_LVL

    if log_level is not None:
        log_level_int = LOGGER_LEVEL_MAP[log_level.upper()]

    logging.basicConfig(format=log_fmt, level=log_level_int)


cli_cmd.add_command(decode)
cli_cmd.add_command(pcap)
