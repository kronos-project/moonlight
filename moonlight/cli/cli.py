"""Moonlight's CLI command"""

import logging as _logging
import click as _click

# from .analyze import analyze as _analyze
from .decode import decode as _decode
from .pcap import pcap as _pcap

STANDARD_LOG_FMT = "%(levelname)-8s %(message)s"
STANDARD_LOG_LVL = _logging.INFO
VERBOSE_LOG_FMT = "%(asctime)s [%(levelname)s::%(module)s:%(lineno)d] %(message)s"
VERBOSE_LOG_LVL = _logging.DEBUG
SILENT_LOG_LVL = 60

LOGGER_LEVEL_MAP: dict[str, int] = {
    "DEBUG": _logging.DEBUG,
    "INFO": _logging.INFO,
    "WARNING": _logging.WARNING,
    "ERROR": _logging.ERROR,
    "CRITICAL": _logging.CRITICAL,
    "SILENT": SILENT_LOG_LVL,
}


@_click.group()
@_click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Log debug information with detailed formatting. --silent takes priority if both specified.",
)
@_click.option(
    "-s", "--silent", is_flag=True, default=False, help="Disable logging output."
)
@_click.option(
    "--log-level",
    default=None,
    type=_click.Choice(["debug", "info", "warning", "error", "critical", "silent"]),
    help="Sets the logging level. Overrides any other specified verbosity flag's level including --silent (not formatting). Silent disables logging.",
)
def cli_cmd(verbose, silent: bool, log_level: str):
    """
    Decodes Wizard101 traffic from unencrypted wireshark packet captures
    """

    _logging.addLevelName(level=LOGGER_LEVEL_MAP["SILENT"], levelName="SILENT")

    log_level_int = STANDARD_LOG_LVL
    log_fmt = STANDARD_LOG_FMT

    if verbose:
        log_level_int = VERBOSE_LOG_LVL
        log_fmt = VERBOSE_LOG_FMT
    if silent:
        log_level_int = SILENT_LOG_LVL

    if log_level is not None:
        log_level_int = LOGGER_LEVEL_MAP[log_level.upper()]

    _logging.basicConfig(format=log_fmt, level=log_level_int)

cli_cmd.add_command(_decode)
cli_cmd.add_command(_pcap)



# def register_to_group(group: _click.Group):
#     """
#     register adds the moonlight cli commands to a click group

#     Args:
#         group (click.Group): `click` cli command group
#     """
#     # _analyze.register(group)
#     _decode.register(group) # type: ignore
#     _pcap.register(group) # type: ignore

