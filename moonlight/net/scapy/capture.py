"""Provides capture utilities for working with KI game network data"""

from __future__ import annotations

import logging
import os
import os.path
import traceback
from datetime import datetime
from os import PathLike, listdir
from os.path import isfile
from pathlib import Path
from typing import Callable, cast
from moonlight.net.control import ControlMessage

# scapy on import prints warnings about system interfaces
# pylint: disable=wrong-import-position disable=wrong-import-order
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import TCP
from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer
from scapy.sessions import TCPSession
from scapy.utils import PcapReader as Scapy_PcapReader
from scapy.utils import PcapWriter as Scapy_PcapWriter

# and now let's set that back
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)
# pylint: enable=wrong-import-position

from moonlight.net import (
    KIHeader,
    Message,
    MessageSender,
    PacketReader,
    SessionAcceptMessage,
    SessionOfferMessage,
)

logger = logging.getLogger(__name__)
SENSITIVE_MSG_OPCODES = [SessionAcceptMessage.OPCODE, SessionOfferMessage.OPCODE]


def is_interesting_packet_naive(packet: Packet) -> bool:
    """
    Naively determines if a packet is one moonlight is capable of decoding

    Args:
        packet (Packet): packet

    Returns:
        bool: the packet is interesting
    """
    return TCP in packet.layers() and isinstance(packet[TCP].payload, Raw)


def is_ki_packet_naive(packet: Packet) -> bool:
    """
    is_ki_packet_naive naively determines if a packet is from Wizard101. Assumes
        that the packet has been checked with `is_interesting_packet_naive`
        first

    Args:
        packet (Packet): packet checked with `is_interesting_packet_naive`

    Returns:
        bool: `True` if the packet is from KI
    """
    return bytes(packet[TCP].payload).startswith(b"\x0D\xF0")


def is_flagtool_packet_naive(packet: Packet) -> bool:
    """
    is_flagtool_packet_naive naively determines if a packet is from the
        netpack flagtool. Assumes that the packet has been checked with
        `is_interesting_packet_naive` first.

    Args:
        packet (Packet): packet checked with `is_interesting_packet_naive`

    Returns:
        bool: `True` if the packet is from flagtool
    """
    return packet[TCP].dport == MessageSender.FLAGTOOL.value


class PcapReader(PacketReader):
    """
    PcapReader is a wrapper around `scapy.utils.PcapReader` for traffic
        moonlight is capable of decoding. Packets that are not determined
        to be from a supported system are ignored.
    """

    def __init__(
        self,
        pcap_path: PathLike,
        msg_def_folder: PathLike,
        typedef_path: PathLike | None = None,
        silence_decode_errors: bool = False,
    ) -> None:
        super().__init__(
            msg_def_folder,
            typedef_path=typedef_path,
            silence_decode_errors=silence_decode_errors,
        )
        if not isfile(pcap_path):
            raise ValueError("Provided pcap filepath doesn't exist")

        self.pcap_path = pcap_path
        self.pcap_reader = Scapy_PcapReader(filename=str(pcap_path))
        self.last_decoded: Message | None = None
        self.last_decoded_raw: Packet | None = None

    def __iter__(self):
        return self

    def next_interesting_raw(self) -> Packet | None:
        """
        next_interesting_raw gets the next packet of interest from the current
            capture and returns it as a standard `scapy.packet.Packet`

        Returns:
            scapy.packet.Packet | None: Next interesting packet or None if at
                the end of the capture
        """
        while True:
            packet = self.pcap_reader.next()
            if not (
                is_interesting_packet_naive(packet)
                and (is_ki_packet_naive(packet) or is_flagtool_packet_naive(packet))
            ):
                continue
            self.last_decoded = None
            self.last_decoded_raw = packet
            return packet
        return None

    def __next__(self) -> Message:
        pkt = self.next_interesting_raw()
        if pkt is None:
            raise StopIteration()

        if is_flagtool_packet_naive(pkt):
            msg = self.decode_flagtool_packet(bytes(pkt[TCP].payload))
        else:  # this is an already checked assumption in next_interesting_raw
            msg = self.decode_ki_packet(bytes(pkt[TCP].payload))

        # populate capture-only data since, well, this is a capture
        if msg is not None:
            msg.sender = MessageSender.from_capture_port(pkt[TCP].dport)
            msg.timestamp = datetime.fromtimestamp(float(pkt.time))
        self.last_decoded = msg
        return msg

    def close(self) -> None:
        """
        close closes the wrapped pcap reader
        """
        self.pcap_reader.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class LiveSniffer(PacketReader):
    """
    Live traffic sniffer for Wizard101. Relies on the connection being unencrypted
    """

    def __init__(
        self,
        filter_str: str,
        callback: Callable[[Message, Packet], None],
        msg_def_folder: PathLike,
        iface: str = "lo0",
        client_port: int | None = None,
        typedef_path: PathLike | None = None,
        silence_decode_errors: bool = False,
    ):
        super().__init__(msg_def_folder, typedef_path, silence_decode_errors)
        self.filter_str = filter_str
        self.callback = callback
        self.iface = iface
        self.client_port = client_port
        self.sniffer = None

    def _scapy_callback(self, pkt: Packet):
        if not is_interesting_packet_naive(pkt) or not is_ki_packet_naive(pkt):
            return
        try:
            self._extracted_from__scapy_callback_5(pkt)
        except ValueError as err:
            if str(err).startswith("Not a KI game protocol packet."):
                logger.debug(err)
                return
            logger.error("Cannot parse packet: %s", traceback.print_exc())

    # TODO Rename this here and in `_scapy_callback`
    def _extracted_from__scapy_callback_5(self, pkt):
        bites = bytes(pkt[TCP].payload)
        message = self.decode_ki_packet(bites)
        message.timestamp = datetime.now()
        if pkt[TCP].dport == self.client_port:
            message.sender = MessageSender.CLIENT
        elif self.client_port:
            message.sender = MessageSender.SERVER

        logger.debug("Captured message: %s", message)
        self.callback(message, pkt)

    def open_livestream(self):
        """
        open_livestream starts sniffing using the set filter, waiting for either
            a SIGINT signal or for `close_livestream` to be called
        """
        self.sniffer = AsyncSniffer(
            filter=self.filter_str,
            session=TCPSession,
            prn=self._scapy_callback,
            iface=self.iface,
        )
        logger.info("Starting sniffer")
        self.sniffer.start()
        logger.info("Waiting for end signal (SIGINT)")
        self.sniffer.join()

    def close_livestream(self, join=True):
        """
        close_livestream interrupts an ongoing sniffing session via
            `open_livestream`, releasing the lock and causing the method
            to exit.

        Args:
            join (bool, optional): Wait for the livestream to
                exit before returning. Defaults to True.
        """
        if self.sniffer:
            self.sniffer.stop(join=join)


def sanitize_signed_msg(pkt_reader: PacketReader, payload: bytes) -> bytes:
    """
    sanitize_signed_msg takes messages with sensitive info (session offer/accept)
        and sets their sensitive content to 0s.

    Args:
        pkt_reader (PacketReader): reader to use when decoding the message
            contents
        payload (bytes): message to sanitize. Full frame is expected.

    Raises:
        ValueError: provided payload could not be decoded to a message

    Returns:
        bytes: payload sanitized of any sensitive information
    """
    header = KIHeader.from_bytes(payload)
    if (
        header.content_is_control
        and header.control_opcode == SessionOfferMessage.OPCODE
    ):
        try:
            # Sizing chart
            # header:         8 :  0 -  7
            # session_id:     2 :  7 -  9
            # sec_timestamp:  8 :  9 - 17
            # millis_into:    4 : 17 - 21
            # signed_msg_len: 4 : 21 - 25
            # signed_msg:     ? : 26 -  ?
            decoded = cast(SessionOfferMessage, pkt_reader.decode_ki_packet(payload))
            old_payload = payload
            # Replace signed msg with zeros
            new_payload = (
                old_payload[:26]
                + (b"\x00" * decoded.signed_msg_len)
                + old_payload[26 + decoded.signed_msg_len :]
            )
            logger.debug(
                "Sanitized session offer packet",
                extra={"old": old_payload, "new": new_payload},
            )
            return new_payload
        except ValueError as exc:
            raise ValueError(
                "Unable to sanitize session offer due to decode error"
            ) from exc
    elif (
        header.content_is_control
        and header.control_opcode == SessionAcceptMessage.OPCODE
    ):
        try:
            # Sizing chart - len : start inclusive - end exclusive
            # header:         8 :  0 -  8
            # reserved_start: 2 :  8 - 10
            # sec_timestamp:  8 : 10 - 18
            # millis_into:    4 : 18 - 22
            # session_id:     2 : 22 - 24
            # signed_msg_len: 4 : 24 - 28
            # signed_msg:     ? : 28 -  ?
            decoded = cast(SessionAcceptMessage, pkt_reader.decode_ki_packet(payload))
            old_payload = payload
            # Replace signed msg with zeros
            new_payload = (
                old_payload[:28]
                + (b"\x00" * decoded.signed_msg_len)
                + old_payload[28 + decoded.signed_msg_len :]
            )
            logger.debug(
                "Sanitized session accept packet. Was '{old_payload}', "
                "now '{new_payload}'"
            )
            return new_payload
        except ValueError as exc:
            raise ValueError(
                "Unable to sanitize session accept due to decode error"
            ) from exc
    return payload


def filter_pcap(
    msg_def_folder: PathLike,
    p_in: Path,
    p_out: Path,
    compress: bool = False,
    sanitize: bool = False,
) -> None:
    """
    filter_pcap removes traffic that moonlight cannot parse from a pcap file.
        Optionally, it can also remove sensitive data from Wizard101 messages,
        mainly session information.

    Args:
        msg_def_folder: path to message definitions
        p_in (Path): pcap file to filter
        p_out (Path): path to write new, filtered pcap to
        compress (bool, optional): compresses the output pcap using the
            gz algorithm. Defaults to False.
        sanitize (bool, optional): Remove sensitive information from packets
            while filtering. Defaults to False.

    Raises:
        Exception: when underlying pcap message cannot be parsed or
            something should have been sanitized but failed
    """
    reader = PcapReader(p_in.absolute().resolve(), msg_def_folder=msg_def_folder)
    writer = Scapy_PcapWriter(str(p_out.absolute().resolve()), gz=compress)
    logger.info("Filtering pcap to ki traffic only: in=%s, out=%s", p_in, p_out)
    if sanitize:
        logger.info(
            "Sanitation is on. SessionOffer and Accept control message signatures will be zeroed out"
        )
    try:
        i = 1
        while True:
            packet = reader.next_interesting_raw()
            if packet is None:
                raise StopIteration()
            if (
                sanitize
                and is_ki_packet_naive(packet)
                and KIHeader.from_bytes(bytes(packet[TCP].payload)).content_is_control
            ):
                try:
                    dirty_data = bytes(packet[TCP].payload)
                    sanitized_data = sanitize_signed_msg(reader, dirty_data)
                    if sanitized_data != dirty_data:
                        packet[TCP].payload = sanitize_signed_msg(
                            reader, packet[TCP].payload
                        )
                        packet[TCP].checksum = None
                except ValueError:
                    logger.error("Message sanitation failed", exc_info=True)
            writer.write(packet)
            i += 1
            if i % 100 == 0:
                logger.info(
                    "Filtering in progress. Found %s interesting packets so far", i
                )
    except StopIteration:
        pass
    except KeyboardInterrupt:
        logger.warning("Cutting filtering short and finalizing")
    except Exception as err:  # pylint: disable=broad-except
        raise RuntimeError(
            "Unrecoverable error occurred while filtering pcap file"
        ) from err
    finally:
        reader.close()
        writer.close()
