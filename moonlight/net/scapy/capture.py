"""
    Provides capture utilities for working with KI game network data
"""

from datetime import datetime
import logging
import os
from pathlib import Path
import traceback
from os import PathLike, listdir
from os.path import isfile, join

from moonlight.net.common import MessageSender, Message

# scapy on import prints warnings about system interfaces
# pylint: disable=wrong-import-position
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
    PacketReader,
    PacketHeader,
    SessionAcceptMessage,
    SessionOfferMessage,
)


logger = logging.getLogger(__name__)
SENSITIVE_MSG_OPCODES = [SessionAcceptMessage.OPCODE, SessionOfferMessage.OPCODE]


def is_ki_packet_naive(packet: Packet):
    return (
        TCP in packet.layers()
        and isinstance(packet[TCP].payload, Raw)
        and bytes(packet[TCP].payload).startswith(b"\x0D\xF0")
    )


def is_sensitive_packet_naive(packet: Packet):
    bytes(packet[TCP].payload).startswith(b"\x0D\xF0")


class PcapReader(PacketReader):
    def __init__(
        self,
        pcap_path: PathLike,
        typedef_path: PathLike = None,
        msg_def_folder: PathLike = os.path.join(
            os.path.dirname(__file__), "..", "..", "res", "dml", "messages"
        ),
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

    def __iter__(self):
        return self

    def next_ki_raw(self):
        while True:
            packet = self.pcap_reader.next()
            if not is_ki_packet_naive(packet):
                continue
            return packet

    def __next__(self) -> Message:
        pkt = self.next_ki_raw()
        msg = self.decode_packet(bytes(pkt[TCP].payload))
        if msg is not None:
            msg.sender = MessageSender.from_capture_port(pkt[TCP].dport)
            msg.timestamp = datetime.fromtimestamp(float(pkt.time))
        return msg

    def close(self):
        self.pcap_reader.close()

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class LiveSniffer:
    def __init__(
        self,
        dml_def_folder: PathLike = os.path.join(
            os.path.dirname(__file__), "..", "res", "dml", "messages"
        ),
        target_ip: str = "127.0.0.1",
    ):
        self.stream = None
        self.target_ip = target_ip
        protocols = [
            f for f in listdir(dml_def_folder) if isfile(join(dml_def_folder, f))
        ]
        protocols = map(lambda x: join(dml_def_folder, x), protocols)
        self.decoder = PacketReader(msg_def_folder=dml_def_folder)

    def scapy_callback(self, pkt: Packet):
        if not isinstance(pkt[TCP].payload, Raw):
            return
        try:
            bites = bytes(pkt[TCP].payload)
            message = self.decoder.decode_packet(bites)
            logger.info(message)
        except ValueError as err:
            if str(err).startswith("Not a KI game protocol packet."):
                logger.debug(err)
                return
            logger.error("Cannot parse packet: %s", traceback.print_exc())

    def open_livestream(self):
        self.stream = AsyncSniffer(
            filter=f"dst host {self.target_ip} or src host {self.target_ip}",
            session=TCPSession,
            prn=self.scapy_callback,
        )
        logger.info("Starting sniffer")
        self.stream.start()
        logger.info("Waiting for end signal")
        self.stream.join()

    def close_livestream(self):
        self.stream.stop()


def sanitize_signed_msg(pkt_reader: PacketReader, payload: bytes) -> bytes:
    header = PacketHeader(payload)
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
            decoded = pkt_reader.decode_packet(payload)
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
            decoded = pkt_reader.decode_packet(payload)
            old_payload = payload
            # Replace signed msg with zeros
            new_payload = (
                old_payload[:28]
                + (b"\x00" * decoded.signed_message_len)
                + old_payload[28 + decoded.signed_message_len :]
            )
            logger.debug(
                "Sanitized session accept packet",
                extra={"old": old_payload, "new": new_payload},
            )
            return new_payload
        except ValueError as exc:
            raise ValueError(
                "Unable to sanitize session accept due to decode error"
            ) from exc
    return payload


def filter_pcap(
    p_in: Path, p_out: Path, compress: bool = False, sanitize: bool = False
):
    reader = PcapReader(str(p_in.absolute().resolve()), msg_def_folder=None)
    writer = Scapy_PcapWriter(str(p_out.absolute().resolve()), gz=compress)
    logger.info("Filtering pcap to ki traffic only: in=%s, out=%s", p_in, p_out)
    if sanitize:
        logger.info(
            "Sanitation is on. SessionOffer and Accept control message signatures will be zeroed out"
        )
    try:
        i = 1
        while True:
            packet = reader.next_ki_raw()
            if sanitize and PacketHeader(bytes(packet[TCP].payload)).content_is_control:
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
                logger.info("Filtering in progress. Found %s KI packets so far", i)
    except StopIteration:
        pass
    except KeyboardInterrupt:
        logger.warning("Cutting filtering short and finalizing")
    except Exception:
        logger.critical(
            "Unrecoverable error occurred while filtering pcap file", exc_info=True
        )
    finally:
        reader.close()
        writer.close()
