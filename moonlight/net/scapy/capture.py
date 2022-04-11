"""
    Provides capture utilities for working with KI game network data
"""

import logging
import os
import traceback
from os import PathLike, listdir
from os.path import isfile, join

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

from moonlight.net import PacketReader


logger = logging.getLogger(__name__)


def is_ki_packet_naive(packet: Packet):
    return (
        TCP in packet.layers()
        and isinstance(packet[TCP].payload, Raw)
        and bytes(packet[TCP].payload).startswith(b"\x0D\xF0")
    )


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

    def __next__(self):
        return self.decode_packet(bytes(self.next_ki_raw()[TCP].payload))

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
    ):
        self.stream = None
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
            filter="dst host 79.110.83.12 or src host 79.110.83.12",
            session=TCPSession,
            prn=self.scapy_callback,
        )
        logger.info("Starting sniffer")
        self.stream.start()
        logger.info("Waiting for end signal")
        self.stream.join()

    def close_livestream(self):
        self.stream.stop()


def filter_pcap(p_in: PathLike, p_out: PathLike, compress: bool = False):
    reader = PcapReader(p_in)
    writer = Scapy_PcapWriter(p_out, gz=compress)
    logger.info("Filtering pcap to ki traffic only: in=%s, out=%s", p_in, p_out)
    try:
        i = 1
        while True:
            packet = reader.next_ki_raw()
            writer.write(packet)
            i += 1
            if i % 100 == 0:
                logger.info("Filtering in progress. Found %s KI packets so far", i)
    except StopIteration:
        pass
    except KeyboardInterrupt:
        logger.warning("Cutting filtering short and finalizing")
    finally:
        reader.close()
        writer.close()
