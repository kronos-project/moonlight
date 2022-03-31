"""
    Provides capture utilities for working with KI game network data
"""

import logging
import os
import sys
import traceback
from os import PathLike, listdir
from os.path import isfile, join

from scapy.layers.inet import TCP
from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer
from scapy.sessions import TCPSession
from scapy.utils import PcapReader as Scapy_PcapReader, PcapWriter as Scapy_PcapWriter

from .common import BytestreamReader, PacketHeader
from .control import ControlMessage, ControlProtocol
from .dml import DMLMessage, DMLProtocolRegistry


def is_ki_packet_naive(packet: Packet):
    return (
        TCP in packet.layers()
        and isinstance(packet[TCP].payload, Raw)
        and bytes(packet[TCP].payload).startswith(b"\x0D\xF0")
    )


class PacketReader:
    def __init__(
        self,
        msg_def_folder: PathLike,
        typedef_path: PathLike = None,
    ):
        self.msg_def_folder = msg_def_folder

        # Load dml decoder
        dml_services = [
            f for f in listdir(msg_def_folder) if isfile(join(msg_def_folder, f))
        ]
        dml_services = map(lambda x: join(msg_def_folder, x), dml_services)
        self.dml_protocol = DMLProtocolRegistry(
            *dml_services, typedef_path=typedef_path
        )

        # Load control decoder
        self.control_protocol: ControlProtocol = ControlProtocol()

    def decode_packet(self, bites: bytes) -> ControlMessage | DMLMessage:
        if isinstance(bites, bytes):
            reader = BytestreamReader(bites)
        else:
            raise ValueError("bites is not of type bytes")

        try:
            header = PacketHeader(reader)
        except ValueError:
            logging.debug("Invalid packet received: bad KI header")
            return None

        if header.content_is_control != 0:
            return self.control_protocol.decode_packet(
                reader, header, original_data=bites
            )

        return self.dml_protocol.decode_packet(bites)


class PcapReader(PacketReader):
    def __init__(
        self,
        pcap_path: PathLike,
        typedef_path: PathLike = None,
        msg_def_folder: PathLike = os.path.join(
            os.path.dirname(__file__), "..", "..", "res", "dml", "messages"
        ),
    ) -> None:
        super().__init__(msg_def_folder, typedef_path=typedef_path)
        if not isfile(pcap_path):
            raise ValueError("Provided pcap filepath doesn't exist")

        self.pcap_path = pcap_path
        self.pcap_reader = Scapy_PcapReader(filename=pcap_path)

    def __iter__(self):
        return self

    def next_ki_raw(self):
        while True:
            packet = self.pcap_reader.next()
            if not is_ki_packet_naive(packet):
                continue
            return packet

    def __next__(self):
        return self.decode_packet(self.next_ki_raw()[TCP].payload)

    def close(self):
        self.pcap_reader.close()


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
        if type(pkt[TCP].payload) is not Raw:
            return
        try:
            bites = bytes(pkt[TCP].payload)
            message = self.decoder.decode_packet(bites)
            logging.info(message)
        except ValueError as err:
            if str(err).startswith("Not a KI game protocol packet."):
                logging.debug(err)
                return
            logging.error("Cannot parse packet: %s", traceback.print_exc())

    def open_livestream(self):
        self.stream = AsyncSniffer(
            filter="dst host 79.110.83.12 or src host 79.110.83.12",
            session=TCPSession,
            prn=self.scapy_callback,
        )
        logging.info("Starting sniffer")
        self.stream.start()
        logging.info("Waiting for end signal")
        self.stream.join()

    def close_livestream(self):
        self.stream.stop()


def filter_pcap(p_in: PathLike, p_out: PathLike):
    reader = PcapReader(p_in)
    writer = Scapy_PcapWriter(p_out)
    logging.info("Filtering file '%s' to ki only traffic ('%s')", p_in, p_out)
    try:
        i = 1
        while True:
            packet = reader.next_ki_raw()
            writer.write(packet)
            i += 1
            if i % 100 == 0:
                logging.info("Filtering in progress. Found %s KI packets so far" % i)
    except StopIteration:
        pass
    except KeyboardInterrupt:
        print("Cutting filtering short and finalizing")
    finally:
        reader.close()
        writer.close()


if __name__ == "__main__":
    logging.basicConfig(
        # format="[%(asctime)s] %(levelname)s: %(message)s",
        format="%(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG,
        handlers=[
            # logging.FileHandler(os.path.join(os.path.dirname(__file__), '..', 'log', 'out.log')),
            logging.StreamHandler(sys.stdout),
        ],
    )
    print("hi")
    s = LiveSniffer()
    print("Opening packet stream")

    s.open_livestream()
