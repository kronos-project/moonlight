"""
    Provides capture utilities for working with KI game network data
"""

import logging
import os
import traceback

from moonlight.ki.framing import KIStreamReader
from .dml import DMLProtocol, DMLMessage
import sys
from scapy.all import IP, TCP
from scapy.packet import NoPayload, Packet, Raw
from scapy.sendrecv import AsyncSniffer, sniff
from scapy.sessions import TCPSession

from os import PathLike, listdir
from os.path import isfile, join


class KIPacketSniffer:
    def __init__(self, dml_def_folder: PathLike = os.path.join(
            os.path.dirname(__file__), "..", "res", "dml", "messages"
        )):
        self.stream = None
        protocols = [f for f in listdir(dml_def_folder) if isfile(join(dml_def_folder, f))]
        protocols = map(lambda x: join(dml_def_folder, x), protocols)
        self.decoder = KIStreamReader(msg_def_folder=dml_def_folder)

    def scapy_callback(self, pkt: Packet):
        if type(pkt[TCP].payload) is not Raw:
            return
        try:
            message = self.decoder.decode_packet(bytes(pkt[TCP].payload))
            logging.info(message)
        except:
            logging.error(f"Cannot parse packet: {traceback.print_exc()}")

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
    s = KIPacketSniffer()
    print("Opening packet stream")

    s.open_livestream()
