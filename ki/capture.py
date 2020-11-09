import logging
import traceback
from types import TracebackType
from kinp import WizDMLDecoder, DMLMessageObject
import sys
from scapy.all import sr1, IP, ICMP, TCP
from scapy.packet import NoPayload, Packet, Raw
from scapy.sendrecv import AsyncSniffer, sniff
from scapy.sessions import TCPSession

from os import listdir
from os.path import isfile, join


class KIPacketSniffer:
    def __init__(self):
        self.stream = None
        res_folder = "/Users/ethanzeigler/Programming/offshot projects/KI/moonlight/res/dml/messages/"
        protocols = [f for f in listdir(res_folder) if isfile(join(res_folder, f))]
        protocols = map(lambda x: join(res_folder, x), protocols)
        self.decoder = WizDMLDecoder(*protocols)

    def scapy_callback(self, pkt: Packet):
        if type(pkt[TCP].payload) is Raw:
            try:
                raw = bytes(pkt[TCP].payload)
                decoded = self.decoder.decode_message(raw)
                if type(decoded) is DMLMessageObject:
                    if pkt[IP].src == "165.193.54.36":
                        decoded.source = "server"
                    else:
                        decoded.source = "client"
                logging.info(decoded)
            except:
                logging.error(f"Cannot parse packet: {traceback.print_exc()}")

    def open_livestream(self):
        self.stream = AsyncSniffer(
            filter="src net 165.193.0.0/16 or dst net 165.193.0.0/16",
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
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler("moonlight.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    print("hi")
    s = KIPacketSniffer()
    print("Opening packet stream")
    
    s.open_livestream()
