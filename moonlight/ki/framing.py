import os.path
from os import PathLike
from os.path import isfile, listdir, join

from scapy.utils import PcapReader
from moonlight.ki.control import ControlDecoder

from moonlight.ki.dml import DMLProtocol

from .net_common import *


class KIStreamReader:
    def __init__(
        self,
        pcap_file: PathLike = None,
        msg_def_folder: PathLike = os.path.join(
            os.path.dirname(__file__), "..", "..", "res", "dml", "messages"
        ),
    ) -> None:
        self.pcap_file = pcap_file
        self.msg_def_folder = msg_def_folder
        self.pcap_reader: PcapReader = None

        if isfile(pcap_file):
            self.pcap_reader = PcapReader(pcap_file)
        else:
            raise ValueError("Provided pcap filepath doesn't exist")

        # Load dml decoder
        dml_services = [
            f for f in listdir(msg_def_folder) if isfile(join(msg_def_folder, f))
        ]
        dml_services = map(lambda x: join(msg_def_folder, x), dml_services)
        self.dml_decoder = DMLProtocol(*dml_services)

        # Load control decoder
        self.control_decoder = ControlDecoder()

    def __iter__(self):
        return self

    def decode_packet(
        self, reader: BytestreamReader, original_data: bytes = None, **kwargs
    ) -> KIMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)

        try:
            header = KIPacketHeader(reader)
        except ValueError:
            logging.debug("Invalid packet received: bad KI header")
            return None

        if header.content_is_control != 0:
            logging.debug("is a control message")
            return None
        if header.control_opcode != 0:
            logging.warn("umm. it says not a control, but I got control data. wat.")
            return None
