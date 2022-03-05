"""
    Classes dealing with the framing of KI game packets. Also holds the whole
    KI protocol wrapper.
"""

import os.path
from os import PathLike
from os.path import isfile, listdir, join

from scapy.utils import PcapReader
from moonlight.ki.control import ControlDecoder, ControlProtocol

from moonlight.ki.dml import DMLProtocol

from .net_common import *


# class KIStreamReaderTo:
#     def __init__(
#         self,
#         msg_def_folder: PathLike = os.path.join(
#             os.path.dirname(__file__), "..", "..", "res", "dml", "messages"
#         ),
#         typedef_file: PathLike = None,
#         pcap_file: PathLike = None,
#     ) -> None:



class KIStreamReader:
    def __init__(
        self,
        typedef_file: PathLike,
        pcap_file: PathLike = None,
        msg_def_folder: PathLike = os.path.join(
            os.path.dirname(__file__), "..", "..", "res", "dml", "messages"
        )
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
        self.control_decoder: ControlProtocol = ControlProtocol()
        BytestreamReader(bites="", type_file=typedef_file)

    def __iter__(self):
        return self

    def decode_packet(
        self, reader: BytestreamReader, original_data: bytes = None, **kwargs
    ) -> KIMessage:
        reader = None
        header = None
        if type(reader) == bytes:
            reader = BytestreamReader(reader)

        try:
            header = KIPacketHeader(reader)
        except ValueError:
            logging.debug("Invalid packet received: bad KI header")
            return None

        if header.content_is_control != 0:
            return self.control_decoder.decode_packet(reader, header)
        else:
            return self.dml_decoder.decode_packet(reader, header)
