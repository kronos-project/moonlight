from os import PathLike, listdir
from os.path import isfile, join
import logging

from .control import ControlProtocol, ControlMessage
from .dml import DMLMessage, DMLProtocolRegistry
from .flagtool import FlagtoolMessage
from .common import Message, KIHeader, BytestreamReader

logger = logging.getLogger(__name__)


class PacketReader:
    """
    Reader for moonlight-compatible message data. Requires a path to a folder
    containing extracted root wad message definitions. Optionally takes a
    path to wizwalker typedefs for further decoding of objectproperty.
    """

    def __init__(
        self,
        msg_def_folder: PathLike,
        typedef_path: PathLike | None = None,
        silence_decode_errors: bool = False,
    ):
        """
        __init__

        Args:
            msg_def_folder (PathLike): folder containing extracted root wad
                message definitions. These are xml files named "*Messages[0-9]?.xml"
                containing "service" definitions, however the naming is
                somewhat inconsistent within the file, so moonlight calls
                them protocols for simplicity's sake.
            typedef_path (PathLike, optional): wizwalker typedefs, used to
                decode objectproperties. Defaults to None.
            silence_decode_errors (bool, optional): when a message cannot be
                decoded, return None instead of raising an error.
                Defaults to False.
        """
        self.msg_def_folder = msg_def_folder
        self.silence_decode_errors = silence_decode_errors

        # Load dml decoder
        if msg_def_folder is not None:
            dml_services = [
                f for f in listdir(msg_def_folder) if isfile(join(msg_def_folder, f))
            ]
        else:
            dml_services = []
        dml_services = map(lambda x: join(msg_def_folder, x), dml_services)
        self.dml_protocol = DMLProtocolRegistry(
            *dml_services, typedef_path=typedef_path
        )

        # Load control decoder
        self.control_protocol: ControlProtocol = ControlProtocol()

    def _handle_decode_exc(self, exc, original_bytes):
        if self.silence_decode_errors:
            logger.debug(
                "An error occurred while attempting to decode a packet. Original bytes are %s",
                original_bytes,
            )
            return
        raise ValueError(
            "Invalid packet data or message definitions", original_bytes
        ) from exc

    def decode_flagtool_packet(self, bites: bytes) -> FlagtoolMessage | None:
        """
        decode_flagtool_packet decodes a flagtool packet. Nuff' said.

        Args:
            bites (bytes): message contents

        Returns:
            FlagtoolMessage: objectproperty serialization data
        """

        try:
            return FlagtoolMessage.from_bytes(bites)
        except ValueError as err:
            # error handling and returns are dependent on reader settings
            return self._handle_decode_exc(err, bites)

    def decode_ki_packet(self, bites: bytes) -> Message | None:
        """
        decode_ki_packet decodes a ki message into a DML or Control message

        Args:
            bites (bytes): message contents

        Returns:
            Message: decoded message
        """

        if isinstance(bites, bytes):
            reader = BytestreamReader(bites)
        else:
            raise ValueError(f"bites is not of type bytes. Found {type(bites)}")

        packets: list[ControlMessage | DMLMessage] = []

        try:
            header = KIHeader.from_bytes(reader)
            # 4 bytes remain in what we consider the header but KI doesn't
            if header.content_len < reader.bytes_remaining() + 4:
                logger.warning(
                    "Provided packet bytes contain more than KI's framing "
                    "expected. There may be more than one message in this packet "
                    "which is not yet supported. Expected %d, found %d",
                    header.content_len,
                    reader.bytes_remaining(),
                )
                # packets.extend(self.decode_packet(bites[:]))

            if header.content_is_control != 0:
                return self.control_protocol.decode_packet(
                    reader, header, original_data=bites, has_ki_header=False
                )

            return self.dml_protocol.decode_packet(bites)

        except ValueError as exc:  # pylint: disable=broad-except
            # error handling and returns are dependent on reader settings
            return self._handle_decode_exc(exc, bites)
