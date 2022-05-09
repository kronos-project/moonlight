"""
Classes related to working with pcap files. Since importing `scapy`
is a very heavy operation, lazily import this package whenever possible.
"""

from .capture import is_ki_packet_naive, LiveSniffer, PcapReader, filter_pcap
