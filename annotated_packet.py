import dpkt

from dpkt.tcp import *
from tcp_util import *

"""
    The AnnotatedPacket data struct contains necessary information for our compression and analysis.
    When a tcp_endpoint adds packets to its packet list, it will compute some features of 
    the Annotated Packets.
"""
class AnnotatedPacket(object):
    def __init__(self, packet, timestamp_us, index):
        # self.packet = 'eth': self.packet.ip.tcp.sport = source port number
        # index = the (index)-th input packet (Ethernet packet)
        self.packet = packet
        self.timestamp_us = timestamp_us
        self.index = index
        self.ack_delay_ms = -1
        self.ack_index = -1

        # rtx = the retransmission packet of self.packet
        # previous_tx = self.packet is the retransmission of the previous_tx
        self.rtx = None
        self.rtx_is_spurious = False
        self.previous_tx = None
        self.previous_packet = None
        
        # data_len: used to compute the goodput
        self.data_len = tcp_data_len(self)
        
        # self.seq = the absolute seq number of the packet (32 bits long)
        self.seq = packet.ip.tcp.seq
        self.seq_end = add_offset(self.seq, self.data_len)

        # Replace raw option buffer by a parsed version
        self.packet.ip.tcp.opts = parse_opts(self.packet.ip.tcp.opts)

        self.ack = packet.ip.tcp.ack

        # Relative sequence numbers are set by the TCP endpoint
        # (requires knowledge about the initial sequence numbers)
        self.seq_relative = -1
        self.ack_relative = -1

        # Bytes that were received successfully by the other endpoint
        # (packets transmitted before this one)
        self.bytes_passed = -1

    def is_lost(self):
        # A packet is considered as a lost packet when it has a retransmission and also 
        # the retransmission is necessary.
        return self.rtx is not None and not self.rtx_is_spurious

    def update_length_and_offset(self, new_length, offset):
        """Update the sequence numbers and payload length (used when splitting
        a jumbo packet into smaller on-the-wire frames"""
        self.data_len = new_length
        tcp_set_data_len(self, new_length)
        assert self.data_len == tcp_data_len(self)

        tcp = self.packet.ip.tcp
        self.seq = tcp.seq = add_offset(self.seq, offset)
        self.seq_end = add_offset(self.seq, self.data_len)

        # trim buffer storing actual payload
        if len(tcp.data) <= offset:
            tcp.data = []
        else:
            buf_start = offset
            buf_end = min(len(tcp.data), offset + new_length)
            tcp.data = tcp.data[buf_start:buf_end]
