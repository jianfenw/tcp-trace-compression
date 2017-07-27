import dpkt

from dpkt.tcp import TH_ACK
from tcp_endpoint import *


class TcpFlow():

    def __init__(self, annotated_packet):
        # endpoint_a: source, endpoint_b: destination
        self.endpoint_a = TcpEndpoint(annotated_packet, True)
        self.endpoint_b = TcpEndpoint(annotated_packet, False)
        #self.count = 0
        self.packets = []

    def add_packet(self, annotated_packet, process_packet=True):
        """Adds a new packet associated with this flow. Both endpoint will use the
        packet to update their internal state if process_packet is set to True."""
        ip = annotated_packet.packet.ip
        if self.endpoint_a.ip == ip.src and self.endpoint_a.port == ip.tcp.sport:
            current_sender = self.endpoint_a
            current_receiver = self.endpoint_b
        else:
            current_sender = self.endpoint_b
            current_receiver = self.endpoint_a

        wire_packets = current_sender.add_packet(annotated_packet, process_packet)
        self.packets.extend(wire_packets)

        if process_packet and ip.tcp.flags & TH_ACK:
            current_receiver.process_ack(annotated_packet)
            #print annotated_packet.packet.ip.tcp.ack

    def post_process(self):
        self.endpoint_a.set_passed_bytes_for_packets()
        self.endpoint_b.set_passed_bytes_for_packets()