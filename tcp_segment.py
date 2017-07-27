import dpkt

from tcp_flow import *

def split_flow_into_segments(flow):
    """
    Splits the flow into multiple segments where a segment is defined by: 
    data only from endpoint A (source -- request) followed by data only from
    endpoint B (destination -- response). 
    New data from endpoint A initiates a new segment.
    Returns: list of TcpFlow instances with each instance representing a segment
    """
    segments = []
    if len(flow.packets) == 0:
        return segments

    current_sender = flow.endpoint_a
    current_segment = TcpFlow(flow.packets[0])
    segments.append(current_segment)
    for packet in flow.packets:
        """
        if packet.packet.ip.src == flow.endpoint_a.ip and \
            packet.packet.ip.tcp.sport == flow.endpoint_a.port:
            print 1, packet.data_len
        else:
            print 0, packet.data_len
        """
        if packet.data_len == 0:
            if len(current_segment.packets) > 0:
                current_segment.add_packet(packet, False)
            continue
            
        # For a one-direction transmission, the first data packet starts a new segment. 
        ip = packet.packet.ip
        if current_sender.ip != ip.src or current_sender.port != ip.tcp.sport:
            if current_sender == flow.endpoint_a:
                current_sender = flow.endpoint_b
            else:
                current_sender = flow.endpoint_a
                current_segment = TcpFlow(packet)
                segments.append(current_segment)
        current_segment.add_packet(packet, False)
    return segments
    