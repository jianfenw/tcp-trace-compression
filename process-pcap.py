""""

This engine is used to process the packets stored in a .pcap file. 
The .pcap phare is based on dpkt.

First, it will assign each packet to a flow on the 4-tuple (src/des * IP address/port number)

Second, each flow is then devided into segments, where a segment is defined as data from
endpoint A followed by data from endpoint B (i.e. a typical request/response model)

Third, the tcp time-sequence number plot is then compressed

output:
<input filename>, <flow index>, <segment index>, <direction>, <number of data packets>

<direction>: either "a-->b" or "b-->a"

"""
import dpkt
import sys

from annotated_packet import *
from tcp_flow import *
from tcp_segment import *
from tcp_util import *
from ts_compress import *
from policing_detector import *

MAX_NUM_PACKETS = 1000

if len(sys.argv) < 2:
	print "Missing input file"
	print "Usage: python %s <input file>" %(sys.argv[0])
	exit(-1)
input_filename = sys.argv[1]

# input_filename = "test.pcap"
input_file = open(input_filename)
pcap = dpkt.pcap.Reader(input_file)

flows = dict()
# index is the # of packet (start from 0 -> MAX_NUM_PACKETS)
index = 1
for ts, buf in pcap:
	if MAX_NUM_PACKETS != -1 and index > MAX_NUM_PACKETS:
		break
	eth = dpkt.ethernet.Ethernet(buf)
	#print ts, " ", eth.ip.tcp.sport, eth.ip.tcp.dport, eth.ip.tcp.seq
	try:
		# convert tcp packets to an annotated version
		# this can fail if the ethernet frame does not encapsulate a IP/TCP packet
		ts_us = int(ts * 1E6)
		annotated_packet = AnnotatedPacket(eth, ts_us, index)
	except AttributeError:
		continue
	# add the annotated packet to a flow based on the 4-tuple
	ip = annotated_packet.packet.ip
	key_1 = (ip.src, ip.dst, ip.tcp.sport, ip.tcp.dport)
	key_2 = (ip.dst, ip.src, ip.tcp.dport, ip.tcp.sport)
	# a flow represents a connection between two endpoints: 
	# endpoint_a -- source (the endpoint requests for service)
	# endpoint_b -- destination (the endpoint listens and responses)
	if key_1 in flows:
		flows[key_1].add_packet(annotated_packet)
	elif key_2 in flows:
		flows[key_2].add_packet(annotated_packet)
	else:
		flows[key_1] = TcpFlow(annotated_packet)
		flows[key_1].add_packet(annotated_packet)

	index += 1

input_file.close()

"""
	After finishing parsing the tcpdump file into flow data structure,
	we start looking at each flow and try to figure out whether there is
	a traffic policing happening.

	1. Segment the flow. Each segment is a request-response round.
	2. Do compression for each segment.
	3. The PD looks at each compressed segment to detect traffic policing.
"""
flow_index = 1
print "The total number of flows is", len(flows.items())
for _, flow in flows.items():
	flow.post_process()
	print "The total number of packets in No. %d flow is %d" %(flow_index, len(flow.packets))
	# split flow into segments
	segments = split_flow_into_segments(flow)

	segment_index = 0
	for segment in segments:
		# look at the segments from a endpoint's view
		for direction in ["a-->b", "b-->a"]:
			if direction == "a-->b":
				# source --> destination update_length_and_offset
				data_endpoint = segment.endpoint_a
				print "The src uses port number (%d), and sends %d packets" %(data_endpoint.port, len(data_endpoint.packets))
			else:
				# destination --> source
				data_endpoint = segment.endpoint_b
				print "The des uses port number (%d), and sends %d packets" %(data_endpoint.port, len(data_endpoint.packets))

			num_data_packets = data_endpoint.num_data_packets
			num_losses = data_endpoint.num_losses()
			if len(data_endpoint.packets) <= 0:
				continue
			uncompressed_plot = get_uncompressed_plot(data_endpoint)
			compressed_plot_3 = get_compressed_plot_3(data_endpoint)
			compressed_plot_2 = get_compressed_plot_2(data_endpoint)
			compressed_plot = get_compressed_plot(data_endpoint, 100000 * 100000)
			print "Compression is completed!"
			print "Uncompressed data:", len(uncompressed_plot[0])
			print "Compressed data:", len(compressed_plot[0])
			print "Compressed data 2:", len(compressed_plot_2[0])
			print "Compressed data 3:", len(compressed_plot_3[0])

			goodput_3 = get_avg_goodput_plot3(compressed_plot_3)
			goodput_2 = get_avg_goodput_plot2(compressed_plot_2)
			avg_goodput = get_avg_goodput(data_endpoint)

			policing_str = ""
			for cutoff in [0, 2]:
				# cutoff: number of lost packets to ignore at the beginning and end
				# when determining the boundaries for policing rate computation and detection
				# policing_params = get_policing_params_for_endpoint(data_endpoint, cutoff)
				# policing_str: number of losses, timeouts, average bandwidth of a connection (goodput)
				policing_params = get_policing_params_for_endpoint(data_endpoint, cutoff)
				policing_str += ", %s, %s" % (policing_params.result_code == RESULT_OK, policing_params.__repr__())

			# print output format:
			# 1. input file name
			# 2. flow index
			# 3. segment index
			# 4. direction
			# 5. number of data packets
			# 6. number of losses
			print "%s, %d, %d, %s: Orig: %d, Comp2: %d, Comp3: %d" %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				avg_goodput,
				goodput_2,
				goodput_3)
			""""
			print "%s, %d, %d, %s, %d, %d, %d, %d%s" %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				num_data_packets,
				num_losses,
				avg_goodput,
				goodput_2,
				goodput_3,
				policing_str)"""
			segment_index += 1
	flow_index += 1

print "Traffic analysis has been done!"




