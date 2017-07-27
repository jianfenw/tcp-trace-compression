""""
This engine is used to process the packets stored in a .pcap file. 
We use dpkt library to parse .pcap file.

First, it will assign each packet to a flow on the 4-tuple (src/des * IP address/port number)

Second, each flow is then devided into segments, where a segment is defined as data from
endpoint A followed by data from endpoint B (i.e. a typical request/response model)

Third, the tcp time-sequence number plot is then compressed
output:
<direction>: either "a-->b" or "b-->a"

"""
import dpkt
import sys

from pylab import *
from annotated_packet import *
from tcp_flow import *
from tcp_segment import *
from tcp_plot import *
from tcp_plot_v20 import *
from tcp_util import *
#from ts_compress import *
from policing_detector import *

# Maximum number of packets that will be processed overall
MAX_NUM_PACKETS = -1

if len(sys.argv) < 2:
	print "Missing input file"
	print "Usage: python %s <input file>" %(sys.argv[0])
	exit(-1)
input_filename = sys.argv[1]

# input_filename = "test.pcap"
input_file = open(input_filename)
pcap = dpkt.pcap.Reader(input_file)

flows = dict()
index = 0
for ts, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)

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
	if MAX_NUM_PACKETS != -1 and index >= MAX_NUM_PACKETS:
		break

input_file.close()

flow_index = 0
for _, flow in flows.items():
	flow.post_process()
	# Split the flow into segments
	segments = split_flow_into_segments(flow)
	segment_index = 0
	for segment in segments:
		for direction in ["a-->b", "b-->a"]:
			if direction == "a-->b":
				data_endpoint = segment.endpoint_a
			else:
				data_endpoint = segment.endpoint_b

			# Use my compression algorithm to compress the trace
			if len(data_endpoint.packets) == 0:
				continue

			#print len(data_endpoint.packets)

			data_plot = TcpPlot(data_endpoint)

			#print "Policing-rate-data-plot:", data_plot.policing_rate_bps()
			#print get_policing_params_from_plot_0(data_plot)

			#tb_simulator = TokenBucketSim(data_plot)
			#print tb_simulator.token_bucket_simulator()

			rtt_plot = TcpRTTPlot(data_plot, 1)
			if rtt_plot.get_rtts_number() <= 2:
				continue

			rtt_statistics = rtt_plot.get_statistics_rtts()
			median_rtt_general = rtt_statistics[0]
			median_before = rtt_statistics[3]
			median_after = rtt_statistics[4]
			dev_before = rtt_statistics[7]
			dev_after = rtt_statistics[8]

			# print median_before, rtt_plot.rtts_before_loss[1], median(rtt_plot.rtts_before_loss[1])
			# print dev_after

			"""
			print '%s,%d,%d,%s,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f' %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				median_rtts[0],
				median_rtts[1][0],
				median_rtts[1][1],
				median_rtts[2][0],
				median_rtts[2][1],
				median_rtts[3][0],
				median_rtts[3][1],
				median_rtts[4][0],
				median_rtts[4][1],
				median_rtts[5][0],
				median_rtts[5][1],
				mean_rtts[0],
				mean_rtts[1][0],
				mean_rtts[1][1],
				mean_rtts[2][0],
				mean_rtts[2][1],
				mean_rtts[3][0],
				mean_rtts[3][1],
				mean_rtts[4][0],
				mean_rtts[4][1],
				mean_rtts[5][0],
				mean_rtts[5][1])
			"""

			com_data_plot = TcpComPlot(data_plot)

			# Define the V20 data plot.
			com_data_plot_v20 = TcpComPlotV20(data_plot)

			# Define the V30 data plot
			com_data_plot_v30_0 = TcpComPlotV30(data_plot)
			com_data_plot_v30_1 = TcpComPlotV30(data_plot, 40000*40000)
			com_data_plot_v30_2 = TcpComPlotV30(data_plot, 80000*80000)
			com_data_plot_v30_3 = TcpComPlotV30(data_plot, 100000*100000)
			com_data_plot_v30_4 = TcpComPlotV30(data_plot, 120000*120000)
			
			#print median_before, median_after
			#print dev_before, dev_after
			#print com_data_plot.last_node_median_rtt(), median(com_data_plot.last_node_median_rtt())
			
			#print median_rtt_general
			#print (median_before[1] == median(com_data_plot.last_node_median_rtt()))
			
			"""
			print '%s, %d, %d, %s, %.2f, %.1f, %.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f' %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				rtt_plot.get_inflated_rtt_flag_com(),
				com_data_plot.last_node_median_rtt(),
				median_before[1],
				dev_before[1],
				dev_before[2],
				dev_before[3],
				dev_before[4],
				dev_after[0],
				dev_after[1],
				dev_after[2],
				dev_after[3],
				dev_after[4])
			"""

			"""
			# This is used to debug TcpComPlot __init__()
			for i in range(data_plot.uncompress_nodes_number):
				if data_plot.uncompress_nodes[i].is_lost:
					print i,
			print

			print data_plot.get_losses_number(0), data_plot.get_losses_number(1), data_plot.get_losses_number(2)
			"""

			# Implementation Correctness Check
			com_data_plot.implementation_validation()
			com_data_plot.check_policing_detector()

			com_data_plot_v30_3.implementation_validation()

			#print com_data_plot_v20.implementation_validation(), com_data_plot_v20.pass_segment[0][2]
			#com_data_plot_v20.set_token_bucket_flag()

			#print com_data_plot_v30_0.implementation_validation()
			com_data_plot_v30_0.set_token_bucket_flag()
			com_data_plot_v30_1.set_token_bucket_flag()
			com_data_plot_v30_2.set_token_bucket_flag()
			com_data_plot_v30_3.set_token_bucket_flag()
			com_data_plot_v30_4.set_token_bucket_flag()

			"""
				com_data_plot.inflated_rtt_flag:
				1. node_pair_number == 0 --> -1
				2. inflated_rtt_count > rtt_threshold --> 1
				3. inflated_rtt_count <= rtt_threshold --> 0 (No inflated RTT detected)
			"""
			com_data_plot_v30_0.set_inflated_rtt_flag()
			com_data_plot_v30_1.set_inflated_rtt_flag()
			com_data_plot_v30_2.set_inflated_rtt_flag()
			com_data_plot_v30_3.set_inflated_rtt_flag()
			com_data_plot_v30_4.set_inflated_rtt_flag()

			#print com_data_plot.last_node_median_rtt(), median(com_data_plot.last_node_median_rtt())


			# token_number_on_loss: the number of samples in the tokens_on_loss
			# token_number_on_pass: the number of samples in the tokens_on_pass

			#print get_policing_params_from_plot_0(data_plot, 0)
			#print com_data_plot.pass_number(), com_data_plot.loss_number()


			#print data_plot.uncompress_nodes[2].is_lost

			#for node_pair in com_data_plot.node_pair:
			#	print node_pair[2], node_pair[3]

			#print get_policing_params_from_plot_0(data_plot, 0)

			print "%s,%d,%d,%s,%d,%d,%f,%d,%d,%d,%f,%d,%d,%d,%f,%d,%d,%d,%f,%d,%d,%d,%f,%d,%d,%d,%f" %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				com_data_plot.policing_detector(),
				get_policing_params_for_endpoint(data_endpoint, 0),
				com_data_plot.compression_ratio,
				com_data_plot_v30_0.token_bucket_flag,
				com_data_plot_v30_0.inflated_rtt_flag,
				com_data_plot_v30_0.policing_detector(),
				com_data_plot_v30_0.compression_ratio,
				com_data_plot_v30_1.token_bucket_flag,
				com_data_plot_v30_1.inflated_rtt_flag,
				com_data_plot_v30_1.policing_detector(),
				com_data_plot_v30_1.compression_ratio,
				com_data_plot_v30_2.token_bucket_flag,
				com_data_plot_v30_2.inflated_rtt_flag,
				com_data_plot_v30_2.policing_detector(),
				com_data_plot_v30_2.compression_ratio,
				com_data_plot_v30_3.token_bucket_flag,
				com_data_plot_v30_3.inflated_rtt_flag,
				com_data_plot_v30_3.policing_detector(),
				com_data_plot_v30_3.compression_ratio,
				com_data_plot_v30_4.token_bucket_flag,
				com_data_plot_v30_4.inflated_rtt_flag,
				com_data_plot_v30_4.policing_detector(),
				com_data_plot_v30_4.compression_ratio
				)


			"""
			print "%d,%d,%d,%d,%d,%d,%f,%f,%d,%f,%f,%d,%f" %(
				com_data_plot.loss_number(),
				com_data_plot.pass_number(),
				com_data_plot_v20.loss_number(),
				com_data_plot_v20.pass_number(),
				com_data_plot_v30_0.loss_number(),
				com_data_plot_v30_0.pass_number(),
				com_data_plot.policing_rate_bps,
				com_data_plot_v20.policing_rate_bps,
				com_data_plot_v20.token_bucket_flag,
				com_data_plot_v20.compression_ratio,
				com_data_plot_v30_0.policing_rate_bps,
				com_data_plot_v30_0.token_bucket_flag,
				com_data_plot_v30_0.compression_ratio
				)
			"""

			'''
			# Debug info: debug the tokens_used on loss

			tokens_used_m = [0, 1452, 2904, 2904, 2904, 4356, 4356, 4356, 5808, 7260, 7260, 7260, 8712, 8712, 8712, 10164, 11616, 11616, 11616, 11616, 13068, 14520, 14520, 14520, 15972, 15972, 15972, 17424, 18876, 18876, 18876, 20328, 21780, 21780, 21780, 23232, 23232, 23232, 24684, 26136, 26136, 26136, 27588, 29040, 29040, 29040, 30492, 30492, 30492, 31944, 33396, 33396, 33396, 33396, 34848, 36300, 36300, 37752, 37752, 45012, 593868, 611292, 611292, 612744, 614196, 614196, 614196, 615648, 615648, 615648, 617100, 618552, 618552, 618552, 620004, 621456, 621456, 621456, 622908, 624360, 624360, 624360, 1158696, 1158696, 1163052, 1184832, 1189188, 1190640]
			tokens_used_t = [0, 1452, 2904, 2904, 2904, 4356, 4356, 4356, 5808, 7260, 7260, 7260, 8712, 8712, 8712, 10164, 11616, 11616, 11616, 11616, 13068, 14520, 14520, 14520, 15972, 15972, 15972, 17424, 18876, 18876, 18876, 20328, 21780, 21780, 21780, 23232, 23232, 23232, 24684, 26136, 26136, 26136, 27588, 29040, 29040, 29040, 30492, 30492, 30492, 31944, 33396, 33396, 33396, 33396, 34848, 36300, 36300, 37752, 37752, 45012, 593868, 611292, 611292, 612744, 614196, 614196, 614196, 615648, 615648, 615648, 617100, 618552, 618552, 618552, 620004, 621456, 621456, 621456, 622908, 624360, 624360, 624360, 1158696, 1158696, 1163052, 1184832, 1189188, 1190640]

			for i in range(len(tokens_used_m)):
				if tokens_used_m[i] != tokens_used_t[i]:
					print i
			'''

			"""
			# The parameter sweeping outputs
			print "%s,%d,%d,%s,%d,%d,%d,%f,%f,%f,%f,%d,%d,%d,%d,%f" %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				(median_before[1] == median(com_data_plot.last_node_median_rtt())),
				com_data_plot.inflated_rtt_flag,
				com_data_plot.token_bucket_flag,
				com_data_plot.tokens_on_loss_range,
				com_data_plot.tokens_on_pass_range,
				com_data_plot.tokens_on_loss_total_range,
				com_data_plot.tokens_on_pass_total_range,
				com_data_plot.policing_detector(),
				com_data_plot.token_number_on_loss,
				com_data_plot.token_number_on_pass,
				get_policing_params_for_endpoint(data_endpoint, 0),
				com_data_plot.compression_ratio
				)
			"""

			#if rtt_plot.get_rtts_number() > 1:
			#	rtt_plot.show_rtts_plot("RTT Exp.", "Red")

			#if flow_index == 0 and segment_index == 0:
			# data_endpoint.bytes_passed_computation_show(True)

			#target_packet = data_endpoint.packets[len(data_endpoint.packets) - 1]
			#print (target_packet.bytes_passed + target_packet.data_len), (target_packet.seq_end - 1 - data_endpoint.seq_init)

			"""
			print "%s,%d,%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d" %(
				input_filename,
				flow_index,
				segment_index,
				direction,
				data_plot.uncompress_nodes_number,
				data_plot.compress_nodes_number[0],
				data_plot.compress_nodes_number[1],
				data_plot.get_losses_number(0),
				data_plot.get_losses_number(1),
				data_plot.get_losses_number(2),
				rtt_plot.get_rtts_number(),
				rtt_plot.get_inflated_rtt_flag(),
				get_policing_params_from_plot_0(data_plot),
				get_policing_params_for_endpoint(data_endpoint, 0))

			print "%s,%d,%d,%d,%d,%d,%d,%d,%d" %(
				com_data_plot.implementation_validation(),
				com_data_plot.node_pair_number,
				com_data_plot.loss_number(),
				com_data_plot.pass_number(),
				com_data_plot.avg_goodput(),
				com_data_plot.late_loss_flag,
				com_data_plot.inflated_rtt_flag,
				com_data_plot.token_bucket_flag,
				com_data_plot.policing_detector()
				)
			"""
		segment_index += 1
	flow_index += 1



#show()















