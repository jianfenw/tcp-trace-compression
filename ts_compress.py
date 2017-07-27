from matplotlib.pylab import gca, figure, axes, plot, scatter, subplot, title, xlabel, ylabel, xlim, ylim, show
from matplotlib.lines import Line2D
import numpy as np
from numpy import arange, array, ones
from numpy.linalg import lstsq

import dpkt
from tcp_endpoint import *
from tcp_flow import *
from tcp_util import *

from matplotlib import animation
from create_segment import *

def draw_plot(x_data, y_data, plot_title, ident_color):
	max_y_data = 0
	for seq_num in y_data:
		if max_y_data < seq_num:
			max_y_data = seq_num
	scatter(x_data, y_data, s = 5, color = ident_color)
	title(plot_title)
	xlabel("time")
	ylabel("sequence number")
	xlim(0, x_data[len(x_data) - 1] + 1000000)
	ylim(0, max_y_data * 1.1)

def get_uncompressed_plot(endpoint):
	time = []
	data = []
	plot = [time, data]
	timestamp_base = endpoint.packets[0].timestamp_us
	seq_base = endpoint.packets[0].seq
	for packet in endpoint.packets:
		time += [packet.timestamp_us - timestamp_base]
		data += [packet.seq - seq_base]
	return plot

""""
Implementation A:
When we come across a loss packet, we need to record the packet.
When a packet gets through the link, we do not record the packet.
We use the first pacekt and the last packet to refer to a non-lossy-packet segment.

This implementation can guarantee a correct throughput, and can reflect every packet that got lost.
"""
def get_compressed_plot_2(endpoint):
	figure()
	plot = get_uncompressed_plot(endpoint)
	draw_plot(plot[0], plot[1], "Uncompressed plot", "red")
	node_time = []
	node_seq = []
	node_annotated_packet = []
	result_plot = [node_time, node_seq, node_annotated_packet]
	length = 0
	index = 0
	while (index < len(plot[0])):
		if index == 0 or index == len(plot[0]) - 1:
			node_time.append(plot[0][index])
			node_seq.append(plot[1][index])
			node_annotated_packet.append(endpoint.packets[index])
		elif endpoint.packets[index].is_lost():
			# print "No. %d packet is lost" %(index)
			node_time.append(plot[0][index])
			node_seq.append(plot[1][index])
			node_annotated_packet.append(endpoint.packets[index])
		index += 1
	#for i in range(len(node_seq)):
	#	print "Seq: %d, Time: %d, data_length: %d, data_pypassed: %d" %(node_seq[i], node_time[i], node_annotated_packet[i].data_len, node_annotated_packet[i].bytes_passed)
	draw_plot(node_time, node_seq, "Compressed Plot 1", "blue")
	#show()
	return result_plot

def get_compressed_plot_3(endpoint):
	figure()
	plot = get_uncompressed_plot(endpoint)
	draw_plot(plot[0], plot[1], "Uncompressed plot", "red")
	time = []
	seq = []
	node_annotated_packet = []
	result_plot = [time,seq,node_annotated_packet]
	index = 0
	prev_state = 0
	while index < len(plot[0]):
		if index == 0 or index == len(plot[0]) - 1:
			time.append(plot[0][index])
			seq.append(plot[1][index])
			node_annotated_packet.append(endpoint.packets[index])
		elif endpoint.packets[index].is_lost() != prev_state:
			time.append(plot[0][index])
			seq.append(plot[1][index])
			node_annotated_packet.append(endpoint.packets[index])
		prev_state = endpoint.packets[index].is_lost()
		index += 1
	draw_plot(time, seq, "Compressed Plot 3", "blue")
	#show()
	return result_plot

def get_compressed_plot(endpoint, max_error):
	figure()
	plot = get_uncompressed_plot(endpoint)
	draw_plot(plot[0], plot[1], "Uncompressed plot", "red")
	result_time = []
	result_seq = []
	result_plot = [result_time, result_seq]
	time = []
	seq = []
	error = 0
	length = 0
	i = 0
	while(i < len(plot[0])):
		time += [plot[0][i]]
		seq += [plot[1][i]]
		length += 1
		if (length <= 1):
			continue
		segment = regression_X_on_Y(time, seq, length)
		error = compute_error(time, seq, length)
		if (error <= max_error):
			result_segment = segment
			i += 1
			continue
		if len(result_time) == 0:
			result_time += [result_segment[0], result_segment[2]]
			result_seq += [result_segment[1], result_segment[3]]
		else:
			result_time += [result_segment[2]]
			result_seq += [result_segment[3]]
		time = []
		seq = []
		length = 0
		error = 0
		i -= 1

	if length != 0:
		result_segment = segment
		result_time += [result_segment[0], result_segment[2]]
		result_seq += [result_segment[1], result_segment[3]]
	""""
	for i in range(len(result_seq)):
		print "Seq: %d, Time: %d" %(result_seq[i], result_time[i])
	"""
	draw_plot(result_time, result_seq, "Compressed Plot", "blue")
	#show()
	return result_plot

