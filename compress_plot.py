from matplotlib.pylab import gca, figure, axes, plot, scatter, subplot, title, xlabel, ylabel, xlim, ylim, show
from matplotlib.lines import Line2D
import numpy as np
from numpy import arange, array, ones
from numpy.linalg import lstsq

import dpkt
from tcp_endpoint import *
from tcp_flow import *
from tcp_util import *
from ts_compress import *

from create_segment import *

"""
	The CompressedPacket data structure is generated from several AnnotatedPackets based on
	different approximation approaches, such as the linear least-square approximation.
"""
class CompressedPlot(object):
	# We will use a TcpEndpoint to generate a Compressed Plot.
	def __init__(self, endpoint):
		self.ip = endpoint.ip
		self.port = endpoint.port

		self.uncompressed_plot_packets = endpoint.packets
		self.uncompressed_plot = get_uncompressed_plot(endpoint)

		self.compressed_plot_packets = []
		self.compressed_plot = get_compressed_plot(endpoint)

	def get_uncompressed_plot(self, endpoint):
		time = []
		seq = []
		plot = [time, seq]
		timestamp_base = endpoint.packets[0].timestamp_us
		for packet in endpoint.packets:
			time.append(packet.timestamp_us - timestamp_base)
			seq.append(packet.seq_relative)
		return plot

	def get_compressed_plot(self, endpoint):
		time = []
		seq = []
		result_plot = [time, seq]
		index = 0
		while index < len(self.uncompressed_plot_packets):
			if index == 0 or index == len(self.uncompressed_plot_packets) - 1:
				time.append(self.uncompressed_plot[0][index])
				seq.append(self.uncompressed_plot[1][index])
				self.compressed_plot_packets.append(self.uncompressed_plot_packets[index])
			if self.uncompressed_plot_packets[index].is_lost():
				time.append(self.uncompressed_plot[0][index])
				seq.append(self.uncompressed_plot[1][index])
				self.compressed_plot_packets.append(self.uncompressed_plot_packets[index])
			index += 1

		for i in range(len(self.compressed_plot_packets)):
			print "Seq: %d, Time: %d, data_length: %d, data_pypassed: %d" %(seq[i], time[i], self.compressed_plot_packets[i].data_len, self.compressed_plot_packets[i].bytes_passed)
		return result_plot


class CompressedPacket(object):
	def __init__(self):
		self.seq = -1
		self.timestamp_us = -1
		self.data_len = -1

		self.rtx = None
		self.rtx_is_spurious = False

		self.bytes_passed = -1