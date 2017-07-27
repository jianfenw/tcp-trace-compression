import dpkt
import sys

input_filename = sys.argv[1]
input_file = open(input_filename)
pcap = dpkt.pcap.Reader(input_file)

flows = dict()
index = 0
for ts, buf in pcap:
	index += 1
input_file.close()

print "%s, %d" %(input_filename, index)