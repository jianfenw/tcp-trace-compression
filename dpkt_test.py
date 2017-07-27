import dpkt

f = open("./tcp-ethereal-trace-1.pcap")
pcap = dpkt.pcap.Reader(f)

""""
for ts, buf in pcap:
	print ts, len(buf)
"""
i = 0
for ts, buf in pcap:
	i = i + 1
	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data
	print ip.src, ip.dst
	tcp = ip.data
	#print i, " ", tcp.sport, tcp.dport
	if tcp.dport == 80 and len(tcp.data) > 0:
		http = dpkt.http.Request(tcp.data)
		print http.method, http.version, http.headers['user-agent']
		#print http.uri

print tcp
f.close()