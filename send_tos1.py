from scapy.all import *

dst_ip = "10.0.6.6"
dst_mac = "08:00:00:00:06:66"  # h6 の MAC
iface = "eth0"              # h1 のインターフェース

pkt = Ether(dst=dst_mac) / IP(dst=dst_ip,tos=1) / ICMP()



sendp(pkt, iface=iface, verbose=False)

