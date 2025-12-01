from scapy.all import *
import random

iface = "eth0"

level_1 = 0b01 #rate limit
level_2 = 0b10 #load balance
level_3 = 0b11 #drop

my_ip = "10.0.3.3"

# Test 将来的には自動化?h4-h6多分いらない
mac_table={
    "10.0.1.1":"08:00:00:00:01:11", #h1
    "10.0.2.2":"08:00:00:00:02:22", #h2
    "10.0.3.3":"08:00:00:00:03:33", #h3
    "10.0.4.4":"08:00:00:00:04:44",
    "10.0.5.5":"08:00:00:00:05:55",
    "10.0.6.6":"08:00:00:00:06:66",
}


def packet_level1_change(pkt):
    if IP not in pkt:
        return
    
    eth =pkt[Ether]
    ip = pkt[IP].copy()

    if ip.src == my_ip:#自分宛てのは無視
        return

    now_ecn = ip.tos & 0b11 #下位2bit
    new_ecn = level_1
    
    ip.tos = (ip.tos & 0b11111100) | new_ecn
    
    print(f"[SFC] ECN {bin(now_ecn)} -> {bin(new_ecn)} ({ip.src}  -> {ip.dst})")

    dst_mac = mac_table.get(ip.dst)
    if dst_mac is None:
        print("[SFC] Mac not found -> drop")
        return

    payload = bytes(pkt[IP].payload)

    # 正しいMACを書いて返す
    new_pkt = Ether(dst=dst_mac, src=get_if_hwaddr(iface)) / ip / Raw(payload)
        
    
    print("---packet---")
    pkt.show()
    print("------------")
    
    print("[SFC] → Sending back to s1")

    sendp(new_pkt, iface=iface, verbose = False)

'''
def packet_level2_change(pkt):
    if IP in pkt:
        ip = pkt[IP]
        now_ecn = ip.tos & 0b11 #
        new_ecn = level_2
        ip.tos = (ip.tos & 0b11111100) | new_ecn
        print(f"[SFC] ECN {bin(old_ecn) -> {bin(new_ecn)}({ip.src}  -> {ip.dst})}")
        send(ip, iface=iface, verbose=False)
'''

'''
def packet_level3_change(pkt):
    if IP in pkt:
        ip = pkt[IP]
        now_ecn = ip.tos & 0b11 #
        new_ecn = level_3
        ip.tos = (ip.tos & 0b11111100) | new_ecn
        print(f"[SFC] ECN {bin(old_ecn) -> {bin(new_ecn)}({ip.src}  -> {ip.dst})}")
        send(ip, iface=iface, verbose=False)
'''

print(f"SFC server running on {iface}")
sniff(iface=iface, prn=packet_level1_change,store=False)     
