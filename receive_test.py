#!/usr/bin/env python3
import sys
from scapy.all import sniff, get_if_list, Ether, IP, TCP, UDP, Raw

def get_if():
    for i in get_if_list():
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    exit(1)

def handle_pkt(pkt):
    # ノイズ対策: IPヘッダがない、またはTCPでないパケットは無視してreturn
    if IP not in pkt or TCP not in pkt:
        return

    print("="*60)
    print(f"Received Packet on {pkt.sniffed_on}")
    
    # 詳細表示
    print(f"IP Src: {pkt[IP].src} -> Dst: {pkt[IP].dst} (Proto: {pkt[IP].proto})")
    print(f"TOS/ECN: {bin(pkt[IP].tos)}")
    print(f"TCP Sport: {pkt[TCP].sport} -> Dport: {pkt[TCP].dport}")
    
    # メッセージ（Rawデータ）の表示
    if Raw in pkt:
        payload = pkt[Raw].load
        try:
            # 文字列としてデコードして表示
            message = payload.decode('utf-8')
            print(f"Message: {message}")
        except:
            # デコードできないバイナリデータの場合はそのまま表示
            print(f"Raw Data: {payload}")
    else:
        print("No Message Data")

    sys.stdout.flush()

def main():
    iface = get_if()
    print(f"[*] DEBUG Sniffer started on {iface}")
    print("[*] Waiting for IPv4 TCP packets only...")
    
    # filter="tcp" を指定して、最初からTCP以外を拾わないようにする
    sniff(iface=iface, filter="tcp", prn=handle_pkt)

if __name__ == '__main__':
    main()
