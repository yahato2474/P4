#!/usr/bin/env python3
import sys
import time
from scapy.all import sendp, Ether, IP, UDP, Raw

def main():
    # 引数が足りない場合の使い方を表示
    if len(sys.argv) < 3:
        print("Usage: python3 measure_send.py <Dst_IP> <Count> [Dst_MAC]")
        sys.exit(1)

    dst_ip = sys.argv[1]
    count = int(sys.argv[2])
    
    # 第3引数があればそれを使い、なければブロードキャスト(ff:ff:...)にする
    if len(sys.argv) > 3:
        dst_mac = sys.argv[3]
    else:
        dst_mac = "ff:ff:ff:ff:ff:ff"

    print(f"Sending {count} packets to {dst_ip} (MAC: {dst_mac})...")

    for i in range(count):
        now = time.time()
        # Etherヘッダにdst(宛先MAC)を明記して、強制的にスイッチへ送る
        pkt = Ether(dst=dst_mac) / IP(dst=dst_ip) / UDP(dport=5555, sport=1234) / Raw(load=str(now))
        pkt = Ether(bytes(pkt))
        
        sendp(pkt, verbose=False)
        time.sleep(0.1)

if __name__ == '__main__':
    main()