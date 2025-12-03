#!/usr/bin/env python3
import sys
import time
import socket
import random
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    if len(sys.argv) < 3:
        print('Usage: python3 send_fast.py <destination_ip> <count> [message]')
        exit(1)

    dst_ip = sys.argv[1]
    count = int(sys.argv[2])
    msg = sys.argv[3] if len(sys.argv) > 3 else "Attack"
    
    # 宛先IPの解決 (ホスト名でもIPでもOK)
    addr = socket.gethostbyname(dst_ip)
    iface = get_if()
    src_mac = get_if_hwaddr(iface)

    print(f"[*] Sending {count} packets to {addr} on {iface}...")

    # パケットを事前に作成してしまう (送信時の計算コストを下げるため)
    # ポート番号だけランダムに変えて、別々のコネクションに見せる
    packets = []
    for i in range(count):
        # 宛先MACは 'ff:ff:ff:ff:ff:ff' (Broadcast) または Gateway MAC
        # Mininet環境ならBroadcastでもスイッチが良しなに処理してくれることが多い
        pkt = Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') / \
              IP(dst=addr) / \
              TCP(dport=80, sport=random.randint(1024, 65535)) / \
              f"{msg}_{i+1}"
        packets.append(pkt)

    start_time = time.time()
    
    # まとめて送信！
    # inter=0.01 とすると 0.01秒間隔 (100pps)
    # inter=0.001 とすると 0.001秒間隔 (1000pps)
    # inter=0 にすると全力送信
    sendp(packets, iface=iface, verbose=False, inter=0.05)

    end_time = time.time()
    duration = end_time - start_time
    
    print(f"[+] Done. Sent {count} packets in {duration:.4f} seconds.")
    print(f"[+] Average Rate: {count / duration:.2f} pps")

if __name__ == '__main__':
    main()