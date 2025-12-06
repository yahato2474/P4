#!/usr/bin/env python3
import sys
import time
import socket
import random
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

def get_if():
    """eth0を含むインターフェースを自動取得"""
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
    if len(sys.argv) < 4:
        print('Usage: python3 send_burst.py <dst_ip> <total_count> <rate_pps> [message]')
        print('Example: python3 send_burst.py 10.0.6.6 20 10 "Test"')
        exit(1)

    dst_ip = sys.argv[1]
    total_count = int(sys.argv[2])
    rate_pps = float(sys.argv[3])
    msg = sys.argv[4] if len(sys.argv) > 4 else "TestPacket"
    
    # 送信間隔 (interval) を計算
    # 1秒 / rate_pps
    interval = 1.0 / rate_pps

    addr = socket.gethostbyname(dst_ip)
    iface = get_if()
    src_mac = get_if_hwaddr(iface)

    print(f"[*] Target: {addr}")
    print(f"[*] Total: {total_count} packets")
    print(f"[*] Rate: {rate_pps} pps (Interval: {interval:.4f}s)")
    print(f"[*] Estimated Duration: {total_count * interval:.2f}s")
    print("-" * 40)

    # パケット生成
    packets = []
    for i in range(total_count):
        pkt = Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') / \
              IP(dst=addr) / \
              TCP(dport=80, sport=random.randint(1024, 65535)) / \
              f"{msg}_{i+1}"
        packets.append(pkt)

    start_time = time.time()
    
    # scapyのsendpで inter (interval) を指定して送信
    # realtime=True にすると、計算上の時間通りに送ろうと努力してくれる
    sendp(packets, iface=iface, verbose=False, inter=interval, realtime=True)

    end_time = time.time()
    actual_duration = end_time - start_time
    actual_rate = total_count / actual_duration if actual_duration > 0 else 0

    print("-" * 40)
    print(f"[+] Done.")
    print(f"[+] Actual Duration: {actual_duration:.4f}s")
    print(f"[+] Actual Rate: {actual_rate:.2f} pps")

if __name__ == '__main__':
    main()