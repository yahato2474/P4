#!/usr/bin/env python3
import sys
import time
import socket
import struct
from scapy.all import IP, UDP, Ether, get_if_hwaddr, get_if_list

# ---- 設定: パケットサイズ調整 ----
# 15Mbpsを目指す場合: 1250pps x 1500byte x 8bit = 15Mbps
# ペイロードサイズを調整して、Ethernetフレーム全体で約1514byteにする
PAYLOAD_SIZE = 1460 

def get_if():
    """eth0を含むインターフェースを自動取得"""
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    if len(sys.argv) < 3:
        print('Usage: python3 send_fast_raw.py <dst_ip> <rate_pps> [duration_sec]')
        print('Example: python3 send_fast_raw.py 10.0.6.6 1250 10')
        exit(1)

    dst_ip = sys.argv[1]
    rate_pps = float(sys.argv[2])
    duration = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0
    
    # 総パケット数
    total_count = int(rate_pps * duration)
    
    # 送信間隔 (秒)
    interval = 1.0 / rate_pps

    iface = get_if()
    src_mac = get_if_hwaddr(iface)
    
    print(f"[*] Target: {dst_ip}")
    print(f"[*] Interface: {iface} ({src_mac})")
    print(f"[*] Rate: {rate_pps} pps (Interval: {interval:.6f}s)")
    print(f"[*] Duration: {duration}s (Total: {total_count} packets)")
    print(f"[*] Packet Size: Payload {PAYLOAD_SIZE} bytes")
    print("-" * 40)

    # 1. パケットのテンプレートを作成 (Scapyを使用)
    # 高速化のため、TCPではなくUDPを使用 (ハンドシェイク不要で送りっぱなしにできるため)
    payload = "X" * PAYLOAD_SIZE
    pkt = Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') / \
          IP(dst=dst_ip) / \
          UDP(dport=5001, sport=12345) / \
          payload

    # 2. パケットをバイナリ(bytes)に変換
    # これをループ内で使い回すことで爆速化する
    pkt_bytes = bytes(pkt)

    # 3. Raw Socketの作成 (AF_PACKETはLinux専用、MininetはLinuxなのでOK)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))

    print(f"[*] Starting High-Speed Attack...")
    
    # 4. 送信ループ (Busy Wait方式)
    start_time = time.time()
    next_send_time = start_time
    sent_count = 0

    try:
        while sent_count < total_count:
            # 現在時刻が送信予定時刻になるまで待機 (Busy Wait)
            # time.sleep()は精度が悪いため、whileループで待つ
            while time.time() < next_send_time:
                pass
            
            # 送信 (バイト列を直接流し込む)
            s.send(pkt_bytes)
            
            sent_count += 1
            # 次回の送信予定時刻を更新
            next_send_time = start_time + (sent_count * interval)

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")

    end_time = time.time()
    actual_duration = end_time - start_time
    actual_rate = sent_count / actual_duration if actual_duration > 0 else 0

    print("-" * 40)
    print(f"[+] Done.")
    print(f"[+] Sent: {sent_count} packets")
    print(f"[+] Actual Duration: {actual_duration:.4f}s")
    print(f"[+] Actual Rate: {actual_rate:.2f} pps")
    
    # Mbps換算 (Ethernetヘッダ14 + IP 20 + UDP 8 + Payload) * 8 bit
    frame_len = len(pkt_bytes)
    mbps = (actual_rate * frame_len * 8) / 1_000_000
    print(f"[+] Estimated Bandwidth: {mbps:.2f} Mbps")

if __name__ == '__main__':
    main()