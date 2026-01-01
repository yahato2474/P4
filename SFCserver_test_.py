#!/usr/bin/env python3
import socket
import struct
import time

# ==========================================
# 設定
# ==========================================
IFACE = "eth0"
MY_IP = "10.0.3.3"
MY_MAC_STR = "08:00:00:00:03:33"

# 閾値 (Mbps)
THRESHOLD_LB_MBPS   = 0
THRESHOLD_RL_MBPS   = 20
THRESHOLD_DROP_MBPS = 20

TIME_WINDOW = 1.0

# packet_level (TOS下位2bit)

LEVEL_LB     = 1
LEVEL_RL     = 2
LEVEL_DROP   = 3

SNAT_ENABLED = False

# ==========================================
# 内部
# ==========================================
packet_history = {}
level_history = {}

def mac_to_bytes(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(":"))

my_mac_bytes = mac_to_bytes(MY_MAC_STR)

def ip_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def get_decision(src_ip, pkt_len):
    now = time.time()
    hist = packet_history.get(src_ip, [])
    hist = [(t, sz) for t, sz in hist if now - t <= TIME_WINDOW]
    hist.append((now, pkt_len))
    packet_history[src_ip] = hist

    total_bytes = sum(sz for _, sz in hist)
    mbps = (total_bytes * 8) / TIME_WINDOW / 1_000_000.0

    if mbps >= THRESHOLD_DROP_MBPS:
        return LEVEL_DROP, mbps
    if mbps >= THRESHOLD_RL_MBPS:
        return LEVEL_RL, mbps
    if mbps >= THRESHOLD_LB_MBPS:
        return LEVEL_LB, mbps
  

# ==========================================
# メイン
# ==========================================
def main():
    print(f"[*] SFC Server started on {IFACE}")
    print(f"[THRESHOLDS] LB >= {THRESHOLD_LB_MBPS} Mbps, RL >= {THRESHOLD_RL_MBPS} Mbps, DROP >= {THRESHOLD_DROP_MBPS} Mbps")
    print("=" * 40)

    raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_sock.bind((IFACE, 0))

    while True:
        packet, _ = raw_sock.recvfrom(4096)
        if len(packet) < 34:
            continue

        eth_type = struct.unpack("!H", packet[12:14])[0]
        if eth_type != 0x0800:
            continue

        ip_off = 14
        ihl = (packet[ip_off] & 0x0f) * 4
        src_ip = socket.inet_ntoa(packet[ip_off+12:ip_off+16])
        dst_ip = socket.inet_ntoa(packet[ip_off+16:ip_off+20])

        # 自己ループ防止
        if packet[6:12] == my_mac_bytes or dst_ip == MY_IP:
            continue

        level, mbps = get_decision(src_ip, len(packet))

        last = level_history.get(src_ip, -1)
        if last != level:
            name = ["NORMAL", "LB", "RL", "DROP"][level]
            print(f"[{name}] {src_ip} -> {dst_ip} ({mbps:.2f} Mbps)")
            level_history[src_ip] = level

        # DROP は SFC で破棄
        
        if level == LEVEL_DROP:
            continue
        


        mutable = bytearray(packet)

        # 1) TOS 下位2bitを書き換え
        old_tos = mutable[ip_off + 1]
        mutable[ip_off + 1] = (old_tos & 0b11111100) | level

        # 2) SNAT（任意）
        """
        if SNAT_ENABLED:
            mutable[ip_off+12:ip_off+16] = socket.inet_aton(MY_IP)
        """

        # 3) IPチェックサム再計算
        mutable[ip_off+10] = 0
        mutable[ip_off+11] = 0
        iphdr = bytes(mutable[ip_off:ip_off+ihl])
        csum = ip_checksum(iphdr)
        mutable[ip_off+10] = (csum >> 8) & 0xff
        mutable[ip_off+11] = csum & 0xff

        raw_sock.send(mutable)

if __name__ == "__main__":
    main()
