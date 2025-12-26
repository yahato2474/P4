import socket
import struct
import time
import random

# ==========================================
# 設定エリア
# ==========================================
IFACE = "eth0"
MY_IP = "10.0.3.3"
MY_MAC_STR = "08:00:00:00:03:33"

# 閾値 (Mbps)
THRESHOLD_LB_MBPS   = 0
THRESHOLD_RL_MBPS   = 999
THRESHOLD_DROP_MBPS = 999

TIME_WINDOW = 1.0

# レベル定義 (TOSの下位2bit)
LEVEL_LB   = 1 # 01
LEVEL_RL   = 2 # 10
LEVEL_DROP = 3 # 11

# ロードバランス先
LB_TARGET_IPS = ["10.0.4.4", "10.0.5.5"]

# ==========================================
# 内部変数・ヘルパー関数
# ==========================================
packet_history = {}
level_history = {}

def mac_to_bytes(mac_str):
    """ MACアドレス文字列(xx:xx:...)をバイナリ変換 """
    return bytes(int(b, 16) for b in mac_str.split(":"))

# MACアドレステーブル (宛先IP -> Next Hop MAC)
mac_table_bytes = {
    "10.0.1.1": mac_to_bytes("08:00:00:00:01:11"),
    "10.0.2.2": mac_to_bytes("08:00:00:00:02:22"),
    "10.0.3.3": mac_to_bytes("08:00:00:00:03:33"),
    "10.0.4.4": mac_to_bytes("08:00:00:00:04:44"),
    "10.0.5.5": mac_to_bytes("08:00:00:00:05:55"),
    "10.0.6.6": mac_to_bytes("08:00:00:00:06:66"),
}

my_mac_bytes = mac_to_bytes(MY_MAC_STR)

def checksum(msg):
    """ IPチェックサム計算用 """
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

def get_decision(src_ip, pkt_len):
    """ Mbpsを計算して判定レベルを返す """
    current_time = time.time()
    if src_ip not in packet_history:
        packet_history[src_ip] = []
    
    # 履歴更新 (1秒以内のデータのみ残す)
    history = packet_history[src_ip]
    valid_data = [(t, size) for t, size in history if current_time - t <= TIME_WINDOW]
    valid_data.append((current_time, pkt_len))
    packet_history[src_ip] = valid_data
    
    # Mbps計算
    total_bytes = sum(size for t, size in valid_data)
    mbps = (total_bytes * 8) / TIME_WINDOW / 1_000_000.0
    
    if mbps >= THRESHOLD_DROP_MBPS: return LEVEL_DROP, mbps
    if mbps >= THRESHOLD_RL_MBPS: return LEVEL_RL, mbps
    if mbps >= THRESHOLD_LB_MBPS: return LEVEL_LB, mbps
    

# ==========================================
# メイン処理
# ==========================================
def main():
    print(f"[*] Raw Socket SFC Server Started on {IFACE}")
    print(f"[*] Mode: SNAT Enabled (Src IP -> {MY_IP})")
    print(f"[*] Thresholds: LB={THRESHOLD_LB_MBPS}M, RL={THRESHOLD_RL_MBPS}M, DROP={THRESHOLD_DROP_MBPS}M")
    
    # Raw Socket作成
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_sock.bind((IFACE, 0))
    except PermissionError:
        print("[!] Error: Root権限(sudo)で実行してください")
        return

    while True:
        try:
            # パケット受信
            packet, _ = raw_sock.recvfrom(2048)
            
            # --- 解析 ---
            eth_type = struct.unpack("!H", packet[12:14])[0]
            if eth_type != 0x0800: continue # IPv4以外無視

            ip_header_start = 14
            
            # Src/Dst IP 取得
            src_ip_bytes = packet[ip_header_start+12 : ip_header_start+16]
            dst_ip_bytes = packet[ip_header_start+16 : ip_header_start+20]
            src_ip_str = socket.inet_ntoa(src_ip_bytes)
            dst_ip_str = socket.inet_ntoa(dst_ip_bytes)

            # ループ防止 (自分宛て or 自分が送信元)
            if dst_ip_str == MY_IP: continue
            if packet[6:12] == my_mac_bytes: continue

            # --- 判定 ---
            level, mbps = get_decision(src_ip_str, len(packet))

            # ログ (変化時のみ)
            last_lvl = level_history.get(src_ip_str, -1)
            target_ip_str = random.choice(LB_TARGET_IPS)
            
            if level != last_lvl:
                lvl_name = ["?", "LB", "RL", "DROP"][level]
                print(f"[!] {src_ip_str} -> {lvl_name} ({mbps:.2f} Mbps) >>> Redirect to {target_ip_str} (as {MY_IP})")
                level_history[src_ip_str] = level

            # --- パケット書き換え (Modifying) ---
            mutable_pkt = bytearray(packet)

            # 1. TOS書き換え (offset 15)
            old_tos = mutable_pkt[14+1]
            new_tos = (old_tos & 0b11111100) | level
            mutable_pkt[14+1] = new_tos

            # 2. 宛先IP書き換え (LB処理)
            target_ip_bytes = socket.inet_aton(target_ip_str)
            mutable_pkt[14+16 : 14+20] = target_ip_bytes

            # 3. ★送信元IP書き換え (SNAT: h
            # 1 -> h3)
            # これでスイッチからは h3 からのパケットに見える
            """SNAT: h1 -> h3"""
            
            new_src_ip_bytes = socket.inet_aton(MY_IP)
            mutable_pkt[14+12 : 14+16] = new_src_ip_bytes
            

            # 4. IPチェックサム再計算
            mutable_pkt[14+10] = 0
            mutable_pkt[14+11] = 0
            
            ihl = (mutable_pkt[14] & 0x0f) * 4
            ip_header = mutable_pkt[14 : 14+ihl]
            
            new_csum = checksum(ip_header)
            mutable_pkt[14+10] = (new_csum >> 8) & 0xff
            mutable_pkt[14+11] = new_csum & 0xff

            # 5. UDPチェックサム無効化 (必須)
            protocol = mutable_pkt[14+9]
            if protocol == 17: # UDP
                udp_base = 14 + ihl
                mutable_pkt[udp_base+6] = 0
                mutable_pkt[udp_base+7] = 0

            # 6. Ethernetヘッダ書き換え
            next_hop_mac = mac_table_bytes.get(target_ip_str)
            if next_hop_mac:
                mutable_pkt[0:6] = next_hop_mac  # Dst MAC
                mutable_pkt[6:12] = my_mac_bytes # Src MAC

            # --- 送信 ---
            raw_sock.send(mutable_pkt)

        except KeyboardInterrupt:
            print("\n[*] Stopping SFC Server...")
            break
        except Exception as e:
            continue

if __name__ == "__main__":
    main()