from scapy.all import *
import random
import time

iface = "eth0"
my_ip = "10.0.3.3"
my_mac = get_if_hwaddr(iface)

# レベル定義 (ECNの値) - 新しい順序
LEVEL_LB     = 1 # 01: Load Balance
LEVEL_RL     = 2 # 10: Rate Limit
LEVEL_DROP   = 3 # 11: Drop

# 閾値設定 (SFC側での独自判断用)
# monitor.pyの検知閾値とは別に、SFC側でより詳細な制御を行う
THRESHOLD_LB   = 1
THRESHOLD_RL   = 40
THRESHOLD_DROP = 60
TIME_WINDOW    = 5.0

# パケット到着履歴 {src_ip: [timestamp, ...]}
packet_history = {}

# ロードバランス先リスト
LB_TARGETS = ["10.0.4.4", "10.0.5.5"]

# MACアドレステーブル
mac_table={
    "10.0.1.1":"08:00:00:00:01:11", 
    "10.0.2.2":"08:00:00:00:02:22",
    "10.0.3.3":"08:00:00:00:03:33", 
    "10.0.4.4":"08:00:00:00:04:44",
    "10.0.5.5":"08:00:00:00:05:55",
    "10.0.6.6":"08:00:00:00:06:66",
}

def get_sfc_decision(src_ip):
    """
    SFC独自のロジックで適用すべきレベルを決定する
    """
    current_time = time.time()
    
    if src_ip not in packet_history:
        packet_history[src_ip] = []
    
    timestamps = packet_history[src_ip]
    # 古い履歴の削除
    valid_timestamps = [t for t in timestamps if current_time - t <= TIME_WINDOW]
    # 新しい履歴の追加
    valid_timestamps.append(current_time)
    packet_history[src_ip] = valid_timestamps
    
    count = len(valid_timestamps)
    
    # 判定ロジック
    if count >= THRESHOLD_DROP:
        return LEVEL_DROP, count
    elif count >= THRESHOLD_RL:
        return LEVEL_RL, count
    elif count >= THRESHOLD_LB:
        return LEVEL_LB, count
    
    # 閾値未満でも、ここに転送されてきたということは怪しいので
    # 最低限の処理（LB）を行うか、または様子見(LB)とする
    return LEVEL_LB, count

def packet_process(pkt):
    """
    SFCサーバが自律的にパケットを分析し、タグ付け・加工を行う
    """
    # 1. フィルタリング
    if Ether not in pkt or IP not in pkt: return
    if pkt[Ether].src == my_mac: return
    if pkt[IP].dst == my_ip: return

    ip = pkt[IP].copy()
    src_ip = ip.src
    
    # 2. SFCによる自律的なレベル決定
    # monitor.pyの指示(タグ)に頼らず、自分で判断して書き込む
    level, count = get_sfc_decision(src_ip)
    
    # 3. ECN (TOS下位2bit) の書き換え
    # ここでSFCが能動的にタグを付与する！
    ip.tos = (ip.tos & 0b11111100) | level
    
    action_msg = ""

    # 4. レベルごとの処理
    if level == LEVEL_DROP:
        action_msg = f"Decision: DROP (Count={count})"
        
    elif level == LEVEL_RL:
        action_msg = f"Decision: RateLimit (Count={count})"
        
    elif level == LEVEL_LB:
        original_dst = ip.dst
        new_dst = random.choice(LB_TARGETS)
        ip.dst = new_dst
        action_msg = f"Decision: LB {original_dst}->{new_dst} (Count={count})"

    print(f"[SFC] Analysis: {src_ip} -> {action_msg}")

    # 5. 送信準備
    del ip.chksum
    del ip.len
    if TCP in ip: del ip[TCP].chksum
    elif UDP in ip: del ip[UDP].chksum

    dst_mac = mac_table.get(ip.dst)
    if dst_mac is None:
        print(f"[SFC] Error: MAC not found for {ip.dst}")
        return

    new_pkt = Ether(dst=dst_mac, src=my_mac) / ip
    sendp(new_pkt, iface=iface, verbose=False)

# --- Main Process ---
print(f"[*] SFC Intelligent Server running on {iface}")
print(f"[*] Role: Autonomous Analysis & Action")
print(f"[*] Thresholds: Drop>={THRESHOLD_DROP}, RL>={THRESHOLD_RL}, LB>={THRESHOLD_LB}")

sniff(iface=iface, prn=packet_process, store=0)