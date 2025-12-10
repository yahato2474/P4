from scapy.all import *
import random
import time

iface = "eth0"
my_ip = "10.0.3.3"
my_mac = get_if_hwaddr(iface)

# ECN
LEVEL_NORMAL = 0b01 # 1: Rate Limit 
LEVEL_LB     = 0b10 # 2: Load Balance
LEVEL_DROP   = 0b11 # 3: Drop

# 閾値設定 (5秒間に何パケット来たか)
THRESHOLD_DROP = 20  # 30パケット以上 -> Drop
THRESHOLD_LB   = 10  # 20パケット以上 -> Load Balance
THRESHOLD_RL = 5  

TIME_WINDOW    = 5.0 # 監視期間(秒)

# パケット到着時刻記録用辞書
# { "10.0.1.1": [time1, time2, ...], ... }
packet_history = {}

# ロードバランス先リスト
LB_TARGETS = ["10.0.4.4", "10.0.5.5"]

# MACアドレステーブル (次のホップの解決用)
mac_table={
    "10.0.1.1":"08:00:00:00:01:11", 
    "10.0.2.2":"08:00:00:00:02:22",
    "10.0.3.3":"08:00:00:00:03:33", 
    "10.0.4.4":"08:00:00:00:04:44",
    "10.0.5.5":"08:00:00:00:05:55",
    "10.0.6.6":"08:00:00:00:06:66",
}

def get_mitigation_level(src_ip):
    """
    送信元IPごとの直近5秒間のパケット数を計算し、適用すべきレベルを返す
    """
    current_time = time.time()
    
    # 初めてのIPならリスト初期化
    if src_ip not in packet_history:
        packet_history[src_ip] = []
    
    # 履歴リストを取得
    timestamps = packet_history[src_ip]
    
    # 1. 掃除: 5秒以上前のタイムスタンプを除去
    valid_timestamps = [t for t in timestamps if current_time - t <= TIME_WINDOW]
    
    # 2. 記録: 現在時刻を追加
    valid_timestamps.append(current_time)
    
    # 辞書を更新
    packet_history[src_ip] = valid_timestamps
    
    # 3. カウント
    count = len(valid_timestamps)
    
    print(f"[Stats] Src:{src_ip} Count(5s): {count}") # デバッグ用

    # 4. 判定ロジック
    if count >= THRESHOLD_DROP:
        return LEVEL_DROP, count
    elif count >= THRESHOLD_LB:
        return LEVEL_LB, count
    
    # それ以外は Level 1 (Rate Limit / Normal)
    return LEVEL_NORMAL, count

def packet_process(pkt):
    """
    パケットを受信し、レベル判定 -> ヘッダ書き換え -> 送信 を一括で行う関数
    """
    # 1. フィルタリング (自分発のパケットやIP以外は無視)
    if Ether not in pkt or IP not in pkt:
        return
    if pkt[Ether].src == my_mac: # 自分が送信したパケットは無視 (ループ防止)
        return
    if pkt[IP].dst == my_ip:     # 自分宛てのパケットは無視
        return

    # パケットをコピーして編集開始
    ip = pkt[IP].copy()
    src_ip = ip.src
    
    # 2. レベル判定
    level, count = get_mitigation_level(src_ip)
    
    # 3. 共通処理: ECN (TOS下位2bit) の書き換え
    # 既存のTOSの上位6bitを残しつつ、下位2bitを新しいレベルにする
    ip.tos = (ip.tos & 0b11111100) | level
    
    action_msg = ""

    # 4. レベルごとの分岐処理
    if level == LEVEL_DROP:
        # Level 3: Drop
        # ここでは「Drop対象だよ」というタグ(11)をつけてスイッチに戻す
        # スイッチ側で ipv4.packet_level==3 を見て drop() する
        action_msg = f"DROP (Count={count})"
        
    elif level == LEVEL_LB:
        # Level 2: Load Balance
        # 宛先IPをCDNサーバに書き換える
        original_dst = ip.dst
        new_dst = random.choice(LB_TARGETS)
        ip.dst = new_dst
        action_msg = f"LB {original_dst}->{new_dst} (Count={count})"
        
    else: # LEVEL_NORMAL (Level 1)
        # Level 1: Rate Limit
        # 宛先は変えずにそのまま戻す (スイッチ側でMeterにかかる)
        action_msg = f"RateLimit/Fwd (Count={count})"

    print(f"[SFC] {src_ip} -> {action_msg}")

    # 5. 送信準備 (チェックサム再計算 & MAC解決)
    
    # チェックサム削除 (Scapyに再計算させる)
    del ip.chksum
    del ip.len
    if TCP in ip:
        del ip[TCP].chksum
    elif UDP in ip:
        del ip[UDP].chksum

    # 次の宛先MACアドレスを解決
    # ip.dst が書き換わっている場合(LB時)はその新しいIPに対応するMACを取得
    dst_mac = mac_table.get(ip.dst)
    
    if dst_mac is None:
        print(f"[SFC] Error: MAC not found for {ip.dst}")
        return

    # パケット再構築
    # SrcMAC=自分(h3), DstMAC=次の宛先
    new_pkt = Ether(dst=dst_mac, src=my_mac) / ip
    
    # 送信
    sendp(new_pkt, iface=iface, verbose=False)

# --- Main Process ---
print(f"[*] SFC Integrated Server running on {iface}")
print(f"[*] Thresholds (5sec): Drop>={THRESHOLD_DROP}, LB>={THRESHOLD_LB}")
print("[*] Waiting for packets...")

# prn に統合関数 packet_process を指定
sniff(iface=iface, prn=packet_process, store=0)
