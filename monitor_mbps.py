import subprocess
import time
import re
import zlib

# ---- 設定 ----
INTERVAL = 1             
THRIFT_PORT = 9090         
REGISTER_NAME = "MyIngress.packet_counter"
AVG_PKT_BYTES = 1500  
BITS_PER_BYTE = 8

# 無視する対象
SFC_SERVER_IP = "10.0.3.3"
H2_IP = "10.0.2.2"
REGISTER_SIZE = 1024 

# ---- ★修正ポイント1: 閾値を2段階にする（ヒステリシス） ----
THRESHOLD_HIGH = 8.0  # これを超えたら防御 ON
THRESHOLD_LOW  = 6.0   # これを下回ったら防御 OFF

# ---- ★修正ポイント2: 状態をインデックスごとに保存する辞書にする ----
current_levels = {}     # {index: level}
last_packet_counts = {} # {index: count} (差分計算用)

def execute_cli(cmd_str):
    full_cmd = f"echo '{cmd_str}' | simple_switch_CLI --thrift-port {THRIFT_PORT}"
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def read_register():
    output = execute_cli(f"register_read {REGISTER_NAME}")
    register_values = {}
    match = re.search(r'MyIngress\.packet_counter\s*=\s*(.*)', output)
    if match:
        values_str = match.group(1).strip()
        values = [v.strip() for v in values_str.split(',') if v.strip() != '']
        for i, v in enumerate(values):
            val = int(v)
            if val != 0:
                register_values[i] = val
    return register_values

# reset_register は削除 (安定化のため)

def calculate_p4_index(ip_str):
    try:
        packed_bytes = bytes(map(int, ip_str.split('.')))
        crc = zlib.crc32(packed_bytes) & 0xffffffff
        return crc % REGISTER_SIZE
    except:
        return -1

def main():
    sfc_index = calculate_p4_index(SFC_SERVER_IP)
    h2_index = calculate_p4_index(H2_IP)

    print("[*] Monitor Started (Stability Mode)")
    print(f"[*] ON Threshold:  > {THRESHOLD_HIGH} Mbps")
    print(f"[*] OFF Threshold: < {THRESHOLD_LOW} Mbps")
    
    # 初回時刻
    last_time = time.time()

    while True:
        time.sleep(INTERVAL)

        now = time.time()
        time_delta = now - last_time
        last_time = now
        
        if time_delta < 0.1: continue

        # 1. 読み取り (リセットしない！)
        current_cumulative = read_register()

        for idx, count_now in current_cumulative.items():
            
            # 除外判定
            if idx == sfc_index or idx == h2_index:
                continue

            # 2. 差分計算 (今回 - 前回)
            count_prev = last_packet_counts.get(idx, 0)
            
            if count_now >= count_prev:
                delta = count_now - count_prev
            else:
                # オーバーフロー対策
                delta = (4294967296 - count_prev) + count_now
            
            # 保存
            last_packet_counts[idx] = count_now

            # Mbps計算
            pps = delta / time_delta
            mbps = (pps * AVG_PKT_BYTES * BITS_PER_BYTE) / 1_000_000.0

            # ---- ★修正ポイント3: 判定ロジック ----
            
            # このインデックスの現在のレベルを取得 (なければ0)
            my_current_level = current_levels.get(idx, 0)
            new_level = my_current_level # デフォルトは「維持」

            if my_current_level == 0:
                # 今が通常時なら、HIGHを超えたら攻撃認定
                if mbps >= THRESHOLD_HIGH:
                    new_level = 1
            else:
                # 今が防御中なら、LOWを下回るまでは解除しない（粘る）
                if mbps < THRESHOLD_LOW:
                    new_level = 0
                else:
                    new_level = 1 # 維持

            # 状態変化があった時だけ処理
            if new_level != my_current_level:
                print(f"[!] Idx={idx}: {mbps:.2f} Mbps -> Change Lv{my_current_level} to Lv{new_level}")
                
                try:
                    if new_level > 0:
                        subprocess.run(["python3", "runtime_test.py", str(idx), str(new_level)], check=True)
                    else:
                        print(f"[*] Traffic normalized (Idx={idx}). Removing rule.")
                        subprocess.run(["python3", "runtime_test.py", str(idx), "0"], check=True)
                    
                    # 辞書を更新
                    current_levels[idx] = new_level

                except Exception as e:
                    print(f"[x] Error: {e}")

if __name__ == "__main__":
    main()