import subprocess
import time
import re
import zlib

# ---- 設定 ----
INTERVAL = 1             # 監視間隔
THRIFT_PORT = 9090         
REGISTER_NAME = "MyIngress.test_counter"
AVG_PKT_BYTES = 1500       # 1パケットあたりのバイト数
BITS_PER_BYTE = 8

# ★ここにSFCのIPを書くだけでOK (マジックナンバー 257 は排除)
SFC_SERVER_IP = "10.0.3.3"
REGISTER_SIZE = 1024  # P4の定義に合わせる
h2_IP="10.0.2.2"  # h2のIPアドレス

# ---- 閾値設定 (Mbps) ----
THRESHOLD_MBPS = 12.0

current_level = 0
last_reset_time = time.time() # 最後にリセットした時刻

def execute_cli(cmd_str):
    """CLIコマンドを実行するヘルパー"""
    full_cmd = f"echo '{cmd_str}' | simple_switch_CLI --thrift-port {THRIFT_PORT}"
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def read_register():
    """値を読む"""
    output = execute_cli(f"register_read {REGISTER_NAME}")
    register_values = {}
    match = re.search(r'MyIngress\.test_counter\s*=\s*(.*)', output)
    if match:
        values_str = match.group(1).strip()
        values = [v.strip() for v in values_str.split(',') if v.strip() != '']
        for i, v in enumerate(values):
            val = int(v)
            if val != 0:
                register_values[i] = val
    return register_values

def reset_register():
    """値を0にリセットする"""
    execute_cli(f"register_reset {REGISTER_NAME}")

    # ==== ★追加: P4と同じロジックでハッシュ(Index)を計算する関数 ====
def calculate_p4_index(ip_str):
    try:
        # IP文字列(10.0.3.3)をバイナリ(Big-Endian 4bytes)に変換
        # sniffer_test.py のロジックをScapyなしで再現
        packed_bytes = bytes(map(int, ip_str.split('.')))
        
        # CRC32計算
        crc = zlib.crc32(packed_bytes) & 0xffffffff
        
        # レジスタサイズで割った余りが Index
        return crc % REGISTER_SIZE
    except Exception as e:
        print(f"[!] Hash calculation failed for {ip_str}: {e}")
        return -1

def main():
    global last_reset_time, current_level

    sfc_index = calculate_p4_index(SFC_SERVER_IP)
    h2_index = calculate_p4_index(h2_IP)

    print("[*] Register monitor started (Silent Mode).")
    print(f"[*] Interval: {INTERVAL}s")
    print(f"[*] Threshold: > {THRESHOLD_MBPS} Mbps")
    
    # 起動時に一度リセットしてクリーンにする
    print("[*] Initial reset...")
    reset_register()
    last_reset_time = time.time()
    time.sleep(INTERVAL)

    while True:
        # 1. 指定時間待つ
        time.sleep(INTERVAL)

        # 2. 現在時刻を記録
        now = time.time()
        
        # 3. レジスタを読み取る
        current_counts = read_register()

        # 4. すぐにリセットする (次回の測定のため)
        reset_register()

        # 5. 正確な経過時間を計算 (前回リセット〜今回読み取りまでの時間)
        time_delta = now - last_reset_time
        last_reset_time = now # 時刻更新

        if time_delta < 0.1: continue # エラー防止

        # 全インデックスをチェック
        for idx, packet_count in current_counts.items():
            
            # ==== SFCのIndexならスキップ ====
            if idx == sfc_index:
                # ★修正: 毎回表示すると邪魔なのでコメントアウト
                # print(f"[*] Ignoring SFC Server traffic (Index={idx})")
                continue
            if idx == h2_index:
                # ★修正: 毎回表示すると邪魔なのでコメントアウト
                # print(f"[*] Ignoring h2 traffic (Index={idx})")
                continue

            # 計算: (パケット数 / 経過時間) * サイズ * 8ビット / 1M
            pps = packet_count / time_delta
            mbps = (pps * AVG_PKT_BYTES * BITS_PER_BYTE) / 1_000_000.0

            # ★修正: 毎回のMbps表示もコメントアウト (ここが処理を軽くするポイント)
            # if mbps > 0:
            #     print(f"[.] Index={idx}: {mbps:.2f} Mbps (pps={pps:.1f}, time={time_delta:.2f}s)")

            # ---- 判定ロジック ----
            new_level = 0
            if mbps >= THRESHOLD_MBPS:
                new_level = 1
            else:
                new_level = 0

            # 状態変化時のみアクション（ここは表示する）
            if new_level != current_level:
                print(f"[!] STATUS CHANGE: {mbps:.2f} Mbps (Lv{current_level}->Lv{new_level})")
                
                try:
                    if new_level > 0:
                        # ルール追加
                        subprocess.run(["python3", "runtime_test.py", str(idx), str(new_level)], check=True)
                    else:
                        # ルール削除
                        print(f"[*] Traffic normalized. Removing rule.")
                        subprocess.run(["python3", "runtime_test.py", str(idx), "0"], check=True)
                    
                    current_level = new_level

                except Exception as e:
                    print(f"[x] Error: {e}")

if __name__ == "__main__":
    main()