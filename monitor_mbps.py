import subprocess
import time
import re

# ---- 設定 ----
INTERVAL = 1             # 監視間隔
THRIFT_PORT = 9090         
REGISTER_NAME = "MyIngress.test_counter"
AVG_PKT_BYTES = 1500       # 1パケットあたりのバイト数
BITS_PER_BYTE = 8

# ---- 閾値設定 (Mbps) ----
THRESHOLD_MBPS = 11.0

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

def main():
    global last_reset_time, current_level

    print("[*] Register monitor started (Read-and-Reset Mode).")
    print(f"[*] Interval: {INTERVAL}s")
    print(f"[*] Threshold: > {THRESHOLD_MBPS} Mbps")
    
    # 起動時に一度リセットしてクリーンにする
    print("[*] Initial reset...")
    reset_register()
    last_reset_time = time.time()
    time.sleep(INTERVAL)

    while True:
        # 1. 指定時間待つ
        # (処理時間を考慮して、正確なスリープ時間を計算する必要はない。
        #  「実際に経過した時間」で割り算すれば正確な速度が出るため)
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
        # (今回はリセットするので、0以外の値が入っている＝この1秒間にパケットが来たということ)
        for idx, packet_count in current_counts.items():
            
            # 計算: (パケット数 / 経過時間) * サイズ * 8ビット / 1M
            pps = packet_count / time_delta
            mbps = (pps * AVG_PKT_BYTES * BITS_PER_BYTE) / 1_000_000.0

            # ログ表示
            if mbps > 0:
                print(f"[.] Index={idx}: {mbps:.2f} Mbps (pps={pps:.1f}, time={time_delta:.2f}s)")

            # ---- 判定ロジック ----
            new_level = 0
            if mbps >= THRESHOLD_MBPS:
                new_level = 1
            else:
                new_level = 0

            # 状態変化時のみアクション
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