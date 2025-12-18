import subprocess
import time
import re

# ppsを閾値に、レベル変わるごとに転送ルール追加・削除

# ---- 設定 ----
INTERVAL = 1.0             # 監視間隔(秒)
THRIFT_PORT = 9090         # CLIのポート

REGISTER_NAME = "MyIngress.test_counter"

# ---- 閾値設定 (パケット数/秒 = pps) ----
# 順序変更: LB -> RL -> Drop
THRESHOLD_L1_LB   = 10  # Level 1: Load Balance (分散)
THRESHOLD_L2_RL   = 40  # Level 2: Rate Limit (制限)
THRESHOLD_L3_DROP = 60  # Level 3: Drop (遮断)

# 各indexの状態管理
# current_levels = { index: level }
# level 0: ルールなし(通常)
# level 1: LB (Load Balance)
# level 2: RL (Rate Limit)
# level 3:Drop
current_levels = {}
# 前回のカウント値 (差分計算用)
last_counts = {}

def read_register():
    """register_readでtest_counterの全値を取得"""
    cmd = f"echo 'register_read {REGISTER_NAME}' | simple_switch_CLI --thrift-port {THRIFT_PORT}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout.strip()

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
    """register_resetで全要素をリセット"""
    cmd = f"echo 'register_reset MyIngress.test_counter' | simple_switch_CLI --thrift-port {THRIFT_PORT}"
    subprocess.run(cmd, shell=True)
    # print("[*] Register reset complete.")

def main():
    print("[*] Register monitor started.")
    print(f"[*] Interval: {INTERVAL}s")
    print(f"[*] Thresholds: LB>={THRESHOLD_L1_LB}, RL>={THRESHOLD_L2_RL}, Drop>={THRESHOLD_L3_DROP}")
    print("-" * 60)

    while True:
        start_time = time.time()
        
        # 1. 現在のカウンタ値を取得 (累積値)
        current_counts = read_register()

        # カウント値があるものだけでなく、前回記録があったものも含めてチェック
        all_indices = set(current_counts.keys()) | set(last_counts.keys())

        for idx in sorted(all_indices):
            cumulative_val = current_counts.get(idx, 0)
            
            # 2. 差分(pps)の計算
            prev_val = last_counts.get(idx, 0)
            diff = cumulative_val - prev_val
            if diff < 0: diff = cumulative_val # リセット対応

            pps = diff
            
            # 3. レベル判定 (新しい順序に対応)
            new_level = 0
            if pps >= THRESHOLD_L3_DROP:
                new_level = 3 # Drop
            elif pps >= THRESHOLD_L2_RL:
                new_level = 2 # Rate Limit
            elif pps >= THRESHOLD_L1_LB:
                new_level = 1 # Load Balance
            else:
                new_level = 0 # 解除
            
            # 4. 状態変更の検知と適用
            old_level = current_levels.get(idx, 0)
            
            if new_level != old_level:
                print(f"[!] Rate Change: index={idx} {pps}pps (Lv{old_level}->Lv{new_level})")
                
                try:
                    if new_level > 0:
                        # ルール追加・更新 (runtime.py <index> <level>)
                        subprocess.run(["python3", "runtime_test.py", str(idx), str(new_level)], check=True)
                    else:
                        # ルール削除
                        print(f"[*] Removing rule for index={idx} (Traffic normalized)")
                        subprocess.run(["python3", "runtime_test.py", str(idx), "0"], check=True)

                except subprocess.CalledProcessError as e:
                    print(f"[x] Runtime error: {e}")

                # 状態更新
                current_levels[idx] = new_level
            
            elif pps > 0 or old_level > 0:
                print(f"[.] index={idx} {pps}pps (Lv{new_level})")

            if idx in current_counts:
                last_counts[idx] = cumulative_val

        # スリープ調整
        elapsed = time.time() - start_time
        sleep_time = max(0, INTERVAL - elapsed)
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
