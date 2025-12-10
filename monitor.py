import subprocess
import time
import re
import os

# 設定秒数間に設定パケット数超えたらルール追加

"""
1. 0〜29秒: 何も起きない（内部でパケット数を数えているだけ）。

2. 30秒時点:

・過去30秒間のパケット増加量を計算。

・100パケット以上来ていたら → runtime_test.py <idx> 2 を実行（ルール追加）。

・100パケット未満なら → もしルールが入っていたら runtime_test.py <idx> 0 を実行（ルール削除）。

3. リセット: その時点のカウント値を基準にして、次の30秒の計測をスタートします。
"""

# ---- 設定 ----
CHECK_INTERVAL = 1.0       # レジスタを読み取る間隔(秒) - 細かく監視は続ける
WINDOW_SIZE = 30.0         # 判定を行うウィンドウサイズ(秒)
THRESHOLD_COUNT = 100      # 30秒間でこのパケット数を超えたらアウト

THRIFT_PORT = 9090
REGISTER_NAME = "MyIngress.test_counter"

# 状態管理
# activated_indices = { index: True/False }
activated_indices = {}

# ウィンドウ開始時のカウント値
# window_start_counts = { index: count }
window_start_counts = {}

# ウィンドウ開始時刻
window_start_time = time.time()

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

def main():
    global window_start_time, window_start_counts

    print("[*] Window-based Monitor started.")
    print(f"[*] Window Size: {WINDOW_SIZE}s")
    print(f"[*] Threshold: {THRESHOLD_COUNT} packets / {WINDOW_SIZE}s")
    
    if not os.path.exists("runtime_test.py"):
        print("[!] Warning: 'runtime_test.py' not found.")

    print("-" * 60)

    # 初回の値をベースラインとして取得
    window_start_counts = read_register()
    window_start_time = time.time()

    while True:
        # 定期的に現在値を取得
        current_counts = read_register()
        current_time = time.time()
        elapsed = current_time - window_start_time

        # ウィンドウ期間が終了したかチェック
        if elapsed >= WINDOW_SIZE:
            print(f"[#] Window finished ({elapsed:.2f}s). Evaluating...")
            
            # 全ての検知済みインデックスについて評価
            all_indices = set(current_counts.keys()) | set(window_start_counts.keys())
            
            for idx in sorted(all_indices):
                # 期間内の増加分を計算
                start_val = window_start_counts.get(idx, 0)
                end_val = current_counts.get(idx, 0)
                diff = end_val - start_val
                
                # P4側でリセットされた場合などのマイナス補正
                if diff < 0: diff = end_val

                is_active = activated_indices.get(idx, False)
                
                print(f"   - index={idx}: {diff} packets (Active={is_active})")

                # --- 判定ロジック ---
                if diff >= THRESHOLD_COUNT:
                    # 閾値超え: ルール追加が必要
                    if not is_active:
                        print(f"[!] Alert: index={idx} exceeded threshold ({diff} > {THRESHOLD_COUNT}) -> Add Rule")
                        try:
                            # Level 2 (Rate Limit) を適用する例
                            subprocess.run(["python3", "runtime_test.py", str(idx), "2"], check=True)
                            activated_indices[idx] = True
                        except subprocess.CalledProcessError as e:
                            print(f"[x] Runtime Error: {e}")
                    else:
                        print(f"[.] index={idx} still high traffic. Rule kept.")

                else:
                    # 閾値以下: ルール削除が必要 (もし適用中なら)
                    if is_active:
                        print(f"[*] Traffic normalized: index={idx} ({diff} <= {THRESHOLD_COUNT}) -> Remove Rule")
                        try:
                            # Level 0 (削除) を適用
                            subprocess.run(["python3", "runtime_test.py", str(idx), "0"], check=True)
                            activated_indices[idx] = False
                        except subprocess.CalledProcessError as e:
                            print(f"[x] Runtime Error: {e}")
            
            print("-" * 60)
            
            # 次のウィンドウへ: 現在の値をスタート値にする
            window_start_counts = current_counts
            window_start_time = time.time()

        # CPU負荷を下げるための短いスリープ
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()