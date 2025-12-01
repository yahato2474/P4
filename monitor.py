import subprocess
import time
import re

# ---- 設定 ----
INTERVAL = 1               # 監視間隔(秒)
THRESHOLD = 1             # 閾値
THRIFT_PORT = 9090         # CLIのポート

# ---- すでにRuntimeを実行したindexを保持 ----
activated_indices = set()

REGISTER_NAME = "MyIngress.test_counter"

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
    print("[*] Register reset complete.")


    
def main():
    print("[*] Register monitor started.")
    print(f"[*] Watching register '{REGISTER_NAME}' every {INTERVAL}s (threshold={THRESHOLD})")
    print("-" * 60)

    while True:
        reg_values = read_register()

        if not reg_values:
            print("[=] 全ての値が0です。")
            time.sleep(INTERVAL)
            continue

        for idx, val in sorted(reg_values.items()):
            print(f"[+] index={idx} value={val}")

            if val > THRESHOLD:
                if idx not in activated_indices:
                    print(f"[!] ALERT: index={idx} value={val} exceeds threshold ({THRESHOLD})")
                    try:
                        subprocess.run(["python3", "runtime.py", str(idx)], check=True)
                        activated_indices.add(idx)
                        reset_register()
                    except subprocess.CalledProcessError as e:
                        print(f"[x] Runtime update failed for index={idx}: {e}")
                else:
                    print(f"[~] index={idx} はすでにRuntime適用済み。")

        print("-" * 60)
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
