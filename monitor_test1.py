import subprocess
import time
import re
import threading
import os
from scapy.all import sniff, IP

# ---- 設定 ----
INTERVAL = 1               # 監視間隔(秒)
THRESHOLD = 100             # 閾値
THRIFT_PORT = 9090         # CLIのポート
REGISTER_NAME = "MyIngress.test_counter"
HOST_FILE_PATH = "./tmp/hosts.txt" # 通信ペアを保存する場所

# ---- すでにRuntimeを実行したindexを保持 ----
activated_indices = set()
hosts={} # {ハッシュ値:(src,dst)}

# ---- 起動時にhosts.txtを読み込む ----
def load_hosts():
    if os.path.exists(HOST_FILE_PATH):
        with open(HOST_FILE_PATH, 'r') as f:
            for line in f:
                try:
                    h, src, dst = line.strip().split(',')
                    hosts[int(h)] = (src, dst)
                except ValueError:
                    continue
        print(f"[*] {len(hosts)} 件の通信ペアを復元しました。")
    else:
        print("[*] hosts.txt は存在しません。新規作成します。")
        f = open('./tmp/hosts.txt', 'w')
        f.close()

def packet_sniffer():
    print("[*] Sniffer 起動中...")

    def process_packet(pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            key= f"{src}-{dst}"
            h = hash(key) % 1024
            
            if h not in hosts:
                hosts[h] = (src,dst)
                abs_path = os.path.abspath(HOST_FILE_PATH)
                os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                print(f"[DEBUG] Writing to {HOST_FILE_PATH} ({src} -> {dst}, hash={h})")
                print(f"[DEBUG] Directory exists? {os.path.exists(os.path.dirname(HOST_FILE_PATH))}")
                print(f"[DEBUG] Current working dir: {os.getcwd()}")

                with open(HOST_FILE_PATH,mode = 'a', buffering = 1) as f: # mode ='a'->追記
                    f.write(f"{h},{src},{dst}\n")
                    f.flush()
                print(f"[+] 新規ハッシュ値登録: {h} -> {src} -> {dst}")

    sniff(filter = "ip", prn = process_packet, store = False)



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


    
def monitor_loop():
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
                    src_dst = hosts.get(idx, ("不明", "不明"))
                    print(f"[!] ALERT: index={idx} value={val} > {THRESHOLD} ({src_dst})")
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
    load_hosts()
    
    # Sniffer start
    t = threading.Thread(target=packet_sniffer, daemon=True)
    t.start()

    # Register monitor start
    monitor_loop()
