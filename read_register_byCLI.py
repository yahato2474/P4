import subprocess
import time
import re

def read_register(register_name="MyIngress.test_counter", index=0, port=9090, interval=3):
    while True:
        # CLIコマンドを実行
        cmd = f"echo 'register_read {register_name} {index}' | simple_switch_CLI --thrift-port {port}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        # 出力を取得
        output = result.stdout.strip()
        print("----- CLI OUTPUT -----")
        print(output)

        # 値だけ抜き出す
        match = re.search(r'\[(\d+)\]\s*=\s*(\d+)', output)
        if match:
            idx, value = match.groups()
            print(f"[OK] Register {register_name}[{idx}] = {value}")
        else:
            print("[WARN] Register value not found in output")

        # 待機
        time.sleep(interval)

if __name__ == "__main__":
    print("[*] Auto reading register via CLI...")
    read_register()
