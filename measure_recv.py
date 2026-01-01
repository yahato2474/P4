#!/usr/bin/env python3
import sys
import time
import csv
import argparse
from statistics import mean, stdev  # stdev(標準偏差)を追加
from scapy.all import sniff, IP, UDP

latencies = []

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", type=str, default="experiment", help="Label for the experiment")
    parser.add_argument("--count", type=int, default=100, help="Expected number of packets")
    parser.add_argument("--output", type=str, default="./latency/h2_h5_honnbannyou_results.csv", help="Output CSV filename")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds") # タイムアウト追加
    return parser.parse_args()

def handle_pkt(pkt):
    global latencies
    if IP in pkt and UDP in pkt:
        try:
            payload = pkt[UDP].payload.load
            send_time = float(payload.decode('utf-8', errors='ignore').strip('A')) # パディング('A')を除去
            current_time = time.time()
            latency_ms = (current_time - send_time) * 1000
            latencies.append(latency_ms)
            
            # 途中経過を表示
            print(f"[{len(latencies)}/{args.count}] Latency: {latency_ms:.2f} ms")
        except:
            pass

def main():
    global args
    args = get_args()
    
    print(f"Waiting for {args.count} packets (Timeout: {args.timeout}s)...")
    
    # timeoutを設定：パケットロスしても時間が来たら終わるようにする
    # UDPをiperfとかぶらないように5555番ポートに変更
    sniff(filter="udp port 5555", prn=handle_pkt, count=args.count, timeout=args.timeout)

    # === 集計処理 ===
    received_count = len(latencies)
    expected_count = args.count
    
    # 1. パケットロス率 (%)
    if expected_count > 0:
        loss_rate = (expected_count - received_count) / expected_count * 100
    else:
        loss_rate = 0.0

    # 2. 平均遅延・最大・最小・ジッタ
    if received_count > 1:
        avg_latency = mean(latencies)
        max_latency = max(latencies)
        min_latency = min(latencies)
        jitter = stdev(latencies) # 標準偏差 = ジッタ
    elif received_count == 1:
        avg_latency = latencies[0]
        max_latency = latencies[0]
        min_latency = latencies[0]
        jitter = 0.0
    else:
        avg_latency = 0.0
        max_latency = 0.0
        min_latency = 0.0
        jitter = 0.0

    print("\n" + "="*40)
    print(f"Result ({args.label}):")
    print(f"  Received: {received_count} / {expected_count}")
    print(f"  Loss Rate: {loss_rate:.2f} %")  # ロス率表示
    print(f"  Avg Latency: {avg_latency:.4f} ms")
    print(f"  Jitter:      {jitter:.4f} ms")  # ジッタ表示
    print("="*40)
    
    # CSV出力 (カラム: ラベル, ロス率, 平均遅延, ジッタ, 受信数)
    # 既存のファイルに追記します
    file_exists = False
    try:
        with open(args.output, 'r') as f:
            file_exists = True
    except FileNotFoundError:
        pass

    with open(args.output, 'a', newline='') as f:
        writer = csv.writer(f)
        # ファイルが新規ならヘッダーを書く
        if not file_exists:
            writer.writerow(["Label", "LossRate(%)", "AvgLatency(ms)", "Jitter(ms)", "ReceivedCount"])
            
        writer.writerow([args.label, f"{loss_rate:.2f}", f"{avg_latency:.4f}", f"{jitter:.4f}", received_count])
        
    print(f"Saved to {args.output}")

if __name__ == '__main__':
    main()