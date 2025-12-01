from scapy.all import sniff, IP, get_if_list
import os
import threading
import time
import zlib
import struct

hosts = {}

def sniff_on_interface(iface):
    print("[*] Sniffer起動中...")
    sniff(iface=iface, filter = "ip", prn = handle_packet, store = 0)

def handle_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        key = (src,dst)
        if key not in hosts:
            hosts[key] = True
            print(f"[Sniffer] 新しい通信ペアを発見: {src} → {dst}")

def register_monitor():
    while True:
        print("[Monitor] Register監視中...")
        # ここに register 読み出し処理を入れる想定
        time.sleep(2)

def main():
    interfaces = [i for i in get_if_list() if i.startswith("s1-eth")]
    if not interfaces:
        print("[!] 監視対象のインタフェースが見つかりません。")
        return

    print(f"[*] 対象インタフェース: {interfaces}")
    for iface in interfaces:
        t = threading.Thread(target=sniff_on_interface,args=(iface,),daemon=True)
        t.start()

    try:
        while True:
            print(f"[Main] 現在 {len(hosts)} ペア検出済み。稼働中...")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] 停止しました。")

if __name__ == "__main__":
    main()

    #print("[*] Register監視を開始します...")
    #register_monitor()
