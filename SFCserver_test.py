from scapy.all import *
import random

iface = "eth0"
my_ip = "10.0.3.3"
my_mac = get_if_hwaddr(iface) # 自分のMACアドレスを取得

level_1 = 0b01 # rate limit
level_2 = 0b10
level_3 = 0b11

# h4,h5
loadbalance_IP_list=["10.0.4.4","10.0.5.5"]

mac_table={
    "10.0.1.1":"08:00:00:00:01:11", 
    "10.0.2.2":"08:00:00:00:02:22",
    "10.0.3.3":"08:00:00:00:03:33", 
    "10.0.4.4":"08:00:00:00:04:44",
    "10.0.5.5":"08:00:00:00:05:55",
    "10.0.6.6":"08:00:00:00:06:66",
}

def packet_level_change_1(pkt):
    # Ethernet層またはIP層がないパケットは無視
    if Ether not in pkt or IP not in pkt:
        return
    
    # 【修正1】 送信元MACが自分(h3)なら、自分が送出したパケットなので無視
    if pkt[Ether].src == my_mac:
        return

    # 自分宛て(h3宛て)のパケットも念のため無視（ARPやPingなど）
    if pkt[IP].dst == my_ip:
        return

    ip = pkt[IP].copy()

    # ECN書き換え (下位2bit)
    now_ecn = ip.tos & 0b11 
    new_ecn = level_1
    
    # 値が変わらないなら送り返さない？（要件次第ですが、とりあえず処理する）
    
    ip.tos = (ip.tos & 0b11111100) | new_ecn
    
    print(f"[SFC] ECN {bin(now_ecn)} -> {bin(new_ecn)} (Src:{ip.src} -> Dst:{ip.dst})")

    dst_mac = mac_table.get(ip.dst)
    if dst_mac is None:
        print(f"[SFC] Mac not found for {ip.dst} -> Ignore")
        return

    # 【修正3】 チェックサムと長さを削除してScapyに再計算させる
    del ip.chksum
    del ip.len

    # 【修正2】 ペイロードを二重につけない
    # ip オブジェクトの中に既にペイロードが含まれています
    new_pkt = Ether(dst=dst_mac, src=my_mac) / ip 
        
    # 送
    sendp(new_pkt, iface=iface, verbose=False)
    print(f"[SFC] → Sent back to s1 (DstMAC={dst_mac})")

def packet_level_change_2(pkt):
    if Ether not in pkt or IP not in pkt:
        return
    if pkt[Ether].src == my_mac:
        return
    if pkt[IP].dst == my_ip:
        return

    ip = pkt[IP].copy()
    # ロードバランス処理
    # ランダムに振り分け,ハッシュも可
    new_dst_ip = random.choice(loadbalance_IP_list)

    print(f"[SFC] Load Balancing:{ip.dst} -> {new_dst_ip}")
    ip.dst=new_dst_ip

    # 必要ないけど一応
    new_ecn = level_2
    ip.tos = (ip.tos & 0b11111100) | new_ecn

    # 重要 チェックサム再計算
    del ip.chksum
    del ip.len

    if TCP in ip:
        del ip[TCP].chksum
    elif UDP in ip:
        del ip[UDP].chksum

    dst_mac = mac_table.get(ip.dst)
    if dst_mac is None:
        print(f"[SFC] Mac not found for {ip.dst}")
        return

    new_pkt=Ether(dst=dst_mac, src=my_mac) / ip

    pkt.show()# デバッグ用
    
    sendp(new_pkt, iface=iface, verbose=False)
    
print(f"SFC server running on {iface} ({my_ip} / {my_mac})")
# store=0 にすることでメモリ圧迫を防ぐ
sniff(iface=iface, prn=packet_level_change_1, store=0)
