#!/usr/bin/env python3
import os
import sys
import grpc
import csv

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/')
)

import p4runtime_lib.bmv2
from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4.v1 import p4runtime_pb2


# 各種設定
P4INFO_PATH = 'build/basic.p4.p4info.txt'
BMV2_JSON_PATH = 'build/basic.json'
SWITCH_ADDRESS = '127.0.0.1:50051'
DEVICE_ID = 0
HOST_FILE_PATH = "./tmp/hosts.txt"

# SFCサーバ(h3)の情報
DST_MAC_h3 = "08:00:00:00:03:33"
DST_PORT_h3 = 3

# meter設定
METER_RATE = 5  # レート,ppsの設定
METER_BURST = 5 # バースト: 一瞬なら5パケット溜め込んでもOK

def lookup_ip_pair(index):
    #hosts.txt から index(ハッシュ値)に対応する通信ペア(src, dst)を探す
    if not os.path.exists(HOST_FILE_PATH):# hosts.txtが無いとき
        print(f"[!] hosts.txt が見つかりません: {HOST_FILE_PATH}")
        return None, None

    with open(HOST_FILE_PATH, 'r')as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) == 3:
                h, src, dst = row
                try:
                    if int(h) == int(index):
                        return src, dst
                except ValueError:
                    continue
    return None,None

"""
def write_meter_entry(s1,p4info_helper, index):
    print(f"[*] Setting meter for index={index} (Rate={METER_RATE} pps)")

    meter_entry = p4info_helper.buildMeterEntry(
        meter_name="MyIngress.my_meter",
        index=index,

        cir=METER_RATE,
        cburst=METER_BURST,
        pir=METER_RATE,
        pburst=METER_BURST
    )

    # 書き込みリクエスト
    request = p4runtime_pb2.WriteRequest() # スイッチへのルール書き込みリクエストを作成
    request.device_id = DEVICE_ID # 対象スイッチを指定
    request.election_id.low = 1  # コントローラのマスター権限を示す 
    update = request.updates.add()   # 書き込み操作を追加
    update.type = p4runtime_pb2.Update.MODIFY # Meterは既に存在するのでMODIFY
    update.entity.meter_entry.CopyFrom(meter_entry)   #ルール追加操作であることを指定

    try:
        s1.client_stub.Write(request)
        print(f"[+] Meter entry updated successfully.")
    except grpc.RpcError as e:
        print(f"[!] Meter update failed: {e.details()}")
"""
    

def insert_redirect_rule(src_ip,dst_ip,index):
    #P4に転送ルール追加
    print(f"[*] Redirecting packets from src={src_ip} to h3 ({DST_MAC_h3}, port={DST_PORT_h3})")
    
    if not os.path.exists(P4INFO_PATH):
        print(f"[!] p4info file not found: {P4INFO_PATH}")
        sys.exit(1)
    p4info_helper = P4InfoHelper(P4INFO_PATH)

    # 接続先スイッチの設定
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address=SWITCH_ADDRESS,
        device_id=DEVICE_ID,
        proto_dump_file='logs/runtime_redirect_to_h3.txt'
    ) 

    try:
        s1.MasterArbitrationUpdate()
    except grpc.RpcError as e:
        print("[!] MasterArbitrationUpdate failed:", e.details())
        ShutdownAllSwitchConnections()
        sys.exit(1)



          
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.redirect_table",
        match_fields={
            "hdr.ipv4.srcAddr": src_ip,
            "hdr.ipv4.dstAddr": dst_ip,
            "hdr.ipv4.packet_level": 0
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": DST_MAC_h3,
            "port": DST_PORT_h3
        }
    )
    # 書き込みリクエスト
    request = p4runtime_pb2.WriteRequest() # スイッチへのルール書き込みリクエストを作成
    request.device_id = DEVICE_ID # 対象スイッチを指定
    request.election_id.low = 1  # コントローラのマスター権限を示す 
    update = request.updates.add()   # 書き込み操作を追加
    update.type = p4runtime_pb2.Update.INSERT 
    update.entity.table_entry.CopyFrom(table_entry)   #ルール追加操作であることを指定


    try:
        s1.client_stub.Write(request) #  実際にスイッチへ送信
        print(f"[+] Redirect rule inserted successfully for src={src_ip}, dst={dst_ip}")
    except grpc.RpcError as e:
        print("[!] gRPC error:", e.code(), e.details())

    ShutdownAllSwitchConnections()
    print("[*] Done.")



    
def main():
    #monitor.pyから実行されるコード -> subprocess.run(["python3", "runtime.py", str(idx)], check=True)
    if len(sys.argv) < 2:
        print("Usage: python3 runtime.py <index>")
        sys.exit(1)

    index = int(sys.argv[1])# str(idx)
    print(f"[*] Received index = {index}")

    src_ip, dst_ip = lookup_ip_pair(index)
    if src_ip is None or dst_ip is None:
        print(f"[x] index={index} に対応する通信ペアが hosts.txt に見つかりません。")
        sys.exit(1)

    

if __name__ == "__main__":
    main()

    
