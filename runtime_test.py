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
HOST_FILE_PATH = "./tmp/hosts_test.txt"

# SFCサーバ(h3)の情報
DST_MAC_h3 = "08:00:00:00:03:33"
DST_PORT_h3 = 3

# Meter設定
METER_RATE = 1
METER_BURST = 1

def lookup_ip_pair(index):
    if not os.path.exists(HOST_FILE_PATH):
        print(f"[!] hosts.txt が見つかりません: {HOST_FILE_PATH}")
        return None, None
    with open(HOST_FILE_PATH, 'r') as f:
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

# エラー回避用の自作関数
def build_meter_entry_direct(p4info_helper, meter_name, index, cir, cburst, pir, pburst):
    meter_entry = p4runtime_pb2.MeterEntry()
    try:
        meter_id = p4info_helper.get_meters_id(meter_name)
    except:
        meter_id = p4info_helper.get_id("meters", meter_name)
        
    meter_entry.meter_id = meter_id
    meter_entry.index.index = index
    
    meter_entry.config.cir = cir
    meter_entry.config.cburst = cburst
    meter_entry.config.pir = pir
    meter_entry.config.pburst = pburst
    return meter_entry

def write_meter_entry(s1, p4info_helper, index):
    meter_entry = build_meter_entry_direct(
        p4info_helper,
        meter_name="MyIngress.my_meter",
        index=index,
        cir=METER_RATE, cburst=METER_BURST,
        pir=METER_RATE, pburst=METER_BURST
    )
    request = p4runtime_pb2.WriteRequest()
    request.device_id = DEVICE_ID
    request.election_id.low = 1
    update = request.updates.add()
    update.type = p4runtime_pb2.Update.MODIFY
    update.entity.meter_entry.CopyFrom(meter_entry)
    try:
        s1.client_stub.Write(request)
    except grpc.RpcError as e:
        print(f"[!] Meter update failed: {e.details()}")

def delete_redirect_rule(s1, p4info_helper, src_ip, dst_ip):
    print(f"[*] Deleting rule for src={src_ip}")
    
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
    
    request = p4runtime_pb2.WriteRequest()
    request.device_id = DEVICE_ID
    request.election_id.low = 1
    update = request.updates.add()
    update.type = p4runtime_pb2.Update.DELETE 
    update.entity.table_entry.CopyFrom(table_entry)
    
    try:
        s1.client_stub.Write(request)
        print(f"[+] Rule Deleted successfully.")
    except grpc.RpcError as e:
        print(f"[!] Delete failed: {e.details()}")

def insert_redirect_rule(src_ip, dst_ip, index, level):
    if not os.path.exists(P4INFO_PATH):
        print(f"[!] p4info file not found.")
        sys.exit(1)
    p4info_helper = P4InfoHelper(P4INFO_PATH)

    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address=SWITCH_ADDRESS,
        device_id=DEVICE_ID,
        proto_dump_file='logs/runtime_redirect.txt'
    ) 

    try:
        s1.MasterArbitrationUpdate()
    except grpc.RpcError as e:
        print("[!] MasterArbitrationUpdate failed:", e.details())
        ShutdownAllSwitchConnections()
        sys.exit(1)

    # Level 0なら削除
    if level == 0:
        delete_redirect_rule(s1, p4info_helper, src_ip, dst_ip)
        ShutdownAllSwitchConnections()
        return

    # 追加・更新
    print(f"[*] Redirecting src={src_ip} to SFC (Tag Level={level})")

    # Meter設定
    write_meter_entry(s1, p4info_helper, index)
          
    # リダイレクトルール
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

    request = p4runtime_pb2.WriteRequest() 
    request.device_id = DEVICE_ID 
    request.election_id.low = 1  
    update = request.updates.add()   
    update.type = p4runtime_pb2.Update.INSERT 
    update.entity.table_entry.CopyFrom(table_entry)

    try:
        s1.client_stub.Write(request) 
        print(f"[+] Rule Inserted: Level {level}")
    except grpc.RpcError as e:
        # INSERT失敗ならMODIFY
        request = p4runtime_pb2.WriteRequest() 
        request.device_id = DEVICE_ID 
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        update.entity.table_entry.CopyFrom(table_entry)
        try:
            s1.client_stub.Write(request)
            print(f"[+] Rule Modified: Level {level}")
        except grpc.RpcError as e2:
            print("[!] Both Insert/Modify failed:", e2.details())

    ShutdownAllSwitchConnections()

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 runtime.py <index> <level>")
        sys.exit(1)

    index = int(sys.argv[1])
    level = int(sys.argv[2])

    src_ip, dst_ip = lookup_ip_pair(index)
    if src_ip is None:
        print(f"[x] index={index} not found.")
        sys.exit(1)

    insert_redirect_rule(src_ip, dst_ip, index, level)

if __name__ == "__main__":
    main()