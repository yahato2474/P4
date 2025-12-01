#Maybe dont work
#!/usr/bin/env python3
import sys
import grpc
import os

#p4runtime_libまでのパス
sys.path.append(os.path.join(os.path.dirname(__file__), '../../utils'))

from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.bmv2
import p4runtime_lib.helper

# 1. P4InfoファイルとJSONファイルのパス
P4INFO_FILE_PATH = "build/basic.p4.p4info.txt"
BMV2_JSON_FILE_PATH = "build/basic.json"

def read_register():
    # 2. P4Runtime helperをロード
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(P4INFO_FILE_PATH)

    # 3. スイッチに接続 (s1: thrift=9090, grpc=50051)
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=0,
        proto_dump_file='logs/s1-p4runtime.log'
    )

    # 4. Masterとして接続開始
    s1.MasterArbitrationUpdate()

    print("[*] Reading register values from MyIngress.test_counter")

    # Registerエントリを読み出す
    entities = s1.ReadTableEntries()  # 全エントリを取得
    reg_id = p4info_helper.get_registers_id('MyIngress.test_counter')

    # P4RuntimeではRegisterもEntityの一種として扱うので、ReadTableEntriesではなく
    # StreamMessageRequestを直接構築する方法を使う：
    from p4.v1 import p4runtime_pb2

    request = p4runtime_pb2.ReadRequest()
    request.device_id = 0
    entity = request.entities.add()
    entity.register_entry.register_id = reg_id

    response = s1.client_stub.Read(request)
    for rep in response:
        for entity in rep.entities:
            reg = entity.register_entry
            idx = reg.index.index
            val = int.from_bytes(reg.data[0].value, byteorder='big')
            print(f"  index {idx}: value = {val}")


    # 7. 終了処理
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    read_register()
