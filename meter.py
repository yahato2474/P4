import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc

from p4.tmp import p4config_pb2
from google.rpc import status_pb2, code_pb2

P4INFO = "build/basic.p4.p4info.txt"
DEVICE_ID = 0
METER_NAME = "MyIngress.my_meter"  # P4 の meter 名と完全一致させる

def write_meter_config(stub, meter_id, index, cir, pir, cburst, pburst):
    """meter index に CIR / PIR を書き込む"""
    meter_entry = p4runtime_pb2.MeterEntry()
    meter_entry.meter_id = meter_id
    meter_entry.index = index

    meter_entry.config.cir = cir      # packets per second
    meter_entry.config.cburst = cburst
    meter_entry.config.pir = pir
    meter_entry.config.pburst = pburst

    request = p4runtime_pb2.WriteRequest()
    request.device_id = DEVICE_ID
    update = request.updates.add()
    update.type = p4runtime_pb2.Update.MODIFY
    update.entity.meter_entry.CopyFrom(meter_entry)

    stub.Write(request)


def main():
    # gRPC 接続
    channel = grpc.insecure_channel('localhost:9559')
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

    # master arbitration
    arb_req = p4runtime_pb2.StreamMessageRequest()
    arb_req.arbitration.device_id = DEVICE_ID
    arb_req.arbitration.election_id.high = 0
    arb_req.arbitration.election_id.low = 1
    stub.StreamChannel(iter([arb_req]))

    # P4Info 読み込み
    from p4runtime_lib.helper import P4InfoHelper
    p4info_helper = P4InfoHelper(P4INFO)

    meter_id = p4info_helper.get_meter_id(METER_NAME)

    # ==== ★ ここで meter を設定 ★ ====
    # 5 pps を超えたら RED になるように：
    CIR = 5      # committed rate
    PIR = 6      # peak rate
    CBURST = 1   # burst allowance
    PBURST = 1

    # あなたの P4 は index = meta.index を使うので
    # 全 index に対して同じ設定を入れたいならループさせる
    for idx in range(1024):
        write_meter_config(stub, meter_id, idx, CIR, PIR, CBURST, PBURST)

    print("Meter configuration applied successfully!")


if __name__ == '__main__':
    main()
