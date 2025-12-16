/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

// 【重要】 色の値を定数として定義 (v1model標準: Green=0, Yellow=1, Red=2)
const bit<32> METER_GREEN = 0;
const bit<32> METER_YELLOW = 1;
const bit<32> METER_RED = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<32> REGISTER_SIZE=1024;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    diffserv;
    bit<2>    packet_level;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<32> packet_count;
    bit<32> index;
    bit<32> meter_tag;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
    inout standard_metadata_t standard_metadata) {


    register <bit<32>>(REGISTER_SIZE) test_counter;
    meter(REGISTER_SIZE, MeterType.packets) my_meter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action count_packet(){
        bit<32> value;
        test_counter.read(value,meta.index); 
        value=value+1;
        test_counter.write(meta.index,value);
    }

    action calc_hash(){
        bit<32> min = 0;
        bit<32> max = REGISTER_SIZE;
        hash(
            meta.index,
            HashAlgorithm.crc32,
            min,
            {
                hdr.ipv4.srcAddr
            },
            max
        );
 }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    /*
    action redirect_with_tag(macAddr_t dstAddr, egressSpec_t port, bit<2> level) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4.packet_level = level; //TOS値書き換え
    }
    */


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
   
    
    table redirect_table{
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.packet_level: exact;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table count_table{
        key={
            hdr.ipv4.srcAddr: exact;
        }
        actions={
            count_packet;
            NoAction;
        }
        size=1024;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            calc_hash(); //　ハッシュ値計算->meta.idxに保存
            count_table.apply(); // idxをもとにregisterに登録

            if(hdr.ipv4.packet_level == 0){
                if(redirect_table.apply().hit){
                    return;
                }
            }

            if(hdr.ipv4.packet_level == 1){
                // load balance
            }

            if(hdr.ipv4.packet_level == 2){
                // rate limit
                my_meter.execute_meter(meta.index, meta.meter_tag);

                // 定数 METER_RED と比較
                if(meta.meter_tag == METER_RED){
                    drop();
                    return;
                }
                // 緑や黄色なら何もしない(通過) -> 下の ipv4_lpm へ
            }


            if(hdr.ipv4.packet_level == 3){
                // drop
                drop();
                return;
            }

            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.packet_level,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;