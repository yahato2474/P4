from scapy.all import IP
import zlib
import struct

def p4_like_crc32(src_ip, dst_ip):
    # IPヘッダを作成
    pkt = IP(src=src_ip, dst=dst_ip)

    # P4が参照している部分（srcAddr + dstAddr）をバイト列に変換
    src_bytes = struct.pack("!I", int.from_bytes(bytes(map(int, pkt.src.split('.'))), 'big'))
    dst_bytes = struct.pack("!I", int.from_bytes(bytes(map(int, pkt.dst.split('.'))), 'big'))
    concat_bytes = src_bytes + dst_bytes

    # CRC32計算
    crc = zlib.crc32(concat_bytes) & 0xffffffff
    return crc

if __name__ == "__main__":
    src_ip_1 = "10.0.1.1"
    dst_ip_1 = "10.0.5.5"

    crc_val_1 = p4_like_crc32(src_ip_1, dst_ip_1)
    print(f"src={src_ip_1}, dst={dst_ip_1}")
    print(f"→ CRC32 = {crc_val_1} (0x{crc_val_1:08x})")

    # registerサイズに合わせてインデックス化
    idx_1 = crc_val_1 % 1024
    print(f"→ Register index = {idx_1}\n")
    
    src_ip_2 = "10.0.1.1"
    dst_ip_2 = "10.0.4.4"

    crc_val_2 = p4_like_crc32(src_ip_2, dst_ip_2)
    print(f"src={src_ip_2}, dst={dst_ip_2}")
    print(f"→ CRC32 = {crc_val_2} (0x{crc_val_2:08x})")

    # registerサイズに合わせてインデックス化
    idx_2 = crc_val_2 % 1024
    print(f"→ Register index = {idx_2}\n")

    src_ip_3 = "10.0.2.2"
    dst_ip_3 = "10.0.5.5"

    crc_val_3 = p4_like_crc32(src_ip_3, dst_ip_3)
    print(f"src={src_ip_3}, dst={dst_ip_3}")
    print(f"→ CRC32 = {crc_val_3} (0x{crc_val_3:08x})")

    # registerサイズに合わせてインデックス化
    idx_3 = crc_val_3 % 1024
    print(f"→ Register index = {idx_3}\n")

    src_ip_4 = "10.0.2.2"
    dst_ip_4 = "10.0.4.4"

    crc_val_4 = p4_like_crc32(src_ip_4, dst_ip_4)
    print(f"src={src_ip_4}, dst={dst_ip_4}")
    print(f"→ CRC32 = {crc_val_4} (0x{crc_val_4:08x})")

    # registerサイズに合わせてインデックス化
    idx_4 = crc_val_4 % 1024
    print(f"→ Register index = {idx_4}\n")
