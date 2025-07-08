#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
8BitDo固件分析工具
用于分析固件文件中的X.509私钥和公钥
"""

import os
import sys
import binascii
import struct
import re

def analyze_firmware(firmware_path):
    """
    分析固件文件，查找X.509私钥和公钥
    """
    print("正在分析固件文件: {}".format(firmware_path))
    
    if not os.path.exists(firmware_path):
        print("错误: 文件不存在")
        return
    
    try:
        with open(firmware_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print("错误: 无法读取文件 - {}".format(e))
        return
    
    print("文件大小: {} bytes".format(len(data)))
    
    # 查找X.509相关字符串
    x509_patterns = [
        b'-----BEGIN CERTIFICATE-----',
        b'-----END CERTIFICATE-----',
        b'-----BEGIN PRIVATE KEY-----',
        b'-----END PRIVATE KEY-----',
        b'-----BEGIN RSA PRIVATE KEY-----',
        b'-----END RSA PRIVATE KEY-----',
        b'-----BEGIN PUBLIC KEY-----',
        b'-----END PUBLIC KEY-----',
        b'-----BEGIN RSA PUBLIC KEY-----',
        b'-----END RSA PUBLIC KEY-----',
        b'X.509',
        b'RSA',
        b'PRIVATE KEY',
        b'PUBLIC KEY',
        b'CERTIFICATE'
    ]
    
    print("\n=== 搜索X.509相关字符串 ===")
    found_patterns = []
    for pattern in x509_patterns:
        matches = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            matches.append(pos)
            start = pos + 1
        
        if matches:
            found_patterns.append((pattern, matches))
            print("找到模式 '{}' 在位置: {}".format(pattern.decode('utf-8', errors='ignore'), matches))
    
    # 查找ASN.1 DER编码结构
    print("\n=== 搜索ASN.1 DER编码结构 ===")
    asn1_patterns = [
        b'\x30\x82',  # SEQUENCE with long form length
        b'\x30\x81',  # SEQUENCE with medium form length
        b'\x02\x01\x00',  # INTEGER 0 (common in private keys)
        b'\x02\x82',  # INTEGER with long form length
        b'\x04\x20',  # OCTET STRING of 32 bytes (common for keys)
        b'\x04\x40',  # OCTET STRING of 64 bytes
        b'\x03\x82',  # BIT STRING with long form length
    ]
    
    asn1_found = []
    for pattern in asn1_patterns:
        matches = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            matches.append(pos)
            start = pos + 1
        
        if matches:
            asn1_found.append((pattern, matches))
            print("找到ASN.1模式 {} 在位置: {}".format(binascii.hexlify(pattern).decode(), matches[:10]))  # 限制显示前10个
    
    # 查找可能的密钥长度数据块
    print("\n=== 搜索可能的密钥数据块 ===")
    key_sizes = [128, 256, 512, 1024, 2048, 4096]  # 常见密钥长度（字节）
    
    for size in key_sizes:
        # 查找连续的非零数据块
        for i in range(0, len(data) - size, 16):  # 每16字节检查一次
            chunk = data[i:i+size]
            # 检查是否包含足够的随机性（简单启发式）
            if len(set(chunk)) > size // 4:  # 至少1/4的字节是不同的
                zero_count = chunk.count(b'\x00')
                if zero_count < size // 8:  # 零字节不超过1/8
                    print("可能的{}字节密钥数据在位置 0x{:08x}".format(size, i))
                    print("  前32字节: {}".format(binascii.hexlify(chunk[:32]).decode()))
                    
                    # 保存可能的密钥数据
                    filename = "possible_key_{}bytes_at_0x{:08x}.bin".format(size, i)
                    dump_key_data(chunk, filename)
                    break  # 每个大小只找第一个
    
    # 查找特定的密钥算法标识符
    print("\n=== 搜索密钥算法标识符 ===")
    oid_patterns = {
        b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01': 'RSA加密',
        b'\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07': 'ECDSA P-256',
        b'\x30\x05\x06\x03\x2b\x65\x70': 'Ed25519',
        b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01': 'RSA OID',
        b'\x2a\x86\x48\xce\x3d\x03\x01\x07': 'ECDSA P-256 OID'
    }
    
    for oid, name in oid_patterns.items():
        pos = data.find(oid)
        if pos != -1:
            print("找到{} OID在位置 0x{:08x}".format(name, pos))
            # 显示周围的数据
            start = max(0, pos - 32)
            end = min(len(data), pos + len(oid) + 32)
            context = data[start:end]
            print("  上下文: {}".format(binascii.hexlify(context).decode()))
    
    # 生成十六进制转储
    if found_patterns or asn1_found:
        print("\n=== 生成详细的十六进制转储 ===")
        all_positions = set()
        for pattern, positions in found_patterns + asn1_found:
            all_positions.update(positions)
        
        for pos in sorted(list(all_positions)[:5]):  # 只显示前5个位置
            print("\n位置 0x{:08x} 周围的数据:".format(pos))
            start = max(0, pos - 64)
            end = min(len(data), pos + 128)
            chunk = data[start:end]
            print(hex_dump(chunk, start))
    
    print("\n分析完成!")

def dump_key_data(data, filename):
    """
    将可能的密钥数据保存到文件
    """
    output_dir = "/Volumes/evo2T/8bitdo-firmware/extracted_keys"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_path = os.path.join(output_dir, filename)
    with open(output_path, 'wb') as f:
        f.write(data)
    print("  已保存到: {}".format(output_path))

def hex_dump(data, offset=0, width=16):
    """
    生成十六进制转储
    """
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join('{:02x}'.format(b) for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append('{:08x}: {:<48} |{}|'.format(offset + i, hex_part, ascii_part))
    return '\n'.join(result)

def main():
    # 默认分析指定的固件文件
    firmware_path = "/Volumes/evo2T/8bitdo-firmware/firmware_downloads/Pro2 Wired for Xbox/1.7000000476837158/firmware_v1.7000000476837158.dat"
    
    if len(sys.argv) > 1:
        firmware_path = sys.argv[1]
    
    analyze_firmware(firmware_path)

if __name__ == "__main__":
    main()