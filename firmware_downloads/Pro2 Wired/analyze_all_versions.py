#!/usr/bin/env python3
"""
8BitDo Pro2 Wired 所有版本固件分析工具
分析所有版本的固件文件，寻找加密模式
"""

import os
import sys
from pathlib import Path
import hashlib
import collections

def load_firmware_file(filepath):
    """加载固件文件"""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"错误：无法读取文件 {filepath}: {e}")
        return None

def calculate_entropy(data):
    """计算数据熵值"""
    if not data:
        return 0
    
    byte_counts = collections.Counter(data)
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(data)
        if probability > 0:
            import math
            entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_firmware_file(filepath):
    """分析单个固件文件"""
    data = load_firmware_file(filepath)
    if data is None:
        return None
    
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    entropy = calculate_entropy(data)
    
    # 分析文件头
    header = data[:32].hex() if len(data) >= 32 else data.hex()
    
    # 查找字符串
    strings = []
    current_string = ""
    for byte in data[:1000]:  # 只检查前1000字节
        if 32 <= byte <= 126:  # 可打印ASCII字符
            current_string += chr(byte)
        else:
            if len(current_string) >= 4:
                strings.append(current_string)
            current_string = ""
    
    if current_string and len(current_string) >= 4:
        strings.append(current_string)
    
    return {
        'size': len(data),
        'md5': md5,
        'sha1': sha1,
        'entropy': entropy,
        'header': header,
        'strings': strings[:5],  # 只保留前5个字符串
        'data': data
    }

def compare_versions(version_data):
    """比较所有版本"""
    print(f"\n=== 版本比较分析 ===")
    
    versions = sorted(version_data.keys())
    
    # 比较相邻版本
    for i in range(len(versions) - 1):
        v1, v2 = versions[i], versions[i + 1]
        data1, data2 = version_data[v1]['data'], version_data[v2]['data']
        
        print(f"\n比较 {v1} vs {v2}:")
        
        # 计算相似度
        min_len = min(len(data1), len(data2))
        same_bytes = sum(1 for j in range(min_len) if data1[j] == data2[j])
        similarity = (same_bytes / min_len) * 100
        
        print(f"  大小: {len(data1)} vs {len(data2)} 字节")
        print(f"  相似度: {similarity:.2f}%")
        
        # XOR分析
        xor_values = [data1[j] ^ data2[j] for j in range(min_len)]
        xor_counter = collections.Counter(xor_values)
        most_common = xor_counter.most_common(3)
        
        print(f"  最常见XOR值: {', '.join(f'0x{x[0]:02x}({x[1]})' for x in most_common)}")
        
        # 检查是否有固定XOR模式
        if most_common[0][1] > min_len * 0.8:  # 如果最常见的XOR值占80%以上
            xor_key = most_common[0][0]
            print(f"  *** 可能的固定XOR密钥: 0x{xor_key:02x} ***")
            
            # 尝试解密
            decrypted = bytes(b ^ xor_key for b in data1)
            dec_entropy = calculate_entropy(decrypted)
            print(f"  解密后熵值: {dec_entropy:.2f} (原始: {version_data[v1]['entropy']:.2f})")
            
            if dec_entropy < version_data[v1]['entropy'] * 0.8:  # 熵值显著降低
                print(f"  *** 解密可能成功！熵值显著降低 ***")
                
                # 保存解密结果
                output_dir = Path(f"/Volumes/evo2T/8bitdo-firmware/firmware_downloads/Pro2 Wired/{v1}")
                output_file = output_dir / f"decrypted_with_key_{xor_key:02x}.bin"
                with open(output_file, 'wb') as f:
                    f.write(decrypted)
                print(f"  解密结果已保存到: {output_file}")
                
                # 分析解密后的数据
                print(f"  解密后文件头: {decrypted[:32].hex()}")
                
                # 检查文件签名
                signatures = {
                    b'\x7fELF': 'ELF executable',
                    b'\x1f\x8b': 'GZIP compressed',
                    b'PK': 'ZIP archive',
                    b'\x42\x5a': 'BZIP2 compressed',
                    b'\xfd7zXZ': 'XZ compressed',
                    b'\x04"M\x18': 'LZ4 compressed',
                    b'(\xb5/\xfd': 'Zstandard compressed'
                }
                
                for sig, desc in signatures.items():
                    if decrypted.startswith(sig):
                        print(f"  *** 检测到文件类型: {desc} ***")
                        break

def analyze_header_patterns(version_data):
    """分析文件头模式"""
    print(f"\n=== 文件头模式分析 ===")
    
    for version, data in version_data.items():
        print(f"\n版本 {version}:")
        print(f"  文件头: {data['header']}")
        print(f"  大小: {data['size']} 字节")
        print(f"  熵值: {data['entropy']:.2f}")
        
        if data['strings']:
            print(f"  字符串: {', '.join(data['strings'])}")

def main():
    # 固件文件目录
    base_dir = Path("/Volumes/evo2T/8bitdo-firmware/firmware_downloads/Pro2 Wired")
    
    # 获取所有版本
    versions = []
    for item in base_dir.iterdir():
        if item.is_dir() and item.name.startswith('1.'):
            versions.append(item.name)
    
    versions.sort()
    print(f"发现 {len(versions)} 个版本: {', '.join(versions)}")
    
    # 分析每个版本
    version_data = {}
    for version in versions:
        firmware_file = base_dir / version / f"firmware_v{version}.dat"
        if firmware_file.exists():
            print(f"\n分析版本 {version}...")
            data = analyze_firmware_file(firmware_file)
            if data:
                version_data[version] = data
                print(f"  大小: {data['size']} 字节")
                print(f"  MD5: {data['md5']}")
                print(f"  熵值: {data['entropy']:.2f}")
    
    if len(version_data) < 2:
        print("需要至少2个版本进行比较")
        return 1
    
    # 分析文件头模式
    analyze_header_patterns(version_data)
    
    # 比较版本
    compare_versions(version_data)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())