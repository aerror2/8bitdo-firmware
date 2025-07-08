#!/usr/bin/env python3
"""
8BitDo Pro2 Wired 固件XOR模式分析工具
分析两个版本间是否存在简单的XOR加密模式
"""

import os
import sys
from pathlib import Path
import collections

def load_firmware_file(filepath):
    """加载固件文件"""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"错误：无法读取文件 {filepath}: {e}")
        return None

def analyze_xor_patterns(data1, data2):
    """分析XOR模式"""
    print(f"\n=== XOR模式分析 ===")
    
    min_len = min(len(data1), len(data2))
    xor_values = []
    
    # 计算每个位置的XOR值
    for i in range(min_len):
        xor_val = data1[i] ^ data2[i]
        xor_values.append(xor_val)
    
    # 统计XOR值的分布
    xor_counter = collections.Counter(xor_values)
    print(f"XOR值统计 (前20个最常见):")
    for xor_val, count in xor_counter.most_common(20):
        percentage = (count / len(xor_values)) * 100
        print(f"  0x{xor_val:02x}: {count} 次 ({percentage:.2f}%)")
    
    # 检查是否有固定的XOR模式
    most_common_xor = xor_counter.most_common(1)[0]
    print(f"\n最常见的XOR值: 0x{most_common_xor[0]:02x} (出现 {most_common_xor[1]} 次, {(most_common_xor[1]/len(xor_values)*100):.2f}%)")
    
    # 检查XOR模式的周期性
    print(f"\n=== 周期性分析 ===")
    for period in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
        if period > len(xor_values):
            break
            
        # 检查是否存在周期性模式
        is_periodic = True
        pattern = xor_values[:period]
        
        for i in range(period, min(len(xor_values), period * 10)):
            if xor_values[i] != pattern[i % period]:
                is_periodic = False
                break
        
        if is_periodic:
            print(f"发现周期为 {period} 的XOR模式:")
            print(f"  模式: {' '.join(f'{x:02x}' for x in pattern)}")
            
            # 验证整个文件
            full_match = True
            for i in range(len(xor_values)):
                if xor_values[i] != pattern[i % period]:
                    full_match = False
                    break
            
            if full_match:
                print(f"  ✓ 整个文件都符合此模式")
                return pattern
            else:
                print(f"  ✗ 只有部分符合此模式")
    
    # 检查递增/递减模式
    print(f"\n=== 递增/递减模式分析 ===")
    
    # 检查是否为简单递增
    is_incrementing = True
    start_val = xor_values[0]
    for i, xor_val in enumerate(xor_values[:1000]):  # 检查前1000个
        expected = (start_val + i) & 0xFF
        if xor_val != expected:
            is_incrementing = False
            break
    
    if is_incrementing:
        print(f"发现递增XOR模式: 起始值 0x{start_val:02x}")
        return "incrementing"
    
    # 检查基于位置的XOR
    print(f"\n=== 基于位置的XOR分析 ===")
    
    # 检查XOR值是否与位置相关
    position_correlations = []
    for i in range(min(1000, len(xor_values))):
        pos_xor = i & 0xFF
        if xor_values[i] == pos_xor:
            position_correlations.append(i)
    
    if len(position_correlations) > 100:
        print(f"发现基于位置的XOR模式: {len(position_correlations)} 个位置匹配")
        return "position_based"
    
    return None

def test_xor_decryption(data, pattern):
    """测试XOR解密"""
    if pattern == "incrementing":
        # 递增模式
        decrypted = bytearray()
        for i, byte in enumerate(data):
            decrypted.append(byte ^ (i & 0xFF))
        return bytes(decrypted)
    
    elif pattern == "position_based":
        # 基于位置的模式
        decrypted = bytearray()
        for i, byte in enumerate(data):
            decrypted.append(byte ^ (i & 0xFF))
        return bytes(decrypted)
    
    elif isinstance(pattern, list):
        # 周期性模式
        decrypted = bytearray()
        for i, byte in enumerate(data):
            xor_key = pattern[i % len(pattern)]
            decrypted.append(byte ^ xor_key)
        return bytes(decrypted)
    
    return None

def analyze_decrypted_data(data):
    """分析解密后的数据"""
    print(f"\n=== 解密数据分析 ===")
    print(f"数据大小: {len(data)} 字节")
    
    # 计算熵值
    byte_counts = collections.Counter(data)
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(data)
        if probability > 0:
            entropy -= probability * (probability.bit_length() - 1)
    
    print(f"熵值: {entropy:.2f}")
    
    # 检查文件头
    print(f"文件头 (前32字节): {data[:32].hex()}")
    
    # 查找可打印字符串
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
    
    if strings:
        print(f"\n发现的字符串 (前10个):")
        for i, s in enumerate(strings[:10]):
            print(f"  {i+1}: {s}")
    
    # 检查常见文件签名
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
        if data.startswith(sig):
            print(f"\n检测到文件类型: {desc}")
            break

def main():
    # 固件文件路径
    base_dir = Path("/Volumes/evo2T/8bitdo-firmware/firmware_downloads/Pro2 Wired")
    
    version1 = "1.0199999809265137"
    version2 = "1.0299999713897705"
    
    file1 = base_dir / version1 / f"firmware_v{version1}.dat"
    file2 = base_dir / version2 / f"firmware_v{version2}.dat"
    
    print(f"分析固件版本的XOR模式:")
    print(f"版本1: {version1}")
    print(f"版本2: {version2}")
    
    # 加载固件文件
    data1 = load_firmware_file(file1)
    data2 = load_firmware_file(file2)
    
    if data1 is None or data2 is None:
        return 1
    
    # 分析XOR模式
    pattern = analyze_xor_patterns(data1, data2)
    
    if pattern:
        print(f"\n=== 尝试解密 ===")
        
        # 尝试解密第一个文件
        decrypted1 = test_xor_decryption(data1, pattern)
        if decrypted1:
            print(f"\n解密版本1:")
            analyze_decrypted_data(decrypted1)
            
            # 保存解密结果
            output_file1 = base_dir / version1 / f"decrypted_v{version1}.bin"
            with open(output_file1, 'wb') as f:
                f.write(decrypted1)
            print(f"解密结果已保存到: {output_file1}")
        
        # 尝试解密第二个文件
        decrypted2 = test_xor_decryption(data2, pattern)
        if decrypted2:
            print(f"\n解密版本2:")
            analyze_decrypted_data(decrypted2)
            
            # 保存解密结果
            output_file2 = base_dir / version2 / f"decrypted_v{version2}.bin"
            with open(output_file2, 'wb') as f:
                f.write(decrypted2)
            print(f"解密结果已保存到: {output_file2}")
    
    else:
        print(f"\n未发现明显的XOR加密模式")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())