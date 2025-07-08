#!/usr/bin/env python3
"""
8BitDo USB Adapter 固件版本分析工具
重点分析相邻版本的差异模式，寻找简单加密
"""

import os
import sys
from pathlib import Path
import hashlib
import collections
import math

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
            entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_xor_pattern(data1, data2):
    """分析两个数据的XOR模式"""
    min_len = min(len(data1), len(data2))
    if min_len == 0:
        return None
    
    xor_values = [data1[i] ^ data2[i] for i in range(min_len)]
    xor_counter = collections.Counter(xor_values)
    
    # 检查是否有单一XOR密钥
    most_common = xor_counter.most_common(1)[0]
    if most_common[1] > min_len * 0.8:  # 80%以上相同XOR值
        return {
            'type': 'single_key',
            'key': most_common[0],
            'confidence': most_common[1] / min_len,
            'xor_distribution': xor_counter.most_common(10)
        }
    
    # 检查周期性XOR模式
    for period in [2, 4, 8, 16, 32, 64, 128, 256]:
        if period > min_len // 4:
            break
        
        pattern_matches = 0
        for i in range(period, min_len):
            if xor_values[i] == xor_values[i % period]:
                pattern_matches += 1
        
        confidence = pattern_matches / (min_len - period)
        if confidence > 0.8:
            pattern = xor_values[:period]
            return {
                'type': 'periodic',
                'period': period,
                'pattern': pattern,
                'confidence': confidence,
                'xor_distribution': xor_counter.most_common(10)
            }
    
    # 检查递增XOR模式
    incremental_matches = 0
    for i in range(1, min(min_len, 1000)):
        expected = (xor_values[0] + i) & 0xFF
        if xor_values[i] == expected:
            incremental_matches += 1
    
    if incremental_matches > min(min_len, 1000) * 0.8:
        return {
            'type': 'incremental',
            'start_key': xor_values[0],
            'confidence': incremental_matches / min(min_len, 1000),
            'xor_distribution': xor_counter.most_common(10)
        }
    
    return {
        'type': 'complex',
        'xor_distribution': xor_counter.most_common(10)
    }

def try_decrypt_with_pattern(data, pattern_info):
    """根据检测到的模式尝试解密"""
    if pattern_info['type'] == 'single_key':
        key = pattern_info['key']
        decrypted = bytes(b ^ key for b in data)
        return decrypted, f"single_key_{key:02x}"
    
    elif pattern_info['type'] == 'periodic':
        pattern = pattern_info['pattern']
        period = pattern_info['period']
        decrypted = bytes(data[i] ^ pattern[i % period] for i in range(len(data)))
        pattern_hex = ''.join(f'{b:02x}' for b in pattern)
        return decrypted, f"periodic_{period}_{pattern_hex}"
    
    elif pattern_info['type'] == 'incremental':
        start_key = pattern_info['start_key']
        decrypted = bytes(data[i] ^ ((start_key + i) & 0xFF) for i in range(len(data)))
        return decrypted, f"incremental_{start_key:02x}"
    
    return None, None

def check_file_signatures(data):
    """检查文件签名"""
    signatures = {
        b'\x7fELF': 'ELF executable',
        b'\x1f\x8b': 'GZIP compressed',
        b'PK': 'ZIP archive',
        b'\x42\x5a': 'BZIP2 compressed',
        b'\xfd7zXZ': 'XZ compressed',
        b'\x04"M\x18': 'LZ4 compressed',
        b'(\xb5/\xfd': 'Zstandard compressed',
        b'\x89PNG': 'PNG image',
        b'\xff\xd8\xff': 'JPEG image',
        b'BM': 'BMP image',
        b'RIFF': 'RIFF container',
        b'\x00\x00\x01\x00': 'ICO image'
    }
    
    detected = []
    for sig, desc in signatures.items():
        if data.startswith(sig):
            detected.append(desc)
    
    return detected

def extract_strings(data, min_length=4, max_strings=10):
    """提取可打印字符串"""
    strings = []
    current_string = ""
    
    for byte in data[:2000]:  # 只检查前2000字节
        if 32 <= byte <= 126:  # 可打印ASCII字符
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
                if len(strings) >= max_strings:
                    break
            current_string = ""
    
    if current_string and len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings[:max_strings]

def analyze_version_pair(version1, version2, base_dir):
    """分析两个相邻版本"""
    file1 = base_dir / version1 / f"firmware_v{version1}.dat"
    file2 = base_dir / version2 / f"firmware_v{version2}.dat"
    
    if not file1.exists() or not file2.exists():
        return None
    
    data1 = load_firmware_file(file1)
    data2 = load_firmware_file(file2)
    
    if not data1 or not data2:
        return None
    
    print(f"\n=== 分析 {version1} vs {version2} ===")
    print(f"文件大小: {len(data1)} vs {len(data2)} 字节")
    
    # 计算相似度
    min_len = min(len(data1), len(data2))
    same_bytes = sum(1 for i in range(min_len) if data1[i] == data2[i])
    similarity = (same_bytes / min_len) * 100
    print(f"相似度: {similarity:.2f}%")
    
    # 分析XOR模式
    pattern_info = analyze_xor_pattern(data1, data2)
    if pattern_info:
        print(f"XOR模式类型: {pattern_info['type']}")
        
        if pattern_info['type'] == 'single_key':
            print(f"*** 发现单一XOR密钥: 0x{pattern_info['key']:02x} (置信度: {pattern_info['confidence']:.2f}) ***")
            
            # 尝试解密
            decrypted, method = try_decrypt_with_pattern(data1, pattern_info)
            if decrypted:
                dec_entropy = calculate_entropy(decrypted)
                orig_entropy = calculate_entropy(data1)
                print(f"解密后熵值: {dec_entropy:.2f} (原始: {orig_entropy:.2f})")
                
                if dec_entropy < orig_entropy * 0.9:  # 熵值降低
                    print(f"*** 解密可能成功！熵值降低 ***")
                    
                    # 保存解密结果
                    output_dir = base_dir / version1
                    output_file = output_dir / f"decrypted_{method}.bin"
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    print(f"解密结果已保存: {output_file}")
                    
                    # 分析解密后的数据
                    signatures = check_file_signatures(decrypted)
                    if signatures:
                        print(f"检测到文件类型: {', '.join(signatures)}")
                    
                    strings = extract_strings(decrypted)
                    if strings:
                        print(f"发现字符串: {', '.join(strings[:3])}")
                    
                    print(f"解密后文件头: {decrypted[:32].hex()}")
        
        elif pattern_info['type'] == 'periodic':
            print(f"*** 发现周期性XOR模式: 周期={pattern_info['period']}, 置信度={pattern_info['confidence']:.2f} ***")
            pattern_hex = ''.join(f'{b:02x}' for b in pattern_info['pattern'])
            print(f"XOR模式: {pattern_hex}")
            
            # 尝试解密
            decrypted, method = try_decrypt_with_pattern(data1, pattern_info)
            if decrypted:
                dec_entropy = calculate_entropy(decrypted)
                orig_entropy = calculate_entropy(data1)
                print(f"解密后熵值: {dec_entropy:.2f} (原始: {orig_entropy:.2f})")
                
                if dec_entropy < orig_entropy * 0.9:
                    print(f"*** 解密可能成功！熵值降低 ***")
                    
                    output_dir = base_dir / version1
                    output_file = output_dir / f"decrypted_{method}.bin"
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    print(f"解密结果已保存: {output_file}")
                    
                    signatures = check_file_signatures(decrypted)
                    if signatures:
                        print(f"检测到文件类型: {', '.join(signatures)}")
                    
                    strings = extract_strings(decrypted)
                    if strings:
                        print(f"发现字符串: {', '.join(strings[:3])}")
        
        elif pattern_info['type'] == 'incremental':
            print(f"*** 发现递增XOR模式: 起始密钥=0x{pattern_info['start_key']:02x}, 置信度={pattern_info['confidence']:.2f} ***")
            
            # 尝试解密
            decrypted, method = try_decrypt_with_pattern(data1, pattern_info)
            if decrypted:
                dec_entropy = calculate_entropy(decrypted)
                orig_entropy = calculate_entropy(data1)
                print(f"解密后熵值: {dec_entropy:.2f} (原始: {orig_entropy:.2f})")
                
                if dec_entropy < orig_entropy * 0.9:
                    print(f"*** 解密可能成功！熵值降低 ***")
                    
                    output_dir = base_dir / version1
                    output_file = output_dir / f"decrypted_{method}.bin"
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    print(f"解密结果已保存: {output_file}")
                    
                    signatures = check_file_signatures(decrypted)
                    if signatures:
                        print(f"检测到文件类型: {', '.join(signatures)}")
        
        # 显示XOR值分布
        print(f"XOR值分布 (前5个): {', '.join(f'0x{x[0]:02x}({x[1]})' for x in pattern_info['xor_distribution'][:5])}")
    
    return pattern_info

def main():
    base_dir = Path("/Volumes/evo2T/8bitdo-firmware/firmware_downloads/USB Adapter")
    
    # 获取所有版本
    versions = []
    for item in base_dir.iterdir():
        if item.is_dir() and (item.name.startswith('1.') or item.name.startswith('2.')):
            versions.append(item.name)
    
    # 按版本号排序
    def version_key(v):
        try:
            return float(v)
        except:
            return 0
    
    versions.sort(key=version_key)
    print(f"发现 {len(versions)} 个版本: {', '.join(versions)}")
    
    # 重点分析2.x系列的相邻版本
    v2_versions = [v for v in versions if v.startswith('2.')]
    print(f"\n2.x系列版本: {', '.join(v2_versions)}")
    
    successful_decryptions = []
    
    # 分析相邻版本
    for i in range(len(v2_versions) - 1):
        result = analyze_version_pair(v2_versions[i], v2_versions[i + 1], base_dir)
        if result and result['type'] in ['single_key', 'periodic', 'incremental']:
            successful_decryptions.append((v2_versions[i], v2_versions[i + 1], result))
    
    # 也分析一些1.x版本
    v1_versions = [v for v in versions if v.startswith('1.')]
    if len(v1_versions) >= 2:
        print(f"\n分析1.x系列最后两个版本...")
        analyze_version_pair(v1_versions[-2], v1_versions[-1], base_dir)
    
    # 总结
    if successful_decryptions:
        print(f"\n=== 成功解密总结 ===")
        for v1, v2, result in successful_decryptions:
            print(f"{v1} vs {v2}: {result['type']} 模式")
    else:
        print(f"\n未发现明显的简单加密模式")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())