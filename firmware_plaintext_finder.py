#!/usr/bin/env python3
"""
8BitDo固件明文查找器
尝试通过多种方法找到固件中的明文数据
"""

import os
import sys
import struct
import zlib
import gzip
import bz2
import lzma
from collections import Counter
import re

def calculate_entropy(data):
    """计算数据的熵值"""
    if not data:
        return 0
    
    import math
    counter = Counter(data)
    length = len(data)
    entropy = 0
    
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def is_printable_text(data, min_ratio=0.7):
    """检查数据是否包含足够的可打印字符"""
    if not data:
        return False
    
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
    ratio = printable_count / len(data)
    return ratio >= min_ratio

def find_strings(data, min_length=4):
    """查找数据中的字符串"""
    strings = []
    current_string = b''
    
    for byte in data:
        if 32 <= byte <= 126:  # 可打印ASCII字符
            current_string += bytes([byte])
        else:
            if len(current_string) >= min_length:
                strings.append(current_string.decode('ascii', errors='ignore'))
            current_string = b''
    
    if len(current_string) >= min_length:
        strings.append(current_string.decode('ascii', errors='ignore'))
    
    return strings

def analyze_firmware_structure(data):
    """分析固件结构"""
    results = []
    
    # 检查常见的固件魔术字节
    magic_patterns = {
        b'\x7fELF': 'ELF executable',
        b'\x89PNG': 'PNG image',
        b'\xff\xd8\xff': 'JPEG image',
        b'PK\x03\x04': 'ZIP archive',
        b'\x1f\x8b': 'GZIP compressed',
        b'BZ': 'BZIP2 compressed',
        b'\xfd7zXZ': 'XZ compressed',
        b'LZMA': 'LZMA compressed',
        b'\x00\x00\x01\x00': 'Windows icon',
        b'MZ': 'DOS/Windows executable',
        b'\xca\xfe\xba\xbe': 'Java class file',
        b'\xfe\xed\xfa': 'Mach-O binary',
        b'\xcf\xfa\xed\xfe': 'Mach-O binary (reverse)',
    }
    
    for pattern, description in magic_patterns.items():
        if data.startswith(pattern):
            results.append(f"发现魔术字节: {description}")
            break
    
    # 分析数据段
    chunk_size = 1024
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        entropy = calculate_entropy(chunk)
        
        if entropy < 3.0:  # 低熵值可能是明文或重复数据
            strings = find_strings(chunk)
            if strings:
                results.append(f"偏移 {i:06x}: 低熵值 {entropy:.2f}, 发现字符串: {strings[:5]}")
        elif 3.0 <= entropy <= 6.0:  # 中等熵值可能是明文
            if is_printable_text(chunk, 0.3):
                strings = find_strings(chunk)
                if strings:
                    results.append(f"偏移 {i:06x}: 中等熵值 {entropy:.2f}, 可能的明文: {strings[:3]}")
    
    return results

def try_decompress_methods(data):
    """尝试各种解压方法"""
    methods = {
        'zlib': lambda d: zlib.decompress(d),
        'gzip': lambda d: gzip.decompress(d),
        'bzip2': lambda d: bz2.decompress(d),
        'lzma': lambda d: lzma.decompress(d),
    }
    
    results = []
    
    for name, method in methods.items():
        try:
            decompressed = method(data)
            entropy = calculate_entropy(decompressed)
            strings = find_strings(decompressed)
            
            results.append({
                'method': name,
                'size': len(decompressed),
                'entropy': entropy,
                'strings': strings[:10],
                'data': decompressed
            })
            
        except Exception as e:
            continue
    
    return results

def try_skip_header(data, max_skip=512):
    """尝试跳过不同大小的头部"""
    results = []
    
    for skip in [0, 4, 8, 16, 32, 64, 128, 256, 512]:
        if skip >= len(data):
            continue
            
        payload = data[skip:]
        entropy = calculate_entropy(payload)
        
        # 尝试解压跳过头部后的数据
        decomp_results = try_decompress_methods(payload)
        
        if decomp_results:
            for result in decomp_results:
                results.append({
                    'skip_bytes': skip,
                    'method': result['method'],
                    'size': result['size'],
                    'entropy': result['entropy'],
                    'strings': result['strings']
                })
        
        # 检查原始数据
        if entropy < 6.0:
            strings = find_strings(payload)
            if strings:
                results.append({
                    'skip_bytes': skip,
                    'method': 'raw',
                    'size': len(payload),
                    'entropy': entropy,
                    'strings': strings[:10]
                })
    
    return results

def main():
    if len(sys.argv) != 2:
        print("用法: python3 firmware_plaintext_finder.py <固件文件>")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    
    if not os.path.exists(firmware_path):
        print(f"错误: 文件 {firmware_path} 不存在")
        sys.exit(1)
    
    print(f"分析固件文件: {firmware_path}")
    print("=" * 60)
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    print(f"文件大小: {len(data)} bytes")
    print(f"整体熵值: {calculate_entropy(data):.2f}")
    print()
    
    # 分析固件结构
    print("=== 固件结构分析 ===")
    structure_results = analyze_firmware_structure(data)
    for result in structure_results:
        print(result)
    print()
    
    # 尝试直接解压
    print("=== 直接解压尝试 ===")
    decomp_results = try_decompress_methods(data)
    for result in decomp_results:
        print(f"{result['method']}: 大小={result['size']}, 熵值={result['entropy']:.2f}")
        if result['strings']:
            print(f"  字符串: {result['strings'][:5]}")
    print()
    
    # 尝试跳过头部
    print("=== 跳过头部分析 ===")
    skip_results = try_skip_header(data)
    
    # 按熵值排序，优先显示低熵值结果
    skip_results.sort(key=lambda x: x['entropy'])
    
    for result in skip_results[:10]:  # 只显示前10个最有希望的结果
        print(f"跳过 {result['skip_bytes']} 字节, {result['method']}: ")
        print(f"  大小={result['size']}, 熵值={result['entropy']:.2f}")
        if result['strings']:
            print(f"  字符串: {result['strings'][:3]}")
        print()
    
    # 保存最有希望的结果
    output_dir = os.path.dirname(firmware_path)
    plaintext_dir = os.path.join(output_dir, 'plaintext_candidates')
    os.makedirs(plaintext_dir, exist_ok=True)
    
    saved_count = 0
    for i, result in enumerate(skip_results[:5]):
        if result['entropy'] < 6.0 and result['strings']:
            filename = f"candidate_{i:02d}_skip{result['skip_bytes']}_{result['method']}.bin"
            filepath = os.path.join(plaintext_dir, filename)
            
            # 重新生成数据
            if result['method'] == 'raw':
                candidate_data = data[result['skip_bytes']:]
            else:
                try:
                    payload = data[result['skip_bytes']:]
                    if result['method'] == 'zlib':
                        candidate_data = zlib.decompress(payload)
                    elif result['method'] == 'gzip':
                        candidate_data = gzip.decompress(payload)
                    elif result['method'] == 'bzip2':
                        candidate_data = bz2.decompress(payload)
                    elif result['method'] == 'lzma':
                        candidate_data = lzma.decompress(payload)
                    else:
                        continue
                except:
                    continue
            
            with open(filepath, 'wb') as f:
                f.write(candidate_data)
            
            print(f"保存候选明文: {filepath}")
            saved_count += 1
    
    print(f"\n分析完成! 保存了 {saved_count} 个候选明文文件到 {plaintext_dir}")

if __name__ == '__main__':
    main()