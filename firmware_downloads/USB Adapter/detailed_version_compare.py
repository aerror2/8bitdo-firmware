#!/usr/bin/env python3
"""
详细比较两个几乎相同的USB Adapter固件版本
分析版本2.0399999618530273和2.049999952316284的具体差异
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

def find_differences(data1, data2):
    """找出两个数据的具体差异位置"""
    min_len = min(len(data1), len(data2))
    differences = []
    
    for i in range(min_len):
        if data1[i] != data2[i]:
            differences.append({
                'offset': i,
                'byte1': data1[i],
                'byte2': data2[i],
                'xor': data1[i] ^ data2[i]
            })
    
    # 如果长度不同，记录额外的字节
    if len(data1) != len(data2):
        longer_data = data1 if len(data1) > len(data2) else data2
        for i in range(min_len, len(longer_data)):
            differences.append({
                'offset': i,
                'byte1': data1[i] if i < len(data1) else None,
                'byte2': data2[i] if i < len(data2) else None,
                'xor': None
            })
    
    return differences

def analyze_difference_patterns(differences):
    """分析差异模式"""
    if not differences:
        return
    
    print(f"\n=== 差异模式分析 ===")
    print(f"总差异数量: {len(differences)}")
    
    # 分析差异的分布
    offsets = [d['offset'] for d in differences if d['xor'] is not None]
    if offsets:
        print(f"差异位置范围: 0x{min(offsets):08x} - 0x{max(offsets):08x}")
        
        # 检查是否有规律的间隔
        if len(offsets) > 1:
            intervals = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
            interval_counter = collections.Counter(intervals)
            common_intervals = interval_counter.most_common(5)
            print(f"常见间隔: {', '.join(f'{interval}({count})' for interval, count in common_intervals)}")
    
    # 分析XOR值
    xor_values = [d['xor'] for d in differences if d['xor'] is not None]
    if xor_values:
        xor_counter = collections.Counter(xor_values)
        common_xors = xor_counter.most_common(10)
        print(f"常见XOR值: {', '.join(f'0x{xor:02x}({count})' for xor, count in common_xors)}")
    
    # 显示前20个差异的详细信息
    print(f"\n前20个差异详情:")
    for i, diff in enumerate(differences[:20]):
        offset = diff['offset']
        if diff['xor'] is not None:
            print(f"  {i+1:2d}. 偏移 0x{offset:08x}: 0x{diff['byte1']:02x} -> 0x{diff['byte2']:02x} (XOR: 0x{diff['xor']:02x})")
        else:
            b1 = f"0x{diff['byte1']:02x}" if diff['byte1'] is not None else "--"
            b2 = f"0x{diff['byte2']:02x}" if diff['byte2'] is not None else "--"
            print(f"  {i+1:2d}. 偏移 0x{offset:08x}: {b1} -> {b2} (长度差异)")

def analyze_context_around_differences(data1, data2, differences, context_size=16):
    """分析差异周围的上下文"""
    print(f"\n=== 差异上下文分析 ===")
    
    for i, diff in enumerate(differences[:5]):  # 只分析前5个差异
        offset = diff['offset']
        start = max(0, offset - context_size)
        end = min(len(data1), offset + context_size + 1)
        
        print(f"\n差异 {i+1} (偏移 0x{offset:08x}):")
        
        # 显示版本1的上下文
        context1 = data1[start:end]
        hex1 = ' '.join(f'{b:02x}' for b in context1)
        print(f"  版本1: {hex1}")
        
        # 显示版本2的上下文
        if end <= len(data2):
            context2 = data2[start:end]
            hex2 = ' '.join(f'{b:02x}' for b in context2)
            print(f"  版本2: {hex2}")
            
            # 标记差异位置
            marker = '   ' * (offset - start) + '^^'
            print(f"  差异:   {marker}")

def check_header_differences(data1, data2):
    """检查文件头的差异"""
    print(f"\n=== 文件头分析 ===")
    
    header_size = 64
    header1 = data1[:header_size]
    header2 = data2[:header_size]
    
    print(f"版本1文件头: {header1.hex()}")
    print(f"版本2文件头: {header2.hex()}")
    
    if header1 != header2:
        print(f"文件头有差异！")
        for i in range(min(len(header1), len(header2))):
            if header1[i] != header2[i]:
                print(f"  偏移 {i:2d}: 0x{header1[i]:02x} -> 0x{header2[i]:02x}")
    else:
        print(f"文件头完全相同")

def main():
    base_dir = Path("/Volumes/evo2T/8bitdo-firmware/firmware_downloads/USB Adapter")
    
    version1 = "2.0399999618530273"
    version2 = "2.049999952316284"
    
    file1 = base_dir / version1 / f"firmware_v{version1}.dat"
    file2 = base_dir / version2 / f"firmware_v{version2}.dat"
    
    print(f"比较版本 {version1} 和 {version2}")
    print(f"文件1: {file1}")
    print(f"文件2: {file2}")
    
    data1 = load_firmware_file(file1)
    data2 = load_firmware_file(file2)
    
    if not data1 or not data2:
        print("无法加载文件")
        return 1
    
    print(f"\n=== 基本信息 ===")
    print(f"版本1大小: {len(data1)} 字节")
    print(f"版本2大小: {len(data2)} 字节")
    print(f"大小差异: {len(data2) - len(data1)} 字节")
    
    # 计算哈希值
    print(f"版本1 MD5: {hashlib.md5(data1).hexdigest()}")
    print(f"版本2 MD5: {hashlib.md5(data2).hexdigest()}")
    
    # 检查文件头
    check_header_differences(data1, data2)
    
    # 找出所有差异
    differences = find_differences(data1, data2)
    
    # 分析差异模式
    analyze_difference_patterns(differences)
    
    # 分析差异上下文
    analyze_context_around_differences(data1, data2, differences)
    
    # 如果差异很少，可能是版本号或时间戳的变化
    if len(differences) < 100:
        print(f"\n=== 可能的版本信息更新 ===")
        print(f"差异数量很少({len(differences)})，可能只是版本号或时间戳的更新")
        
        # 检查是否有ASCII字符串的变化
        for diff in differences[:10]:
            offset = diff['offset']
            if diff['byte1'] and diff['byte2']:
                if 32 <= diff['byte1'] <= 126 and 32 <= diff['byte2'] <= 126:
                    print(f"  偏移 0x{offset:08x}: '{chr(diff['byte1'])}' -> '{chr(diff['byte2'])}'")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())