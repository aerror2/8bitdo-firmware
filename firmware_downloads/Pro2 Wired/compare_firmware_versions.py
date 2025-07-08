#!/usr/bin/env python3
"""
8BitDo Pro2 Wired 固件版本比较工具
比较相邻版本的固件文件，分析差异模式
"""

import os
import sys
from pathlib import Path
import hashlib

def load_firmware_file(filepath):
    """加载固件文件"""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"错误：无法读取文件 {filepath}: {e}")
        return None

def calculate_hash(data):
    """计算文件哈希值"""
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    return md5, sha1

def find_common_sequences(data1, data2, min_length=16):
    """查找两个数据中的公共序列"""
    common_sequences = []
    
    # 使用滑动窗口查找公共序列
    for i in range(len(data1) - min_length + 1):
        sequence = data1[i:i + min_length]
        if sequence in data2:
            # 扩展序列长度
            start1, start2 = i, data2.find(sequence)
            length = min_length
            
            # 向前扩展
            while (start1 + length < len(data1) and 
                   start2 + length < len(data2) and 
                   data1[start1 + length] == data2[start2 + length]):
                length += 1
            
            # 向后扩展
            while (start1 > 0 and start2 > 0 and 
                   data1[start1 - 1] == data2[start2 - 1]):
                start1 -= 1
                start2 -= 1
                length += 1
            
            common_sequences.append({
                'offset1': start1,
                'offset2': start2,
                'length': length,
                'data': data1[start1:start1 + length]
            })
    
    # 去重并按长度排序
    unique_sequences = []
    for seq in common_sequences:
        is_duplicate = False
        for existing in unique_sequences:
            if (abs(seq['offset1'] - existing['offset1']) < 10 and 
                abs(seq['offset2'] - existing['offset2']) < 10):
                is_duplicate = True
                break
        if not is_duplicate:
            unique_sequences.append(seq)
    
    return sorted(unique_sequences, key=lambda x: x['length'], reverse=True)

def analyze_differences(data1, data2):
    """分析两个固件的差异"""
    print(f"\n=== 固件差异分析 ===")
    print(f"文件1大小: {len(data1)} 字节")
    print(f"文件2大小: {len(data2)} 字节")
    print(f"大小差异: {len(data2) - len(data1)} 字节")
    
    # 计算相同字节的数量
    min_len = min(len(data1), len(data2))
    same_bytes = sum(1 for i in range(min_len) if data1[i] == data2[i])
    similarity = (same_bytes / min_len) * 100
    
    print(f"前 {min_len} 字节中相同字节: {same_bytes} ({similarity:.2f}%)")
    
    # 查找差异位置
    diff_positions = []
    for i in range(min_len):
        if data1[i] != data2[i]:
            diff_positions.append(i)
    
    print(f"差异位置数量: {len(diff_positions)}")
    
    if diff_positions:
        print(f"前10个差异位置:")
        for i, pos in enumerate(diff_positions[:10]):
            print(f"  位置 {pos:06x}: {data1[pos]:02x} -> {data2[pos]:02x}")
    
    return diff_positions

def analyze_patterns(data1, data2, diff_positions):
    """分析差异模式"""
    print(f"\n=== 差异模式分析 ===")
    
    if not diff_positions:
        print("没有发现差异")
        return
    
    # 分析差异的分布
    clusters = []
    current_cluster = [diff_positions[0]]
    
    for i in range(1, len(diff_positions)):
        if diff_positions[i] - diff_positions[i-1] <= 16:  # 16字节内认为是同一簇
            current_cluster.append(diff_positions[i])
        else:
            clusters.append(current_cluster)
            current_cluster = [diff_positions[i]]
    clusters.append(current_cluster)
    
    print(f"差异簇数量: {len(clusters)}")
    print(f"前5个差异簇:")
    for i, cluster in enumerate(clusters[:5]):
        start, end = cluster[0], cluster[-1]
        print(f"  簇 {i+1}: 位置 {start:06x}-{end:06x} ({len(cluster)} 个差异)")
        
        # 显示簇中的数据
        if end - start <= 32:  # 只显示小簇的详细信息
            print(f"    文件1: {data1[start:end+1].hex()}")
            print(f"    文件2: {data2[start:end+1].hex()}")

def main():
    # 固件文件路径
    base_dir = Path("/Volumes/evo2T/8bitdo-firmware/firmware_downloads/Pro2 Wired")
    
    version1 = "1.0199999809265137"
    version2 = "1.0299999713897705"
    
    file1 = base_dir / version1 / f"firmware_v{version1}.dat"
    file2 = base_dir / version2 / f"firmware_v{version2}.dat"
    
    print(f"比较固件版本:")
    print(f"版本1: {version1}")
    print(f"版本2: {version2}")
    
    # 加载固件文件
    data1 = load_firmware_file(file1)
    data2 = load_firmware_file(file2)
    
    if data1 is None or data2 is None:
        return 1
    
    # 计算哈希值
    md5_1, sha1_1 = calculate_hash(data1)
    md5_2, sha1_2 = calculate_hash(data2)
    
    print(f"\n=== 文件信息 ===")
    print(f"文件1 MD5: {md5_1}")
    print(f"文件1 SHA1: {sha1_1}")
    print(f"文件2 MD5: {md5_2}")
    print(f"文件2 SHA1: {sha1_2}")
    
    if md5_1 == md5_2:
        print("文件完全相同！")
        return 0
    
    # 分析差异
    diff_positions = analyze_differences(data1, data2)
    
    # 分析差异模式
    analyze_patterns(data1, data2, diff_positions)
    
    # 查找公共序列
    print(f"\n=== 公共序列分析 ===")
    common_sequences = find_common_sequences(data1, data2, min_length=32)
    
    print(f"找到 {len(common_sequences)} 个公共序列 (>= 32字节)")
    
    total_common_bytes = sum(seq['length'] for seq in common_sequences)
    print(f"公共序列总长度: {total_common_bytes} 字节")
    
    if common_sequences:
        print(f"前5个最长公共序列:")
        for i, seq in enumerate(common_sequences[:5]):
            print(f"  序列 {i+1}: 长度 {seq['length']} 字节")
            print(f"    文件1位置: 0x{seq['offset1']:06x}")
            print(f"    文件2位置: 0x{seq['offset2']:06x}")
            print(f"    数据预览: {seq['data'][:16].hex()}...")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())