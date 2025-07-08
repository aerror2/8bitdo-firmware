#!/usr/bin/env python3
"""
8BitDo固件高级解析器
基于fwupd ebitdo插件的逆向工程
"""

import os
import sys
import struct
import hashlib
import binascii
from collections import Counter
import math

def calculate_entropy(data):
    """计算数据的熵值"""
    if not data:
        return 0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0
    
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def find_repeating_patterns(data, min_length=4, max_length=32):
    """查找重复模式"""
    patterns = {}
    
    for length in range(min_length, min_length + max_length):
        for i in range(len(data) - length):
            pattern = data[i:i+length]
            if pattern in patterns:
                patterns[pattern].append(i)
            else:
                patterns[pattern] = [i]
    
    # 只返回出现多次的模式
    repeated = {k: v for k, v in patterns.items() if len(v) > 1}
    return repeated

def analyze_header_candidates(data, max_header_size=512):
    """分析可能的头部结构"""
    results = []
    
    for header_size in [4, 8, 12, 16, 20, 24, 28, 32, 48, 64, 128, 256, 512]:
        if header_size > len(data):
            continue
            
        header = data[:header_size]
        payload = data[header_size:]
        
        # 分析头部
        header_info = {
            'size': header_size,
            'hex': binascii.hexlify(header).decode(),
            'entropy': calculate_entropy(header),
            'payload_size': len(payload),
            'payload_entropy': calculate_entropy(payload),
        }
        
        # 检查头部中的可能字段
        if header_size >= 4:
            # 尝试解释为长度字段
            length_le = struct.unpack('<I', header[:4])[0]
            length_be = struct.unpack('>I', header[:4])[0]
            
            header_info['possible_length_le'] = length_le
            header_info['possible_length_be'] = length_be
            
            # 检查长度字段是否合理
            if length_le == len(payload) or length_le == len(data) - header_size:
                header_info['length_match_le'] = True
            if length_be == len(payload) or length_be == len(data) - header_size:
                header_info['length_match_be'] = True
        
        if header_size >= 8:
            # 检查可能的校验和
            checksum_candidates = []
            for i in range(0, header_size - 4, 4):
                checksum = struct.unpack('<I', header[i:i+4])[0]
                checksum_candidates.append(checksum)
            header_info['checksum_candidates'] = checksum_candidates
        
        results.append(header_info)
    
    return results

def try_simple_ciphers(data, key_length=1):
    """尝试简单的密码"""
    results = []
    
    # XOR with single byte
    for key in range(256):
        decrypted = bytes(b ^ key for b in data)
        entropy = calculate_entropy(decrypted)
        
        if entropy < 7.5:  # 可能的明文
            results.append({
                'method': f'XOR_{key:02x}',
                'entropy': entropy,
                'data': decrypted,
                'preview': binascii.hexlify(decrypted[:32]).decode()
            })
    
    return sorted(results, key=lambda x: x['entropy'])

def try_multi_byte_xor(data, max_key_length=16):
    """尝试多字节XOR"""
    results = []
    
    # 常见的多字节密钥
    common_keys = [
        b'8BitDo',
        b'8bitdo',
        b'EBITDO',
        b'ebitdo',
        b'firmware',
        b'FIRMWARE',
        b'\x00\x01\x02\x03',
        b'\xff\xfe\xfd\xfc',
        b'\x55\xaa',
        b'\xaa\x55',
    ]
    
    for key in common_keys:
        decrypted = bytearray()
        for i, byte in enumerate(data):
            decrypted.append(byte ^ key[i % len(key)])
        
        decrypted = bytes(decrypted)
        entropy = calculate_entropy(decrypted)
        
        if entropy < 7.5:
            results.append({
                'method': f'XOR_multi_{binascii.hexlify(key).decode()}',
                'entropy': entropy,
                'data': decrypted,
                'preview': binascii.hexlify(decrypted[:32]).decode()
            })
    
    return sorted(results, key=lambda x: x['entropy'])

def analyze_block_structure(data, block_sizes=[16, 32, 64, 128, 256, 512, 1024]):
    """分析块结构"""
    results = []
    
    for block_size in block_sizes:
        if len(data) < block_size * 2:
            continue
            
        blocks = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if len(block) == block_size:
                blocks.append(block)
        
        if len(blocks) < 2:
            continue
            
        # 分析块的相似性
        unique_blocks = set(blocks)
        similarity_ratio = len(unique_blocks) / len(blocks)
        
        # 计算每个块的熵值
        block_entropies = [calculate_entropy(block) for block in blocks]
        avg_entropy = sum(block_entropies) / len(block_entropies)
        
        results.append({
            'block_size': block_size,
            'total_blocks': len(blocks),
            'unique_blocks': len(unique_blocks),
            'similarity_ratio': similarity_ratio,
            'avg_entropy': avg_entropy,
            'entropy_variance': sum((e - avg_entropy) ** 2 for e in block_entropies) / len(block_entropies)
        })
    
    return results

def check_known_signatures(data):
    """检查已知的文件签名"""
    signatures = {
        b'\x7fELF': 'ELF executable',
        b'\x89PNG': 'PNG image',
        b'\xff\xd8\xff': 'JPEG image',
        b'PK\x03\x04': 'ZIP archive',
        b'\x1f\x8b': 'GZIP compressed',
        b'BZ': 'BZIP2 compressed',
        b'\xfd7zXZ': 'XZ compressed',
        b'LZMA': 'LZMA compressed',
        b'MZ': 'DOS/Windows executable',
        b'\xca\xfe\xba\xbe': 'Java class file',
        b'\xfe\xed\xfa': 'Mach-O binary',
        b'\xcf\xfa\xed\xfe': 'Mach-O binary (reverse)',
        # ARM相关
        b'\x00\x00\xa0\xe1': 'ARM code (NOP)',
        b'\x00\x00\x00\xea': 'ARM branch instruction',
        # 8BitDo特定
        b'8BitDo': '8BitDo string',
        b'8bitdo': '8bitdo string',
        b'EBITDO': 'EBITDO string',
    }
    
    found = []
    for sig, desc in signatures.items():
        if sig in data:
            positions = []
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            found.append({
                'signature': binascii.hexlify(sig).decode(),
                'description': desc,
                'positions': positions[:10]  # 最多显示10个位置
            })
    
    return found

def main():
    if len(sys.argv) != 2:
        print("用法: python3 ebitdo_advanced_parser.py <固件文件>")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    
    if not os.path.exists(firmware_path):
        print(f"错误: 文件 {firmware_path} 不存在")
        sys.exit(1)
    
    print(f"高级分析固件文件: {firmware_path}")
    print("=" * 80)
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    print(f"文件大小: {len(data)} bytes")
    print(f"整体熵值: {calculate_entropy(data):.2f}")
    print(f"MD5: {hashlib.md5(data).hexdigest()}")
    print(f"SHA1: {hashlib.sha1(data).hexdigest()}")
    print()
    
    # 检查已知签名
    print("=== 已知签名检查 ===")
    signatures = check_known_signatures(data)
    if signatures:
        for sig in signatures:
            print(f"{sig['description']}: {sig['signature']} at positions {sig['positions']}")
    else:
        print("未发现已知签名")
    print()
    
    # 分析头部候选
    print("=== 头部结构分析 ===")
    headers = analyze_header_candidates(data)
    for header in headers[:5]:  # 只显示前5个
        print(f"头部大小 {header['size']} bytes:")
        print(f"  十六进制: {header['hex'][:64]}...")
        print(f"  头部熵值: {header['entropy']:.2f}")
        print(f"  载荷熵值: {header['payload_entropy']:.2f}")
        if 'possible_length_le' in header:
            print(f"  可能长度(LE): {header['possible_length_le']}")
            print(f"  可能长度(BE): {header['possible_length_be']}")
            if header.get('length_match_le'):
                print(f"  ✓ 长度字段匹配(LE)")
            if header.get('length_match_be'):
                print(f"  ✓ 长度字段匹配(BE)")
        print()
    
    # 分析块结构
    print("=== 块结构分析 ===")
    blocks = analyze_block_structure(data)
    for block in blocks:
        print(f"块大小 {block['block_size']}: {block['total_blocks']} 块, "
              f"{block['unique_blocks']} 唯一, 相似度 {block['similarity_ratio']:.2f}, "
              f"平均熵值 {block['avg_entropy']:.2f}")
    print()
    
    # 尝试简单密码
    print("=== 简单XOR解密尝试 ===")
    simple_results = try_simple_ciphers(data)
    for result in simple_results[:5]:  # 只显示前5个最有希望的结果
        print(f"{result['method']}: 熵值 {result['entropy']:.2f}, 预览 {result['preview']}")
    print()
    
    # 尝试多字节XOR
    print("=== 多字节XOR解密尝试 ===")
    multi_results = try_multi_byte_xor(data)
    for result in multi_results[:5]:
        print(f"{result['method']}: 熵值 {result['entropy']:.2f}, 预览 {result['preview']}")
    print()
    
    # 保存最有希望的结果
    output_dir = os.path.dirname(firmware_path)
    advanced_dir = os.path.join(output_dir, 'advanced_analysis')
    os.makedirs(advanced_dir, exist_ok=True)
    
    saved_count = 0
    all_results = simple_results + multi_results
    all_results.sort(key=lambda x: x['entropy'])
    
    for i, result in enumerate(all_results[:10]):
        if result['entropy'] < 7.0:  # 只保存低熵值结果
            filename = f"candidate_{i:02d}_{result['method']}_entropy{result['entropy']:.2f}.bin"
            filepath = os.path.join(advanced_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(result['data'])
            
            print(f"保存候选文件: {filename}")
            saved_count += 1
    
    # 生成分析报告
    report_path = os.path.join(advanced_dir, 'analysis_report.txt')
    with open(report_path, 'w') as f:
        f.write(f"8BitDo固件高级分析报告\n")
        f.write(f"文件: {firmware_path}\n")
        f.write(f"大小: {len(data)} bytes\n")
        f.write(f"熵值: {calculate_entropy(data):.2f}\n")
        f.write(f"MD5: {hashlib.md5(data).hexdigest()}\n")
        f.write(f"SHA1: {hashlib.sha1(data).hexdigest()}\n\n")
        
        f.write("已知签名:\n")
        for sig in signatures:
            f.write(f"  {sig['description']}: {sig['positions']}\n")
        f.write("\n")
        
        f.write("头部分析:\n")
        for header in headers[:3]:
            f.write(f"  大小 {header['size']}: 熵值 {header['entropy']:.2f}\n")
        f.write("\n")
        
        f.write("解密尝试结果:\n")
        for result in all_results[:10]:
            f.write(f"  {result['method']}: 熵值 {result['entropy']:.2f}\n")
    
    print(f"\n分析完成! 保存了 {saved_count} 个候选文件到 {advanced_dir}")
    print(f"详细报告: {report_path}")

if __name__ == '__main__':
    main()