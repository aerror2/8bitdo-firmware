#!/usr/bin/env python3
"""
提取固件中嵌入的数据
基于发现的签名位置
"""

import os
import sys
import gzip
import zlib
import struct
import binascii

def extract_gzip_data(data, offset):
    """从指定偏移提取GZIP数据"""
    try:
        # 查找GZIP数据的结束位置
        gzip_data = data[offset:]
        
        # 尝试解压不同长度的数据
        for end_offset in range(100, len(gzip_data), 100):
            try:
                candidate = gzip_data[:end_offset]
                decompressed = gzip.decompress(candidate)
                return candidate, decompressed
            except:
                continue
        
        # 如果上面失败，尝试整个剩余数据
        try:
            decompressed = gzip.decompress(gzip_data)
            return gzip_data, decompressed
        except:
            return None, None
            
    except Exception as e:
        return None, None

def extract_pe_data(data, offset):
    """从指定偏移提取PE/DOS数据"""
    try:
        # PE文件通常有明确的大小信息
        pe_data = data[offset:]
        
        # 检查DOS头
        if len(pe_data) >= 64:
            # DOS头中的e_lfanew字段指向PE头
            e_lfanew = struct.unpack('<I', pe_data[60:64])[0]
            
            if e_lfanew < len(pe_data) - 4:
                # 检查PE签名
                pe_sig = pe_data[e_lfanew:e_lfanew+4]
                if pe_sig == b'PE\x00\x00':
                    # 这是一个有效的PE文件
                    # 尝试提取整个PE文件（简化版本）
                    return pe_data[:min(len(pe_data), 100000)]  # 限制大小
        
        # 如果不是PE文件，可能是简单的DOS程序
        return pe_data[:min(len(pe_data), 10000)]  # 限制大小
        
    except Exception as e:
        return None

def analyze_extracted_data(data, data_type):
    """分析提取的数据"""
    if not data:
        return None
    
    analysis = {
        'size': len(data),
        'type': data_type,
        'hex_preview': binascii.hexlify(data[:64]).decode(),
        'strings': []
    }
    
    # 查找字符串
    current_string = b''
    for byte in data:
        if 32 <= byte <= 126:  # 可打印ASCII字符
            current_string += bytes([byte])
        else:
            if len(current_string) >= 4:
                try:
                    analysis['strings'].append(current_string.decode('ascii'))
                except:
                    pass
            current_string = b''
    
    if len(current_string) >= 4:
        try:
            analysis['strings'].append(current_string.decode('ascii'))
        except:
            pass
    
    # 限制字符串数量
    analysis['strings'] = analysis['strings'][:20]
    
    return analysis

def main():
    if len(sys.argv) != 2:
        print("用法: python3 extract_embedded_data.py <固件文件>")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    
    if not os.path.exists(firmware_path):
        print(f"错误: 文件 {firmware_path} 不存在")
        sys.exit(1)
    
    print(f"提取嵌入数据: {firmware_path}")
    print("=" * 60)
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    output_dir = os.path.dirname(firmware_path)
    extracted_dir = os.path.join(output_dir, 'extracted_embedded')
    os.makedirs(extracted_dir, exist_ok=True)
    
    # 提取GZIP数据
    gzip_offsets = [1814, 59370]
    for i, offset in enumerate(gzip_offsets):
        print(f"\n=== 提取GZIP数据 #{i+1} (偏移 {offset}) ===")
        
        gzip_raw, gzip_decompressed = extract_gzip_data(data, offset)
        
        if gzip_raw:
            # 保存原始GZIP数据
            gzip_path = os.path.join(extracted_dir, f'gzip_{i+1}_raw.gz')
            with open(gzip_path, 'wb') as f:
                f.write(gzip_raw)
            print(f"保存原始GZIP: {gzip_path} ({len(gzip_raw)} bytes)")
            
            if gzip_decompressed:
                # 保存解压数据
                decompressed_path = os.path.join(extracted_dir, f'gzip_{i+1}_decompressed.bin')
                with open(decompressed_path, 'wb') as f:
                    f.write(gzip_decompressed)
                print(f"保存解压数据: {decompressed_path} ({len(gzip_decompressed)} bytes)")
                
                # 分析解压数据
                analysis = analyze_extracted_data(gzip_decompressed, 'GZIP_decompressed')
                if analysis:
                    print(f"解压数据分析:")
                    print(f"  大小: {analysis['size']} bytes")
                    print(f"  预览: {analysis['hex_preview']}")
                    if analysis['strings']:
                        print(f"  字符串: {analysis['strings'][:5]}")
        else:
            print(f"无法提取GZIP数据")
    
    # 提取PE/DOS数据
    pe_offset = 59532
    print(f"\n=== 提取PE/DOS数据 (偏移 {pe_offset}) ===")
    
    pe_data = extract_pe_data(data, pe_offset)
    
    if pe_data:
        # 保存PE数据
        pe_path = os.path.join(extracted_dir, 'pe_dos_executable.bin')
        with open(pe_path, 'wb') as f:
            f.write(pe_data)
        print(f"保存PE/DOS数据: {pe_path} ({len(pe_data)} bytes)")
        
        # 分析PE数据
        analysis = analyze_extracted_data(pe_data, 'PE_DOS')
        if analysis:
            print(f"PE/DOS数据分析:")
            print(f"  大小: {analysis['size']} bytes")
            print(f"  预览: {analysis['hex_preview']}")
            if analysis['strings']:
                print(f"  字符串: {analysis['strings'][:5]}")
    else:
        print(f"无法提取PE/DOS数据")
    
    # 尝试提取其他可能的数据段
    print(f"\n=== 搜索其他数据段 ===")
    
    # 查找其他可能的压缩数据
    zlib_magic = b'\x78\x9c'  # zlib deflate
    zlib_positions = []
    start = 0
    while True:
        pos = data.find(zlib_magic, start)
        if pos == -1:
            break
        zlib_positions.append(pos)
        start = pos + 1
    
    if zlib_positions:
        print(f"发现 {len(zlib_positions)} 个可能的zlib数据段: {zlib_positions[:10]}")
        
        for i, pos in enumerate(zlib_positions[:3]):  # 只处理前3个
            try:
                # 尝试解压zlib数据
                remaining_data = data[pos:]
                for end_offset in range(100, min(len(remaining_data), 10000), 100):
                    try:
                        candidate = remaining_data[:end_offset]
                        decompressed = zlib.decompress(candidate)
                        
                        # 保存成功的解压数据
                        zlib_path = os.path.join(extracted_dir, f'zlib_{i+1}_decompressed.bin')
                        with open(zlib_path, 'wb') as f:
                            f.write(decompressed)
                        print(f"保存zlib解压数据: {zlib_path} ({len(decompressed)} bytes)")
                        
                        # 分析数据
                        analysis = analyze_extracted_data(decompressed, 'zlib_decompressed')
                        if analysis and analysis['strings']:
                            print(f"  字符串: {analysis['strings'][:3]}")
                        break
                    except:
                        continue
            except:
                continue
    
    print(f"\n提取完成! 所有数据保存到: {extracted_dir}")

if __name__ == '__main__':
    main()