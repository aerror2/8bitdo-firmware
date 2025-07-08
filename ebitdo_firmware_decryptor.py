#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import hashlib
import binascii
from collections import Counter

class EbitdoFirmwareDecryptor:
    def __init__(self, payload_path):
        self.payload_path = payload_path
        self.payload_data = None
        self.output_dir = "decrypted_results"
        self.load_payload()
        self.create_output_dir()
    
    def load_payload(self):
        """加载载荷文件"""
        try:
            with open(self.payload_path, 'rb') as f:
                self.payload_data = f.read()
            print("✓ 载荷文件加载成功: {} bytes".format(len(self.payload_data)))
        except Exception as e:
            print("✗ 载荷文件加载失败: {}".format(e))
            sys.exit(1)
    
    def create_output_dir(self):
        """创建输出目录"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        print("输出目录: {}".format(os.path.abspath(self.output_dir)))
    
    def calculate_entropy(self, data):
        """计算数据熵值"""
        if not data:
            return 0
        
        import math
        byte_counts = Counter(data)
        data_len = len(data)
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def extract_strings(self, data, min_length=4):
        """提取可打印字符串"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # 可打印ASCII字符
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def detect_file_signatures(self, data):
        """检测文件签名"""
        signatures = {
            b'\x1f\x8b': 'GZIP',
            b'\x78\x9c': 'ZLIB (default)',
            b'\x78\x01': 'ZLIB (best speed)',
            b'\x78\xda': 'ZLIB (best compression)',
            b'PK\x03\x04': 'ZIP',
            b'PK\x05\x06': 'ZIP (empty)',
            b'PK\x07\x08': 'ZIP (spanned)',
            b'BZh': 'BZIP2',
            b'\xfd7zXZ\x00': 'XZ',
            b'\x04"M\x18': 'LZ4',
            b'(\xb5/\xfd': 'ZSTD',
            b'\x7fELF': 'ELF executable',
            b'MZ': 'PE/DOS executable',
            b'\xcf\xfa\xed\xfe': 'Mach-O (32-bit)',
            b'\xcf\xfa\xed\xfe': 'Mach-O (64-bit)',
            b'\x89PNG\r\n\x1a\n': 'PNG image',
            b'\xff\xd8\xff': 'JPEG image',
            b'GIF8': 'GIF image',
            b'RIFF': 'RIFF (WAV/AVI)',
        }
        
        detected = []
        for sig, name in signatures.items():
            if data.startswith(sig):
                detected.append(name)
        
        return detected
    
    def try_ebitdo_xor_keys(self):
        """尝试8BitDo特定的XOR密钥"""
        print("\n=== 尝试8BitDo特定XOR密钥 ===")
        
        # 8BitDo固件常用的XOR密钥
        ebitdo_keys = [
            # 基于产品名称的密钥
            b'8BitDo',
            b'8bitdo',
            b'EBITDO',
            b'ebitdo',
            b'SN30Pro',
            b'SF30Pro',
            b'M30',
            b'N30',
            b'Zero',
            b'Lite',
            b'Pro',
            b'Ultimate',
            b'Adapter',
            b'USB',
            
            # 常见的固件密钥模式
            b'firmware',
            b'FIRMWARE',
            b'update',
            b'UPDATE',
            b'bootloader',
            b'BOOTLOADER',
            
            # 十六进制模式
            bytes.fromhex('8B1D'),
            bytes.fromhex('D18B'),
            bytes.fromhex('DEAD'),
            bytes.fromhex('BEEF'),
            bytes.fromhex('CAFE'),
            bytes.fromhex('BABE'),
            bytes.fromhex('FACE'),
            bytes.fromhex('FEED'),
            
            # 重复字节模式
            b'\x8B' * 16,
            b'\xD1' * 16,
            b'\x1D' * 16,
            b'\x8B\xD1' * 8,
            b'\xD1\x8B' * 8,
            b'\x8B\x1D' * 8,
            b'\x1D\x8B' * 8,
            
            # 基于文件名的密钥
            b'payload',
            b'PAYLOAD',
            b'bin',
            b'BIN',
        ]
        
        results = []
        
        for key in ebitdo_keys:
            try:
                decrypted = self.xor_decrypt(self.payload_data, key)
                entropy = self.calculate_entropy(decrypted)
                strings = self.extract_strings(decrypted)
                signatures = self.detect_file_signatures(decrypted)
                
                # 判断解密是否成功
                if entropy < 7.5 and (len(strings) > 10 or signatures):
                    result = {
                        'key': key,
                        'key_hex': binascii.hexlify(key).decode(),
                        'entropy': entropy,
                        'strings_count': len(strings),
                        'strings': strings[:10],  # 前10个字符串
                        'signatures': signatures,
                        'data': decrypted
                    }
                    results.append(result)
                    
                    print("✓ 密钥 {} 解密成功! 熵值: {:.2f}, 字符串: {}, 签名: {}".format(
                        binascii.hexlify(key).decode(), entropy, len(strings), signatures))
            
            except Exception as e:
                continue
        
        return results
    
    def try_rolling_xor(self):
        """尝试滚动XOR解密"""
        print("\n=== 尝试滚动XOR解密 ===")
        
        results = []
        
        # 尝试不同的滚动模式
        patterns = [
            # 简单递增
            lambda i: i & 0xFF,
            lambda i: (i * 2) & 0xFF,
            lambda i: (i * 3) & 0xFF,
            
            # 基于位置的模式
            lambda i: (i ^ 0x8B) & 0xFF,
            lambda i: (i ^ 0xD1) & 0xFF,
            lambda i: ((i >> 1) ^ (i << 1)) & 0xFF,
            
            # 周期性模式
            lambda i: (0x8B + (i % 16)) & 0xFF,
            lambda i: (0xD1 - (i % 16)) & 0xFF,
            
            # 复杂模式
            lambda i: ((i * 0x8B) ^ 0xD1) & 0xFF,
            lambda i: ((i + 0x8B) ^ (i >> 2)) & 0xFF,
        ]
        
        for pattern_idx, pattern_func in enumerate(patterns):
            try:
                decrypted = bytearray()
                for i, byte in enumerate(self.payload_data):
                    key_byte = pattern_func(i)
                    decrypted.append(byte ^ key_byte)
                
                entropy = self.calculate_entropy(decrypted)
                strings = self.extract_strings(decrypted)
                signatures = self.detect_file_signatures(decrypted)
                
                if entropy < 7.5 and (len(strings) > 10 or signatures):
                    result = {
                        'pattern': pattern_idx,
                        'entropy': entropy,
                        'strings_count': len(strings),
                        'strings': strings[:10],
                        'signatures': signatures,
                        'data': bytes(decrypted)
                    }
                    results.append(result)
                    
                    print("✓ 滚动模式 {} 解密成功! 熵值: {:.2f}, 字符串: {}, 签名: {}".format(
                        pattern_idx, entropy, len(strings), signatures))
            
            except Exception as e:
                continue
        
        return results
    
    def try_block_cipher_modes(self):
        """尝试块密码模式的特征检测"""
        print("\n=== 检测块密码特征 ===")
        
        # 检查常见的块大小
        block_sizes = [8, 16, 32, 64]
        
        for block_size in block_sizes:
            if len(self.payload_data) % block_size == 0:
                print("数据长度对齐到 {} 字节块".format(block_size))
                
                # 检查块之间的相似性
                blocks = []
                for i in range(0, len(self.payload_data), block_size):
                    block = self.payload_data[i:i+block_size]
                    blocks.append(block)
                
                # 统计重复块
                block_counts = Counter(blocks)
                repeated_blocks = [(block, count) for block, count in block_counts.items() if count > 1]
                
                if repeated_blocks:
                    print("  发现 {} 个重复的 {}-字节块".format(len(repeated_blocks), block_size))
                    for block, count in repeated_blocks[:5]:  # 显示前5个
                        print("    {} 重复 {} 次".format(binascii.hexlify(block).decode()[:32], count))
    
    def xor_decrypt(self, data, key):
        """XOR解密"""
        if not key:
            return data
        
        decrypted = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            decrypted.append(byte ^ key[i % key_len])
        
        return bytes(decrypted)
    
    def save_results(self, results, method_name):
        """保存解密结果"""
        if not results:
            return
        
        print("\n保存 {} 解密结果...".format(method_name))
        
        for i, result in enumerate(results):
            # 保存解密数据
            filename = "{}_{}.bin".format(method_name.lower().replace(' ', '_'), i)
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(result['data'])
            
            # 保存分析报告
            report_filename = "{}_{}_report.txt".format(method_name.lower().replace(' ', '_'), i)
            report_filepath = os.path.join(self.output_dir, report_filename)
            
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write("=== {} 解密结果 {} ===\n".format(method_name, i))
                f.write("原始文件: {}\n".format(self.payload_path))
                f.write("解密方法: {}\n".format(method_name))
                
                if 'key' in result:
                    f.write("密钥: {}\n".format(result['key_hex']))
                if 'pattern' in result:
                    f.write("模式: {}\n".format(result['pattern']))
                
                f.write("数据大小: {} bytes\n".format(len(result['data'])))
                f.write("熵值: {:.2f}\n".format(result['entropy']))
                f.write("字符串数量: {}\n".format(result['strings_count']))
                
                if result['signatures']:
                    f.write("文件签名: {}\n".format(', '.join(result['signatures'])))
                
                if result['strings']:
                    f.write("\n发现的字符串:\n")
                    for s in result['strings']:
                        f.write("  {}\n".format(s))
            
            print("  保存: {} (数据) 和 {} (报告)".format(filepath, report_filepath))
    
    def run_decryption(self):
        """运行解密过程"""
        print("=== 8BitDo固件解密器 ===")
        print("文件: {}".format(self.payload_path))
        print("大小: {} bytes".format(len(self.payload_data)))
        
        # 原始数据信息
        entropy = self.calculate_entropy(self.payload_data)
        print("原始熵值: {:.2f}".format(entropy))
        
        all_results = []
        
        # 尝试8BitDo特定密钥
        ebitdo_results = self.try_ebitdo_xor_keys()
        if ebitdo_results:
            all_results.extend(ebitdo_results)
            self.save_results(ebitdo_results, "8BitDo_XOR")
        
        # 尝试滚动XOR
        rolling_results = self.try_rolling_xor()
        if rolling_results:
            all_results.extend(rolling_results)
            self.save_results(rolling_results, "Rolling_XOR")
        
        # 检测块密码特征
        self.try_block_cipher_modes()
        
        if all_results:
            print("\n✓ 找到 {} 个可能的解密结果".format(len(all_results)))
            print("结果已保存到: {}".format(os.path.abspath(self.output_dir)))
        else:
            print("\n✗ 未找到有效的解密结果")
            print("建议尝试其他解密方法或分析工具")

def main():
    if len(sys.argv) != 2:
        print("用法: {} <payload_file>".format(sys.argv[0]))
        sys.exit(1)
    
    payload_file = sys.argv[1]
    if not os.path.exists(payload_file):
        print("错误: 文件不存在 - {}".format(payload_file))
        sys.exit(1)
    
    decryptor = EbitdoFirmwareDecryptor(payload_file)
    decryptor.run_decryption()

if __name__ == "__main__":
    main()