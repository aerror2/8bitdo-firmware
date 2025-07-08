#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import hashlib
from collections import Counter
import binascii

class AdvancedPayloadAnalyzer:
    def __init__(self, payload_path):
        self.payload_path = payload_path
        self.payload_data = None
        self.load_payload()
    
    def load_payload(self):
        """加载载荷文件"""
        try:
            with open(self.payload_path, 'rb') as f:
                self.payload_data = f.read()
            print("✓ 载荷文件加载成功: {} bytes".format(len(self.payload_data)))
        except Exception as e:
            print("✗ 载荷文件加载失败: {}".format(e))
            sys.exit(1)
    
    def analyze_entropy(self):
        """分析数据熵值"""
        if not self.payload_data:
            return 0
        
        # 计算字节频率
        byte_counts = Counter(self.payload_data)
        data_len = len(self.payload_data)
        
        # 计算熵值
        import math
        entropy = 0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_patterns(self):
        """分析数据模式"""
        print("\n=== 数据模式分析 ===")
        
        # 字节分布
        byte_counts = Counter(self.payload_data)
        print("唯一字节数: {}/256".format(len(byte_counts)))
        
        # 最常见的字节
        most_common = byte_counts.most_common(5)
        print("最常见字节:")
        for byte_val, count in most_common:
            print("  0x{:02x}: {} 次 ({:.2f}%)".format(
                byte_val, count, count * 100.0 / len(self.payload_data)))
        
        # 检查重复模式
        self.check_repeating_patterns()
    
    def check_repeating_patterns(self):
        """检查重复模式"""
        print("\n检查重复模式:")
        
        # 检查2-8字节的重复模式
        for pattern_len in range(2, 9):
            patterns = {}
            for i in range(len(self.payload_data) - pattern_len + 1):
                pattern = self.payload_data[i:i+pattern_len]
                if pattern in patterns:
                    patterns[pattern] += 1
                else:
                    patterns[pattern] = 1
            
            # 找出重复次数最多的模式
            if patterns:
                most_repeated = max(patterns.items(), key=lambda x: x[1])
                if most_repeated[1] > 2:  # 至少重复3次
                    print("  {}-字节模式: {} 重复 {} 次".format(
                        pattern_len, 
                        binascii.hexlify(most_repeated[0]).decode(),
                        most_repeated[1]))
    
    def analyze_structure(self):
        """分析可能的文件结构"""
        print("\n=== 结构分析 ===")
        
        # 检查文件头
        header = self.payload_data[:16]
        print("文件头 (16字节): {}".format(binascii.hexlify(header).decode()))
        
        # 检查可能的长度字段
        self.check_length_fields()
        
        # 检查对齐
        self.check_alignment()
    
    def check_length_fields(self):
        """检查可能的长度字段"""
        print("\n检查可能的长度字段:")
        
        file_size = len(self.payload_data)
        
        # 检查前几个字节是否包含文件长度信息
        for i in range(0, min(16, len(self.payload_data) - 4), 4):
            # 小端序
            le_val = struct.unpack('<I', self.payload_data[i:i+4])[0]
            # 大端序
            be_val = struct.unpack('>I', self.payload_data[i:i+4])[0]
            
            # 检查是否接近文件大小
            if abs(le_val - file_size) < 100:
                print("  偏移 {}: 小端序 {} (差异: {})".format(i, le_val, abs(le_val - file_size)))
            if abs(be_val - file_size) < 100:
                print("  偏移 {}: 大端序 {} (差异: {})".format(i, be_val, abs(be_val - file_size)))
    
    def check_alignment(self):
        """检查数据对齐"""
        print("\n检查数据对齐:")
        
        # 检查常见的对齐边界
        alignments = [4, 8, 16, 32, 64, 128, 256, 512, 1024]
        
        for align in alignments:
            if len(self.payload_data) % align == 0:
                print("  数据大小对齐到 {} 字节".format(align))
    
    def try_simple_transforms(self):
        """尝试简单的数据变换"""
        print("\n=== 尝试简单变换 ===")
        
        # 尝试字节反转
        self.try_byte_reverse()
        
        # 尝试位反转
        self.try_bit_reverse()
        
        # 尝试简单的移位
        self.try_bit_shifts()
    
    def try_byte_reverse(self):
        """尝试字节反转"""
        reversed_data = self.payload_data[::-1]
        entropy = self.calculate_entropy(reversed_data)
        print("字节反转后熵值: {:.2f}".format(entropy))
        
        # 检查反转后是否有已知的文件头
        self.check_file_signatures(reversed_data[:16], "字节反转")
    
    def try_bit_reverse(self):
        """尝试位反转"""
        bit_reversed = bytearray()
        for byte in self.payload_data:
            # 反转字节中的位
            reversed_byte = int('{:08b}'.format(byte)[::-1], 2)
            bit_reversed.append(reversed_byte)
        
        entropy = self.calculate_entropy(bit_reversed)
        print("位反转后熵值: {:.2f}".format(entropy))
        
        # 检查位反转后是否有已知的文件头
        self.check_file_signatures(bit_reversed[:16], "位反转")
    
    def try_bit_shifts(self):
        """尝试位移位"""
        print("\n尝试位移位:")
        
        for shift in range(1, 8):
            shifted_data = bytearray()
            carry = 0
            
            for byte in self.payload_data:
                new_byte = ((byte << shift) | carry) & 0xFF
                carry = byte >> (8 - shift)
                shifted_data.append(new_byte)
            
            entropy = self.calculate_entropy(shifted_data)
            print("  左移 {} 位后熵值: {:.2f}".format(shift, entropy))
            
            # 检查是否有已知的文件头
            self.check_file_signatures(shifted_data[:16], "左移{}位".format(shift))
    
    def calculate_entropy(self, data):
        """计算数据熵值"""
        if not data:
            return 0
        
        byte_counts = Counter(data)
        data_len = len(data)
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def check_file_signatures(self, data, transform_name):
        """检查文件签名"""
        signatures = {
            b'\x1f\x8b': 'GZIP',
            b'\x78\x9c': 'ZLIB',
            b'\x78\x01': 'ZLIB',
            b'\x78\xda': 'ZLIB',
            b'PK': 'ZIP',
            b'BZ': 'BZIP2',
            b'\xfd7zXZ': 'XZ',
            b'\x04"M\x18': 'LZ4',
            b'(\xb5/\xfd': 'ZSTD',
            b'\x7fELF': 'ELF',
            b'MZ': 'PE/DOS',
            b'\xcf\xfa\xed\xfe': 'Mach-O',
        }
        
        for sig, name in signatures.items():
            if data.startswith(sig):
                print("  {} 检测到 {} 文件签名!".format(transform_name, name))
                return True
        
        return False
    
    def run_analysis(self):
        """运行完整分析"""
        print("=== 高级载荷分析 ===")
        print("文件: {}".format(self.payload_path))
        print("大小: {} bytes".format(len(self.payload_data)))
        
        # 基本信息
        entropy = self.analyze_entropy()
        print("熵值: {:.2f}".format(entropy))
        
        # 文件哈希
        md5_hash = hashlib.md5(self.payload_data).hexdigest()
        sha1_hash = hashlib.sha1(self.payload_data).hexdigest()
        print("MD5: {}".format(md5_hash))
        print("SHA1: {}".format(sha1_hash))
        
        # 模式分析
        self.analyze_patterns()
        
        # 结构分析
        self.analyze_structure()
        
        # 尝试变换
        self.try_simple_transforms()
        
        print("\n=== 分析完成 ===")

def main():
    if len(sys.argv) != 2:
        print("用法: {} <payload_file>".format(sys.argv[0]))
        sys.exit(1)
    
    payload_file = sys.argv[1]
    if not os.path.exists(payload_file):
        print("错误: 文件不存在 - {}".format(payload_file))
        sys.exit(1)
    
    analyzer = AdvancedPayloadAnalyzer(payload_file)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()