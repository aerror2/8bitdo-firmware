#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8BitDo固件高级分析工具
专门用于分析8BitDo固件文件的结构和内容
"""

import os
import sys
import struct
import binascii
import hashlib
from collections import OrderedDict

class FirmwareAnalyzer:
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.data = None
        self.analysis_results = OrderedDict()
        
    def load_firmware(self):
        """加载固件文件"""
        try:
            with open(self.firmware_path, 'rb') as f:
                self.data = f.read()
            print("固件文件加载成功，大小: {} bytes".format(len(self.data)))
            return True
        except Exception as e:
            print("加载固件文件失败: {}".format(e))
            return False
    
    def analyze_header(self):
        """分析文件头"""
        if len(self.data) < 32:
            return
            
        header = self.data[:32]
        self.analysis_results['文件头'] = {
            '前16字节': binascii.hexlify(header[:16]).decode(),
            '后16字节': binascii.hexlify(header[16:32]).decode(),
            '可能的魔术字节': self.find_magic_bytes(header)
        }
        
        # 检查常见的文件格式标识
        magic_patterns = {
            b'\x50\x4B': 'ZIP/JAR格式',
            b'\x1F\x8B': 'GZIP格式',
            b'\x42\x5A': 'BZIP2格式',
            b'\x37\x7A': '7Z格式',
            b'\x52\x61\x72': 'RAR格式',
            b'\x4D\x53\x43\x46': 'CAB格式',
            b'\x7F\x45\x4C\x46': 'ELF格式',
            b'\x4D\x5A': 'PE/EXE格式',
            b'\xFE\xED\xFA': 'Mach-O格式'
        }
        
        detected_format = None
        for magic, format_name in magic_patterns.items():
            if header.startswith(magic):
                detected_format = format_name
                break
                
        self.analysis_results['检测到的格式'] = detected_format or '未知格式'
    
    def find_magic_bytes(self, data):
        """查找可能的魔术字节"""
        magic_candidates = []
        for i in range(min(16, len(data) - 4)):
            chunk = data[i:i+4]
            if all(b != 0 for b in chunk):  # 非零字节
                magic_candidates.append({
                    '偏移': i,
                    '字节': binascii.hexlify(chunk).decode(),
                    'ASCII': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                })
        return magic_candidates
    
    def analyze_structure(self):
        """分析文件结构"""
        # 查找重复模式
        patterns = self.find_patterns()
        self.analysis_results['重复模式'] = patterns
        
        # 查找字符串
        strings = self.extract_strings()
        self.analysis_results['可读字符串'] = strings[:20]  # 只显示前20个
        
        # 分析熵值
        entropy = self.calculate_entropy()
        self.analysis_results['熵值分析'] = entropy
    
    def find_patterns(self):
        """查找重复模式"""
        patterns = {}
        chunk_size = 4
        
        for i in range(0, len(self.data) - chunk_size, chunk_size):
            chunk = self.data[i:i+chunk_size]
            chunk_hex = binascii.hexlify(chunk).decode()
            
            if chunk_hex in patterns:
                patterns[chunk_hex]['count'] += 1
                patterns[chunk_hex]['positions'].append(i)
            else:
                patterns[chunk_hex] = {
                    'count': 1,
                    'positions': [i]
                }
        
        # 只返回出现多次的模式
        repeated_patterns = {k: v for k, v in patterns.items() if v['count'] > 1}
        return dict(list(repeated_patterns.items())[:10])  # 只显示前10个
    
    def extract_strings(self, min_length=4):
        """提取可读字符串"""
        strings = []
        current_string = ""
        
        for byte in self.data:
            if 32 <= byte <= 126:  # 可打印ASCII字符
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # 添加最后一个字符串
        if len(current_string) >= min_length:
            strings.append(current_string)
            
        return list(set(strings))  # 去重
    
    def calculate_entropy(self):
        """计算文件熵值"""
        if not self.data:
            return 0
            
        # 计算字节频率
        byte_counts = [0] * 256
        for byte in self.data:
            byte_counts[byte] += 1
        
        # 计算熵值
        import math
        entropy = 0
        data_len = len(self.data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return {
            '熵值': round(entropy, 4),
            '最大熵值': 8.0,
            '压缩程度': '高' if entropy > 7.5 else '中' if entropy > 6.0 else '低'
        }
    
    def search_crypto_patterns(self):
        """搜索加密相关模式"""
        crypto_patterns = {
            'RSA私钥开始': b'-----BEGIN RSA PRIVATE KEY-----',
            'RSA私钥结束': b'-----END RSA PRIVATE KEY-----',
            'RSA公钥开始': b'-----BEGIN RSA PUBLIC KEY-----',
            'RSA公钥结束': b'-----END RSA PUBLIC KEY-----',
            '私钥开始': b'-----BEGIN PRIVATE KEY-----',
            '私钥结束': b'-----END PRIVATE KEY-----',
            '公钥开始': b'-----BEGIN PUBLIC KEY-----',
            '公钥结束': b'-----END PUBLIC KEY-----',
            '证书开始': b'-----BEGIN CERTIFICATE-----',
            '证书结束': b'-----END CERTIFICATE-----',
            'X509标识': b'\x30\x82',  # ASN.1 SEQUENCE
            'RSA标识': b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01',
        }
        
        found_patterns = {}
        for name, pattern in crypto_patterns.items():
            positions = []
            start = 0
            while True:
                pos = self.data.find(pattern, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            
            if positions:
                found_patterns[name] = positions
        
        self.analysis_results['加密模式'] = found_patterns
    
    def analyze_sections(self):
        """分析文件段"""
        # 将文件分成多个段进行分析
        section_size = 1024
        sections = []
        
        for i in range(0, len(self.data), section_size):
            section_data = self.data[i:i+section_size]
            section_info = {
                '偏移': '0x{:08x}'.format(i),
                '大小': len(section_data),
                '熵值': self.calculate_section_entropy(section_data),
                '零字节比例': section_data.count(0) / len(section_data),
                'MD5': hashlib.md5(section_data).hexdigest()[:16]
            }
            sections.append(section_info)
        
        self.analysis_results['文件段分析'] = sections[:10]  # 只显示前10个段
    
    def calculate_section_entropy(self, data):
        """计算段的熵值"""
        if not data:
            return 0
            
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        import math
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)
    
    def generate_report(self):
        """生成分析报告"""
        print("\n" + "="*60)
        print("8BitDo固件分析报告")
        print("="*60)
        print("文件: {}".format(self.firmware_path))
        print("大小: {} bytes".format(len(self.data)))
        print("MD5: {}".format(hashlib.md5(self.data).hexdigest()))
        print("="*60)
        
        for section, data in self.analysis_results.items():
            print("\n[{}]".format(section))
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, list) and len(value) > 5:
                        print("  {}: {} items (showing first 5)".format(key, len(value)))
                        for item in value[:5]:
                            print("    - {}".format(item))
                    else:
                        print("  {}: {}".format(key, value))
            elif isinstance(data, list):
                print("  {} items (showing first 5):".format(len(data)))
                for item in data[:5]:
                    print("    - {}".format(item))
            else:
                print("  {}".format(data))
    
    def run_analysis(self):
        """运行完整分析"""
        if not self.load_firmware():
            return False
            
        print("\n开始分析固件文件...")
        
        self.analyze_header()
        print("✓ 文件头分析完成")
        
        self.analyze_structure()
        print("✓ 结构分析完成")
        
        self.search_crypto_patterns()
        print("✓ 加密模式搜索完成")
        
        self.analyze_sections()
        print("✓ 文件段分析完成")
        
        self.generate_report()
        return True

def main():
    if len(sys.argv) != 2:
        print("用法: python3 {} <固件文件路径>".format(sys.argv[0]))
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    if not os.path.exists(firmware_path):
        print("错误: 文件不存在 - {}".format(firmware_path))
        sys.exit(1)
    
    analyzer = FirmwareAnalyzer(firmware_path)
    if analyzer.run_analysis():
        print("\n分析完成!")
    else:
        print("\n分析失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()