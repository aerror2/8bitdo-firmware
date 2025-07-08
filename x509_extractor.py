#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
X.509证书和密钥提取工具
专门从二进制文件中搜索和提取X.509证书、公钥和私钥
"""

import os
import sys
import re
import binascii
import struct
from collections import OrderedDict

class X509Extractor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = None
        self.output_dir = os.path.join(os.path.dirname(file_path), 'x509_extracted')
        self.findings = OrderedDict()
        
    def load_file(self):
        """加载文件"""
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()
            print("文件加载成功，大小: {} bytes".format(len(self.data)))
            return True
        except Exception as e:
            print("加载文件失败: {}".format(e))
            return False
    
    def create_output_dir(self):
        """创建输出目录"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print("创建输出目录: {}".format(self.output_dir))
    
    def search_pem_certificates(self):
        """搜索PEM格式的证书和密钥"""
        print("\n=== 搜索PEM格式证书和密钥 ===")
        
        pem_patterns = {
            'RSA_PRIVATE_KEY': (b'-----BEGIN RSA PRIVATE KEY-----', b'-----END RSA PRIVATE KEY-----'),
            'PRIVATE_KEY': (b'-----BEGIN PRIVATE KEY-----', b'-----END PRIVATE KEY-----'),
            'RSA_PUBLIC_KEY': (b'-----BEGIN RSA PUBLIC KEY-----', b'-----END RSA PUBLIC KEY-----'),
            'PUBLIC_KEY': (b'-----BEGIN PUBLIC KEY-----', b'-----END PUBLIC KEY-----'),
            'CERTIFICATE': (b'-----BEGIN CERTIFICATE-----', b'-----END CERTIFICATE-----'),
            'X509_CRL': (b'-----BEGIN X509 CRL-----', b'-----END X509 CRL-----'),
            'CERTIFICATE_REQUEST': (b'-----BEGIN CERTIFICATE REQUEST-----', b'-----END CERTIFICATE REQUEST-----'),
            'EC_PRIVATE_KEY': (b'-----BEGIN EC PRIVATE KEY-----', b'-----END EC PRIVATE KEY-----'),
        }
        
        found_pem = []
        for key_type, (begin_marker, end_marker) in pem_patterns.items():
            start_pos = 0
            while True:
                begin_pos = self.data.find(begin_marker, start_pos)
                if begin_pos == -1:
                    break
                
                end_pos = self.data.find(end_marker, begin_pos)
                if end_pos == -1:
                    start_pos = begin_pos + 1
                    continue
                
                end_pos += len(end_marker)
                pem_data = self.data[begin_pos:end_pos]
                
                found_pem.append({
                    'type': key_type,
                    'start': begin_pos,
                    'end': end_pos,
                    'size': len(pem_data),
                    'data': pem_data
                })
                
                print("✓ 发现 {}: 位置 0x{:08x}-0x{:08x}, 大小 {} bytes".format(
                    key_type, begin_pos, end_pos, len(pem_data)))
                
                start_pos = end_pos
        
        self.findings['PEM'] = found_pem
        return found_pem
    
    def search_der_certificates(self):
        """搜索DER格式的证书和密钥"""
        print("\n=== 搜索DER格式证书和密钥 ===")
        
        # ASN.1 DER编码的常见模式
        der_patterns = [
            # X.509证书通常以30 82开始 (SEQUENCE, length > 127)
            (b'\x30\x82', 'X509_CERTIFICATE'),
            # RSA公钥
            (b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01', 'RSA_PUBLIC_KEY_OID'),
            # RSA私钥
            (b'\x30\x82.*\x02\x01\x00\x02\x82', 'RSA_PRIVATE_KEY_PATTERN'),
            # ECDSA相关
            (b'\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01', 'ECDSA_OID'),
        ]
        
        found_der = []
        for pattern, pattern_name in der_patterns:
            if b'.*' in pattern:  # 正则表达式模式
                matches = re.finditer(pattern, self.data, re.DOTALL)
                for match in matches:
                    start_pos = match.start()
                    # 尝试解析ASN.1长度
                    try:
                        length = self._parse_asn1_length(self.data[start_pos:])
                        if length and length < len(self.data) - start_pos:
                            end_pos = start_pos + length
                            found_der.append({
                                'type': pattern_name,
                                'start': start_pos,
                                'end': end_pos,
                                'size': length,
                                'data': self.data[start_pos:end_pos]
                            })
                            print("✓ 发现 {}: 位置 0x{:08x}-0x{:08x}, 大小 {} bytes".format(
                                pattern_name, start_pos, end_pos, length))
                    except:
                        continue
            else:  # 简单字节模式
                start_pos = 0
                while True:
                    pos = self.data.find(pattern, start_pos)
                    if pos == -1:
                        break
                    
                    # 尝试解析ASN.1结构
                    try:
                        length = self._parse_asn1_length(self.data[pos:])
                        if length and length < 10000:  # 合理的长度限制
                            end_pos = pos + length
                            found_der.append({
                                'type': pattern_name,
                                'start': pos,
                                'end': end_pos,
                                'size': length,
                                'data': self.data[pos:end_pos]
                            })
                            print("✓ 发现 {}: 位置 0x{:08x}-0x{:08x}, 大小 {} bytes".format(
                                pattern_name, pos, end_pos, length))
                    except:
                        pass
                    
                    start_pos = pos + 1
        
        self.findings['DER'] = found_der
        return found_der
    
    def _parse_asn1_length(self, data):
        """解析ASN.1 DER编码的长度字段"""
        if len(data) < 2:
            return None
        
        # 跳过tag字节
        offset = 1
        length_byte = data[offset]
        
        if length_byte & 0x80 == 0:
            # 短格式长度
            return length_byte + offset + 1
        else:
            # 长格式长度
            length_bytes = length_byte & 0x7f
            if length_bytes == 0 or length_bytes > 4:
                return None
            
            if len(data) < offset + 1 + length_bytes:
                return None
            
            length = 0
            for i in range(length_bytes):
                length = (length << 8) + data[offset + 1 + i]
            
            return length + offset + 1 + length_bytes
    
    def search_key_patterns(self):
        """搜索密钥相关的二进制模式"""
        print("\n=== 搜索密钥二进制模式 ===")
        
        # 常见的密钥长度（以字节为单位）
        key_lengths = [128, 256, 384, 512, 1024, 2048, 3072, 4096]
        
        found_patterns = []
        
        # 搜索可能的密钥数据块
        for key_len in key_lengths:
            byte_len = key_len // 8
            if byte_len > len(self.data):
                continue
            
            for i in range(0, len(self.data) - byte_len, 16):  # 每16字节检查一次
                chunk = self.data[i:i + byte_len]
                
                # 检查是否像密钥数据
                if self._looks_like_key_data(chunk):
                    found_patterns.append({
                        'type': 'POSSIBLE_KEY_{}bits'.format(key_len),
                        'start': i,
                        'end': i + byte_len,
                        'size': byte_len,
                        'data': chunk
                    })
                    print("✓ 发现可能的{}位密钥: 位置 0x{:08x}, 大小 {} bytes".format(
                        key_len, i, byte_len))
        
        self.findings['KEY_PATTERNS'] = found_patterns
        return found_patterns
    
    def _looks_like_key_data(self, data):
        """判断数据是否像密钥数据"""
        if len(data) < 32:
            return False
        
        # 检查熵值
        entropy = self._calculate_entropy(data)
        if entropy < 6.0:  # 密钥数据应该有较高的熵值
            return False
        
        # 检查零字节比例
        zero_ratio = data.count(0) / len(data)
        if zero_ratio > 0.3:  # 密钥数据不应该有太多零字节
            return False
        
        # 检查重复模式
        if self._has_repetitive_pattern(data):
            return False
        
        return True
    
    def _calculate_entropy(self, data):
        """计算熵值"""
        if not data:
            return 0
        
        import math
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_repetitive_pattern(self, data):
        """检查是否有重复模式"""
        # 检查4字节重复模式
        for pattern_len in [4, 8, 16]:
            if len(data) < pattern_len * 3:
                continue
            
            pattern = data[:pattern_len]
            repetitions = 0
            for i in range(pattern_len, len(data) - pattern_len, pattern_len):
                if data[i:i + pattern_len] == pattern:
                    repetitions += 1
                    if repetitions > len(data) // (pattern_len * 4):  # 超过25%重复
                        return True
        
        return False
    
    def search_crypto_constants(self):
        """搜索加密常量"""
        print("\n=== 搜索加密常量 ===")
        
        crypto_constants = {
            # RSA相关常量
            b'\x01\x00\x01': 'RSA_EXPONENT_65537',
            b'\x03': 'RSA_EXPONENT_3',
            
            # OID常量
            b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01': 'RSA_ENCRYPTION_OID',
            b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05': 'SHA1_WITH_RSA_OID',
            b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b': 'SHA256_WITH_RSA_OID',
            b'\x2a\x86\x48\xce\x3d\x02\x01': 'EC_PUBLIC_KEY_OID',
            
            # 证书相关
            b'\x55\x04\x03': 'COMMON_NAME_OID',
            b'\x55\x04\x06': 'COUNTRY_NAME_OID',
            b'\x55\x04\x08': 'STATE_NAME_OID',
            b'\x55\x04\x0a': 'ORGANIZATION_NAME_OID',
        }
        
        found_constants = []
        for constant, name in crypto_constants.items():
            start_pos = 0
            while True:
                pos = self.data.find(constant, start_pos)
                if pos == -1:
                    break
                
                found_constants.append({
                    'type': name,
                    'start': pos,
                    'size': len(constant),
                    'data': constant
                })
                print("✓ 发现 {}: 位置 0x{:08x}".format(name, pos))
                start_pos = pos + 1
        
        self.findings['CRYPTO_CONSTANTS'] = found_constants
        return found_constants
    
    def save_findings(self):
        """保存发现的数据"""
        if not any(self.findings.values()):
            print("\n没有发现任何证书或密钥数据")
            return
        
        self.create_output_dir()
        
        for category, items in self.findings.items():
            if not items:
                continue
            
            for i, item in enumerate(items):
                filename = "{}_{:03d}_{}.bin".format(
                    category.lower(), i, item['type'].lower())
                filepath = os.path.join(self.output_dir, filename)
                
                try:
                    with open(filepath, 'wb') as f:
                        f.write(item['data'])
                    print("保存: {} ({} bytes)".format(filename, len(item['data'])))
                    
                    # 如果是PEM格式，也保存为.pem文件
                    if category == 'PEM':
                        pem_filename = filename.replace('.bin', '.pem')
                        pem_filepath = os.path.join(self.output_dir, pem_filename)
                        with open(pem_filepath, 'wb') as f:
                            f.write(item['data'])
                        print("保存: {} (PEM格式)".format(pem_filename))
                        
                except Exception as e:
                    print("保存文件失败: {}".format(e))
    
    def generate_report(self):
        """生成分析报告"""
        print("\n" + "="*60)
        print("X.509证书和密钥提取报告")
        print("="*60)
        print("文件: {}".format(self.file_path))
        print("大小: {} bytes".format(len(self.data)))
        
        total_found = sum(len(items) for items in self.findings.values())
        print("总计发现: {} 个项目".format(total_found))
        
        for category, items in self.findings.items():
            if items:
                print("\n[{}] - {} 个项目:".format(category, len(items)))
                for item in items:
                    print("  - {}: 0x{:08x} ({} bytes)".format(
                        item['type'], item['start'], item['size']))
        
        if total_found > 0:
            print("\n输出目录: {}".format(self.output_dir))
        
        print("="*60)
    
    def run_extraction(self):
        """运行完整提取流程"""
        if not self.load_file():
            return False
        
        print("\n开始X.509证书和密钥提取...")
        
        # 搜索PEM格式
        self.search_pem_certificates()
        
        # 搜索DER格式
        self.search_der_certificates()
        
        # 搜索密钥模式
        self.search_key_patterns()
        
        # 搜索加密常量
        self.search_crypto_constants()
        
        # 保存结果
        self.save_findings()
        
        # 生成报告
        self.generate_report()
        
        return True

def main():
    if len(sys.argv) != 2:
        print("用法: python3 {} <文件路径>".format(sys.argv[0]))
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print("错误: 文件不存在 - {}".format(file_path))
        sys.exit(1)
    
    extractor = X509Extractor(file_path)
    if extractor.run_extraction():
        print("\n提取完成!")
    else:
        print("\n提取失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()