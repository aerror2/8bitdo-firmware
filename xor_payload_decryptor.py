#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8BitDo固件载荷XOR解密工具
尝试使用不同的XOR密钥解密payload数据
"""

import os
import sys
import hashlib
import zlib
import gzip
try:
    from typing import List, Dict, Tuple
except ImportError:
    # Python < 3.5 compatibility
    List = list
    Dict = dict
    Tuple = tuple

class XORPayloadDecryptor:
    def __init__(self, payload_path):
        self.payload_path = payload_path
        self.payload_data = b''
        self.output_dir = os.path.join(os.path.dirname(payload_path), 'xor_decrypted')
        
    def load_payload(self):
        """加载payload文件"""
        try:
            with open(self.payload_path, 'rb') as f:
                self.payload_data = f.read()
            print("✓ 载荷文件加载成功: {} bytes".format(len(self.payload_data)))
            return True
        except Exception as e:
            print("✗ 载荷文件加载失败: {}".format(e))
            return False
    
    def create_output_dir(self):
        """创建输出目录"""
        os.makedirs(self.output_dir, exist_ok=True)
        print("✓ 输出目录: {}".format(self.output_dir))
    
    def _calculate_entropy(self, data):
        """计算数据熵值"""
        if not data:
            return 0.0
        
        # 计算字节频率
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # 计算熵值
        import math
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _extract_strings(self, data, min_length=4):
        """提取可读字符串"""
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
        
        return strings[:20]  # 返回前20个字符串
    
    def _detect_file_signatures(self, data):
        """检测文件签名"""
        signatures = []
        
        # 常见文件签名
        file_sigs = {
            b'\x1F\x8B': 'GZIP',
            b'\x50\x4B': 'ZIP/JAR',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x4D\x5A': 'PE/EXE',
            b'\x89\x50\x4E\x47': 'PNG',
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x42\x4D': 'BMP',
            b'\x47\x49\x46': 'GIF',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x78\x9C': 'ZLIB',
            b'\x78\x01': 'ZLIB',
            b'\x78\xDA': 'ZLIB'
        }
        
        for sig, name in file_sigs.items():
            if data.startswith(sig):
                signatures.append(name)
        
        return signatures
    
    def _analyze_decrypted_data(self, data, key_info):
        """分析解密后的数据"""
        analysis = {
            'key_info': key_info,
            'size': len(data),
            'entropy': self._calculate_entropy(data[:1000]),
            'md5': hashlib.md5(data).hexdigest(),
            'signatures': self._detect_file_signatures(data),
            'strings': self._extract_strings(data[:2000])
        }
        
        # 尝试解压缩
        analysis['decompression'] = {}
        
        # 尝试ZLIB解压
        try:
            decompressed = zlib.decompress(data)
            analysis['decompression']['zlib'] = {
                'success': True,
                'size': len(decompressed),
                'entropy': self._calculate_entropy(decompressed[:1000])
            }
        except:
            analysis['decompression']['zlib'] = {'success': False}
        
        # 尝试GZIP解压
        try:
            decompressed = gzip.decompress(data)
            analysis['decompression']['gzip'] = {
                'success': True,
                'size': len(decompressed),
                'entropy': self._calculate_entropy(decompressed[:1000])
            }
        except:
            analysis['decompression']['gzip'] = {'success': False}
        
        return analysis
    
    def xor_decrypt(self, data, key):
        """XOR解密"""
        if not key:
            return data
        
        result = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        return bytes(result)
    
    def try_single_byte_xor(self):
        """尝试单字节XOR解密"""
        print("\n=== 尝试单字节XOR解密 ===")
        results = {}
        
        # 尝试所有可能的单字节密钥
        for key_byte in range(256):
            key = bytes([key_byte])
            decrypted = self.xor_decrypt(self.payload_data, key)
            
            # 分析解密结果
            analysis = self._analyze_decrypted_data(decrypted, "单字节XOR: 0x{:02X}".format(key_byte))
            
            # 降低判断阈值，增加调试信息
            if key_byte % 64 == 0:  # 每64个密钥打印一次进度
                print("  进度: 测试密钥 0x{:02X}, 当前熵值={:.2f}".format(key_byte, analysis['entropy']))
            
            # 如果熵值较低或检测到文件签名，认为可能是有效解密
            if (analysis['entropy'] < 7.5 or 
                analysis['signatures'] or 
                analysis['decompression']['zlib']['success'] or
                analysis['decompression']['gzip']['success'] or
                len(analysis['strings']) > 10):  # 增加字符串数量判断
                
                results["xor_single_{:02X}".format(key_byte)] = (decrypted, analysis)
                print("  ✓ 密钥 0x{:02X}: 熵值={:.2f}, 签名={}, 字符串数={}".format(key_byte, analysis['entropy'], analysis['signatures'], len(analysis['strings'])))
        
        print("找到 {} 个可能的解密结果".format(len(results)))
        return results
    
    def try_multi_byte_xor(self):
        """尝试多字节XOR解密"""
        print("\n=== 尝试多字节XOR解密 ===")
        results = {}
        
        # 常见的多字节密钥
        common_keys = [
            b'\x00\x01',
            b'\x01\x02',
            b'\xFF\xFE',
            b'\xAA\x55',
            b'\x55\xAA',
            b'\x12\x34',
            b'\x34\x12',
            b'\xDE\xAD',
            b'\xBE\xEF',
            b'\xCA\xFE',
            b'\xBA\xBE',
            b'\x8B\x1D\xD0',  # 常见的固件密钥模式
            b'\x00\x01\x02\x03',
            b'\xFF\xFE\xFD\xFC',
            b'\xAA\x55\xAA\x55',
            b'\x12\x34\x56\x78',
            b'\x87\x65\x43\x21',
        ]
        
        # 添加基于文件名的密钥
        filename_keys = [
            b'8bitdo',
            b'EBITDO',
            b'usb',
            b'USB',
            b'adapter',
            b'ADAPTER',
            b'firmware',
            b'FIRMWARE'
        ]
        
        all_keys = common_keys + filename_keys
        
        for i, key in enumerate(all_keys):
            decrypted = self.xor_decrypt(self.payload_data, key)
            analysis = self._analyze_decrypted_data(decrypted, "多字节XOR: {}".format(key.hex()))
            
            # 如果熵值较低或检测到文件签名，认为可能是有效解密
            if (analysis['entropy'] < 6.0 or 
                analysis['signatures'] or 
                analysis['decompression']['zlib']['success'] or
                analysis['decompression']['gzip']['success']):
                
                results["xor_multi_{:02d}_{}".format(i, key.hex())] = (decrypted, analysis)
                print("  ✓ 密钥 {}: 熵值={:.2f}, 签名={}".format(key.hex(), analysis['entropy'], analysis['signatures']))
        
        print("找到 {} 个可能的解密结果".format(len(results)))
        return results
    
    def try_pattern_based_xor(self):
        """尝试基于模式的XOR解密"""
        print("\n=== 尝试基于模式的XOR解密 ===")
        results = {}
        
        # 尝试从payload开头提取可能的密钥
        if len(self.payload_data) >= 16:
            # 假设前几个字节可能是密钥或与密钥相关
            potential_keys = [
                self.payload_data[:1],
                self.payload_data[:2],
                self.payload_data[:4],
                self.payload_data[:8],
                self.payload_data[4:8],
                self.payload_data[8:12],
                self.payload_data[12:16],
            ]
            
            for i, key in enumerate(potential_keys):
                if key:
                    decrypted = self.xor_decrypt(self.payload_data, key)
                    analysis = self._analyze_decrypted_data(decrypted, "模式密钥: {}".format(key.hex()))
                    
                    if (analysis['entropy'] < 6.0 or 
                        analysis['signatures'] or 
                        analysis['decompression']['zlib']['success'] or
                        analysis['decompression']['gzip']['success']):
                        
                        results["xor_pattern_{:02d}_{}".format(i, key.hex())] = (decrypted, analysis)
                        print("  ✓ 模式密钥 {}: 熵值={:.2f}, 签名={}".format(key.hex(), analysis['entropy'], analysis['signatures']))
        
        print("找到 {} 个可能的解密结果".format(len(results)))
        return results
    
    def save_results(self, results):
        """保存解密结果"""
        if not results:
            print("没有解密结果需要保存")
            return
        
        print("\n=== 保存解密结果 ===")
        
        # 生成分析报告
        report_path = os.path.join(self.output_dir, 'xor_decryption_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("8BitDo固件载荷XOR解密分析报告\n")
            f.write("=" * 50 + "\n\n")
            f.write("原始载荷文件: {}\n".format(self.payload_path))
            f.write("载荷大小: {} bytes\n".format(len(self.payload_data)))
            f.write("找到可能的解密结果: {} 个\n\n".format(len(results)))
            
            for result_name, (data, analysis) in results.items():
                f.write("解密结果: {}\n".format(result_name))
                f.write("  密钥信息: {}\n".format(analysis['key_info']))
                f.write("  数据大小: {} bytes\n".format(analysis['size']))
                f.write("  熵值: {:.2f}\n".format(analysis['entropy']))
                f.write("  MD5: {}\n".format(analysis['md5']))
                f.write("  文件签名: {}\n".format(', '.join(analysis['signatures']) if analysis['signatures'] else '无'))
                
                # 解压缩结果
                if analysis['decompression']['zlib']['success']:
                    f.write("  ZLIB解压: 成功 ({} bytes)\n".format(analysis['decompression']['zlib']['size']))
                if analysis['decompression']['gzip']['success']:
                    f.write("  GZIP解压: 成功 ({} bytes)\n".format(analysis['decompression']['gzip']['size']))
                
                # 字符串
                if analysis['strings']:
                    f.write("  发现字符串: {}\n".format(', '.join(analysis['strings'][:5])))
                
                f.write("\n")
        
        print("✓ 分析报告已保存: {}".format(report_path))
        
        # 保存解密数据
        for result_name, (data, analysis) in results.items():
            data_path = os.path.join(self.output_dir, "{}.bin".format(result_name))
            with open(data_path, 'wb') as f:
                f.write(data)
            print("✓ 解密数据已保存: {}".format(data_path))
            
            # 如果解压缩成功，也保存解压后的数据
            if analysis['decompression']['zlib']['success']:
                try:
                    decompressed = zlib.decompress(data)
                    decomp_path = os.path.join(self.output_dir, "{}_zlib_decompressed.bin".format(result_name))
                    with open(decomp_path, 'wb') as f:
                        f.write(decompressed)
                    print("✓ ZLIB解压数据已保存: {}".format(decomp_path))
                except:
                    pass
            
            if analysis['decompression']['gzip']['success']:
                try:
                    decompressed = gzip.decompress(data)
                    decomp_path = os.path.join(self.output_dir, "{}_gzip_decompressed.bin".format(result_name))
                    with open(decomp_path, 'wb') as f:
                        f.write(decompressed)
                    print("✓ GZIP解压数据已保存: {}".format(decomp_path))
                except:
                    pass
    
    def run_decryption(self):
        """运行完整的XOR解密流程"""
        print("8BitDo固件载荷XOR解密工具")
        print("=" * 40)
        
        if not self.load_payload():
            return False
        
        self.create_output_dir()
        
        # 显示原始载荷信息
        print("\n=== 原始载荷信息 ===")
        print("文件路径: {}".format(self.payload_path))
        print("数据大小: {} bytes".format(len(self.payload_data)))
        print("原始熵值: {:.2f}".format(self._calculate_entropy(self.payload_data[:1000])))
        print("前16字节: {}".format(self.payload_data[:16].hex()))
        
        # 收集所有解密结果
        all_results = {}
        
        # 尝试不同的XOR解密方法
        single_results = self.try_single_byte_xor()
        all_results.update(single_results)
        
        multi_results = self.try_multi_byte_xor()
        all_results.update(multi_results)
        
        pattern_results = self.try_pattern_based_xor()
        all_results.update(pattern_results)
        
        # 保存结果
        self.save_results(all_results)
        
        print("\n=== 解密完成 ===")
        print("总共找到 {} 个可能的解密结果".format(len(all_results)))
        print("结果已保存到: {}".format(self.output_dir))
        
        return len(all_results) > 0

def main():
    if len(sys.argv) != 2:
        print("用法: python xor_payload_decryptor.py <payload.bin>")
        print("示例: python xor_payload_decryptor.py firmware_downloads/USB\ Adapter/1.25/fwupd_parsed/payload.bin")
        sys.exit(1)
    
    payload_path = sys.argv[1]
    
    if not os.path.exists(payload_path):
        print("错误: 文件不存在 - {}".format(payload_path))
        sys.exit(1)
    
    decryptor = XORPayloadDecryptor(payload_path)
    success = decryptor.run_decryption()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()