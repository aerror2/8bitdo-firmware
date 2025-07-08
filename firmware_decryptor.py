#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8BitDo固件解密工具
尝试多种方法解密或解压8BitDo固件文件
"""

import os
import sys
import struct
import binascii
import hashlib
import zlib
import gzip
import bz2
from io import BytesIO

class FirmwareDecryptor:
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.data = None
        self.output_dir = os.path.join(os.path.dirname(firmware_path), 'decrypted')
        
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
    
    def create_output_dir(self):
        """创建输出目录"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print("创建输出目录: {}".format(self.output_dir))
    
    def try_standard_decompression(self):
        """尝试标准解压方法"""
        methods = {
            'zlib': self._try_zlib,
            'gzip': self._try_gzip,
            'bzip2': self._try_bzip2,
            'lzma': self._try_lzma
        }
        
        results = {}
        for method_name, method_func in methods.items():
            try:
                result = method_func()
                if result:
                    results[method_name] = result
                    print("✓ {} 解压成功，解压后大小: {} bytes".format(method_name, len(result)))
                else:
                    print("✗ {} 解压失败".format(method_name))
            except Exception as e:
                print("✗ {} 解压出错: {}".format(method_name, e))
        
        return results
    
    def _try_zlib(self):
        """尝试zlib解压"""
        try:
            # 尝试不同的起始位置
            for offset in [0, 4, 8, 16, 32]:
                if offset >= len(self.data):
                    continue
                try:
                    decompressed = zlib.decompress(self.data[offset:])
                    return decompressed
                except:
                    continue
        except:
            pass
        return None
    
    def _try_gzip(self):
        """尝试gzip解压"""
        try:
            return gzip.decompress(self.data)
        except:
            pass
        return None
    
    def _try_bzip2(self):
        """尝试bzip2解压"""
        try:
            return bz2.decompress(self.data)
        except:
            pass
        return None
    
    def _try_lzma(self):
        """尝试LZMA解压"""
        try:
            import lzma
            return lzma.decompress(self.data)
        except:
            pass
        return None
    
    def try_xor_decryption(self):
        """尝试XOR解密"""
        print("\n尝试XOR解密...")
        
        # 常见的XOR密钥
        common_keys = [
            b'\x00',
            b'\xFF',
            b'\xAA',
            b'\x55',
            b'8BitDo',
            b'firmware',
            b'\x12\x34\x56\x78',
            b'\xDE\xAD\xBE\xEF'
        ]
        
        results = {}
        for key in common_keys:
            try:
                decrypted = self._xor_decrypt(self.data, key)
                # 检查解密结果是否有意义
                if self._is_meaningful_data(decrypted):
                    key_str = binascii.hexlify(key).decode() if len(key) <= 8 else key.decode('ascii', errors='ignore')
                    results[key_str] = decrypted
                    print("✓ XOR密钥 '{}' 可能有效".format(key_str))
            except Exception as e:
                continue
        
        return results
    
    def _xor_decrypt(self, data, key):
        """XOR解密"""
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
    
    def _is_meaningful_data(self, data):
        """检查数据是否有意义"""
        if len(data) < 100:
            return False
        
        # 检查是否包含常见的文件头
        file_signatures = [
            b'\x50\x4B',  # ZIP
            b'\x1F\x8B',  # GZIP
            b'\x42\x5A',  # BZIP2
            b'\x37\x7A',  # 7Z
            b'\x7F\x45\x4C\x46',  # ELF
            b'\x4D\x5A',  # PE/EXE
            b'\x89\x50\x4E\x47',  # PNG
            b'\xFF\xD8\xFF',  # JPEG
        ]
        
        for sig in file_signatures:
            if data.startswith(sig):
                return True
        
        # 检查可打印字符比例
        printable_count = sum(1 for b in data[:1000] if 32 <= b <= 126)
        if printable_count / min(1000, len(data)) > 0.3:
            return True
        
        # 检查熵值（解密后的数据熵值应该较低）
        entropy = self._calculate_entropy(data[:1000])
        if entropy < 6.0:
            return True
        
        return False
    
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
    
    def try_custom_decryption(self):
        """尝试自定义解密方法"""
        print("\n尝试自定义解密方法...")
        
        results = {}
        
        # 方法1: 跳过文件头
        for skip_bytes in [4, 8, 16, 32, 64]:
            if skip_bytes >= len(self.data):
                continue
            
            skipped_data = self.data[skip_bytes:]
            
            # 尝试解压跳过头部的数据
            try:
                decompressed = zlib.decompress(skipped_data)
                results['skip_{}_zlib'.format(skip_bytes)] = decompressed
                print("✓ 跳过{}字节后zlib解压成功".format(skip_bytes))
            except:
                pass
        
        # 方法2: 反转字节序
        try:
            reversed_data = self.data[::-1]
            decompressed = zlib.decompress(reversed_data)
            results['reversed_zlib'] = decompressed
            print("✓ 反转字节序后zlib解压成功")
        except:
            pass
        
        # 方法3: 简单的Caesar密码
        for shift in [1, 2, 3, 7, 13]:
            try:
                shifted_data = bytes((b + shift) % 256 for b in self.data)
                if self._is_meaningful_data(shifted_data):
                    results['caesar_{}'.format(shift)] = shifted_data
                    print("✓ Caesar密码(shift={})可能有效".format(shift))
            except:
                pass
        
        return results
    
    def save_results(self, results, method_type):
        """保存解密结果"""
        if not results:
            return
        
        for method_name, data in results.items():
            filename = "{}_{}.bin".format(method_type, method_name)
            filepath = os.path.join(self.output_dir, filename)
            
            try:
                with open(filepath, 'wb') as f:
                    f.write(data)
                print("保存解密结果: {}".format(filepath))
                
                # 分析解密后的数据
                self._analyze_decrypted_data(data, method_name)
                
            except Exception as e:
                print("保存文件失败: {}".format(e))
    
    def _analyze_decrypted_data(self, data, method_name):
        """分析解密后的数据"""
        print("  分析 {}: 大小={} bytes, 熵值={:.2f}".format(
            method_name, len(data), self._calculate_entropy(data[:1000])))
        
        # 检查文件类型
        if data.startswith(b'\x50\x4B'):
            print("    -> 可能是ZIP文件")
        elif data.startswith(b'\x1F\x8B'):
            print("    -> 可能是GZIP文件")
        elif data.startswith(b'\x7F\x45\x4C\x46'):
            print("    -> 可能是ELF可执行文件")
        elif data.startswith(b'\x4D\x5A'):
            print("    -> 可能是PE/EXE文件")
        
        # 查找可读字符串
        strings = self._extract_strings(data[:2000])
        if strings:
            print("    -> 发现字符串: {}".format(', '.join(strings[:5])))
    
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
        
        return list(set(strings))[:10]  # 去重并限制数量
    
    def run_decryption(self):
        """运行完整解密流程"""
        if not self.load_firmware():
            return False
        
        self.create_output_dir()
        
        print("\n开始解密固件文件...")
        print("原始文件: {}".format(self.firmware_path))
        print("输出目录: {}".format(self.output_dir))
        
        # 尝试标准解压
        print("\n=== 尝试标准解压方法 ===")
        decompression_results = self.try_standard_decompression()
        if decompression_results:
            self.save_results(decompression_results, 'decompression')
        
        # 尝试XOR解密
        print("\n=== 尝试XOR解密 ===")
        xor_results = self.try_xor_decryption()
        if xor_results:
            self.save_results(xor_results, 'xor')
        
        # 尝试自定义解密
        print("\n=== 尝试自定义解密方法 ===")
        custom_results = self.try_custom_decryption()
        if custom_results:
            self.save_results(custom_results, 'custom')
        
        # 总结
        total_results = len(decompression_results) + len(xor_results) + len(custom_results)
        if total_results > 0:
            print("\n✓ 解密完成! 共生成 {} 个可能的解密结果".format(total_results))
            print("请检查输出目录: {}".format(self.output_dir))
        else:
            print("\n✗ 未能成功解密固件文件")
            print("该固件可能使用了未知的加密算法或专有格式")
        
        return total_results > 0

def main():
    if len(sys.argv) != 2:
        print("用法: python3 {} <固件文件路径>".format(sys.argv[0]))
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    if not os.path.exists(firmware_path):
        print("错误: 文件不存在 - {}".format(firmware_path))
        sys.exit(1)
    
    decryptor = FirmwareDecryptor(firmware_path)
    if decryptor.run_decryption():
        print("\n解密流程完成!")
    else:
        print("\n解密流程失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()