#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8BitDo固件解析工具
基于fwupd ebitdo插件的固件格式信息
参考: https://github.com/fwupd/fwupd/blob/main/plugins/ebitdo/README.md
"""

import os
import sys
import struct
import binascii
import hashlib
import zlib
import gzip
from io import BytesIO

class EbitdoFirmwareParser:
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.data = None
        self.header_info = {}
        self.payload_data = None
        self.output_dir = os.path.join(os.path.dirname(firmware_path), 'parsed')
        
    def load_firmware(self):
        """加载固件文件"""
        try:
            with open(self.firmware_path, 'rb') as f:
                self.data = f.read()
            print(f"固件文件加载成功，大小: {len(self.data)} bytes")
            return True
        except Exception as e:
            print(f"加载固件文件失败: {e}")
            return False
    
    def create_output_dir(self):
        """创建输出目录"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"创建输出目录: {self.output_dir}")
    
    def analyze_header(self):
        """分析8BitDo固件头部"""
        print("\n=== 分析8BitDo固件头部 ===")
        
        if len(self.data) < 64:
            print("文件太小，无法包含有效的固件头部")
            return False
        
        # 尝试不同的头部大小
        header_sizes = [16, 32, 64, 128, 256]
        
        for header_size in header_sizes:
            if header_size > len(self.data):
                continue
                
            header = self.data[:header_size]
            print(f"\n尝试头部大小: {header_size} bytes")
            print(f"头部十六进制: {binascii.hexlify(header[:32]).decode()}...")
            
            # 检查是否有明显的结构
            if self._analyze_header_structure(header, header_size):
                self.header_info['size'] = header_size
                self.header_info['data'] = header
                self.payload_data = self.data[header_size:]
                print(f"✓ 检测到可能的头部结构，大小: {header_size} bytes")
                return True
        
        print("未能识别固件头部结构")
        return False
    
    def _analyze_header_structure(self, header, size):
        """分析头部结构"""
        try:
            # 检查常见的固件头部模式
            
            # 模式1: 前4字节可能是魔术数字或版本
            magic = struct.unpack('<I', header[:4])[0]
            print(f"  前4字节 (小端): 0x{magic:08X}")
            
            # 模式2: 检查是否有长度字段
            if size >= 8:
                length1 = struct.unpack('<I', header[4:8])[0]
                length2 = struct.unpack('>I', header[4:8])[0]
                print(f"  字节5-8 (小端): {length1}, (大端): {length2}")
                
                # 如果长度字段指向文件末尾附近，可能是有效的
                if abs(length1 - len(self.data)) < 1000 or abs(length2 - len(self.data)) < 1000:
                    print("  ✓ 可能包含文件长度信息")
                    return True
            
            # 模式3: 检查是否有校验和
            if size >= 16:
                # 尝试MD5或CRC32
                payload = self.data[size:]
                if payload:
                    md5_hash = hashlib.md5(payload).digest()
                    if md5_hash == header[-16:]:
                        print("  ✓ 检测到MD5校验和")
                        return True
            
            # 模式4: 检查重复模式
            zero_count = header.count(0)
            if zero_count > size * 0.7:  # 如果70%以上是0，可能不是有效头部
                return False
            
            # 模式5: 检查是否有可读字符串
            try:
                text = header.decode('ascii', errors='ignore')
                if any(word in text.lower() for word in ['8bitdo', 'firmware', 'version']):
                    print(f"  ✓ 检测到相关字符串: {text[:20]}")
                    return True
            except:
                pass
            
            return False
            
        except Exception as e:
            print(f"  分析头部时出错: {e}")
            return False
    
    def extract_payload(self):
        """提取载荷数据"""
        if not self.payload_data:
            print("没有载荷数据可提取")
            return False
        
        print(f"\n=== 提取载荷数据 ===")
        print(f"载荷大小: {len(self.payload_data)} bytes")
        
        # 尝试不同的解压方法
        decompression_methods = {
            'raw': self._extract_raw,
            'zlib': self._extract_zlib,
            'gzip': self._extract_gzip,
            'deflate': self._extract_deflate
        }
        
        extracted_data = {}
        
        for method_name, method_func in decompression_methods.items():
            try:
                result = method_func(self.payload_data)
                if result:
                    extracted_data[method_name] = result
                    print(f"✓ {method_name} 提取成功，大小: {len(result)} bytes")
                    
                    # 分析提取的数据
                    self._analyze_extracted_data(result, method_name)
                else:
                    print(f"✗ {method_name} 提取失败")
            except Exception as e:
                print(f"✗ {method_name} 提取出错: {e}")
        
        return extracted_data
    
    def _extract_raw(self, data):
        """直接提取原始数据"""
        return data
    
    def _extract_zlib(self, data):
        """尝试zlib解压"""
        try:
            return zlib.decompress(data)
        except:
            # 尝试跳过一些字节
            for skip in [1, 2, 4, 8, 16]:
                try:
                    return zlib.decompress(data[skip:])
                except:
                    continue
        return None
    
    def _extract_gzip(self, data):
        """尝试gzip解压"""
        try:
            return gzip.decompress(data)
        except:
            pass
        return None
    
    def _extract_deflate(self, data):
        """尝试deflate解压"""
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except:
            pass
        return None
    
    def _analyze_extracted_data(self, data, method_name):
        """分析提取的数据"""
        print(f"  分析 {method_name} 数据:")
        
        # 检查文件类型
        if data.startswith(b'\x7FELF'):
            print("    -> ELF可执行文件")
        elif data.startswith(b'PK'):
            print("    -> ZIP/JAR文件")
        elif data.startswith(b'\x1f\x8b'):
            print("    -> GZIP文件")
        elif data.startswith(b'BZ'):
            print("    -> BZIP2文件")
        
        # 计算熵值
        entropy = self._calculate_entropy(data[:1000])
        print(f"    -> 熵值: {entropy:.2f}")
        
        # 查找字符串
        strings = self._extract_strings(data[:2000])
        if strings:
            print(f"    -> 发现字符串: {', '.join(strings[:3])}...")
        
        # 保存数据
        filename = f"extracted_{method_name}.bin"
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'wb') as f:
                f.write(data)
            print(f"    -> 已保存: {filepath}")
        except Exception as e:
            print(f"    -> 保存失败: {e}")
    
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
    
    def generate_report(self):
        """生成分析报告"""
        report_path = os.path.join(self.output_dir, 'analysis_report.txt')
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("8BitDo固件分析报告\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"原始文件: {self.firmware_path}\n")
                f.write(f"文件大小: {len(self.data)} bytes\n\n")
                
                if self.header_info:
                    f.write("头部信息:\n")
                    f.write(f"  大小: {self.header_info.get('size', 'Unknown')} bytes\n")
                    if 'data' in self.header_info:
                        f.write(f"  十六进制: {binascii.hexlify(self.header_info['data'][:32]).decode()}...\n")
                    f.write("\n")
                
                if self.payload_data:
                    f.write("载荷信息:\n")
                    f.write(f"  大小: {len(self.payload_data)} bytes\n")
                    f.write(f"  熵值: {self._calculate_entropy(self.payload_data[:1000]):.2f}\n")
                    f.write("\n")
                
                f.write("提取的文件:\n")
                for filename in os.listdir(self.output_dir):
                    if filename.endswith('.bin'):
                        filepath = os.path.join(self.output_dir, filename)
                        size = os.path.getsize(filepath)
                        f.write(f"  {filename}: {size} bytes\n")
            
            print(f"\n分析报告已保存: {report_path}")
            
        except Exception as e:
            print(f"生成报告失败: {e}")
    
    def parse_firmware(self):
        """解析固件的主函数"""
        if not self.load_firmware():
            return False
        
        self.create_output_dir()
        
        print(f"\n开始解析8BitDo固件文件...")
        print(f"原始文件: {self.firmware_path}")
        print(f"输出目录: {self.output_dir}")
        
        # 分析头部
        if self.analyze_header():
            # 提取载荷
            extracted_data = self.extract_payload()
            
            if extracted_data:
                print(f"\n✓ 固件解析完成! 共提取 {len(extracted_data)} 种格式的数据")
                self.generate_report()
                return True
            else:
                print("\n✗ 载荷提取失败")
        else:
            print("\n✗ 头部分析失败")
            # 即使头部分析失败，也尝试直接提取
            print("\n尝试直接提取数据...")
            self.payload_data = self.data
            extracted_data = self.extract_payload()
            if extracted_data:
                print(f"\n✓ 直接提取完成! 共提取 {len(extracted_data)} 种格式的数据")
                self.generate_report()
                return True
        
        return False

def main():
    if len(sys.argv) != 2:
        print(f"用法: python3 {sys.argv[0]} <固件文件路径>")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    if not os.path.exists(firmware_path):
        print(f"错误: 文件不存在 - {firmware_path}")
        sys.exit(1)
    
    parser = EbitdoFirmwareParser(firmware_path)
    if parser.parse_firmware():
        print("\n固件解析成功!")
    else:
        print("\n固件解析失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()