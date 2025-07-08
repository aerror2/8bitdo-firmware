#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8BitDo固件载荷解压缩工具
尝试使用多种解压缩算法解压payload文件
"""

import os
import sys
import gzip
import zlib
import zipfile
import tarfile
import bz2
import lzma
import hashlib
from pathlib import Path

try:
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False
    print("警告: lz4 库未安装，跳过 LZ4 解压缩")

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False
    print("警告: zstandard 库未安装，跳过 ZSTD 解压缩")

class PayloadDecompressor:
    def __init__(self, payload_path):
        self.payload_path = payload_path
        self.payload_data = None
        self.output_dir = None
        self.results = []
        
    def load_payload(self):
        """加载载荷文件"""
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
        base_dir = os.path.dirname(self.payload_path)
        self.output_dir = os.path.join(base_dir, 'decompressed')
        os.makedirs(self.output_dir, exist_ok=True)
        print("✓ 输出目录: {}".format(self.output_dir))
    
    def calculate_entropy(self, data):
        """计算数据熵值"""
        if not data:
            return 0.0
        
        import math
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_file_type(self, data):
        """检测文件类型"""
        if not data:
            return "空文件"
        
        # 检查文件头签名
        signatures = {
            b'\x1f\x8b': 'GZIP',
            b'PK\x03\x04': 'ZIP',
            b'PK\x05\x06': 'ZIP (空)',
            b'PK\x07\x08': 'ZIP',
            b'\x42\x5a\x68': 'BZIP2',
            b'\xfd7zXZ\x00': 'XZ',
            b'\x04"M\x18': 'LZ4',
            b'(\xb5/\xfd': 'ZSTD',
            b'\x78\x9c': 'ZLIB (默认压缩)',
            b'\x78\x01': 'ZLIB (最佳速度)',
            b'\x78\xda': 'ZLIB (最佳压缩)',
            b'\x78\x5e': 'ZLIB (无压缩)',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF8': 'GIF',
            b'\x00\x00\x01\x00': 'ICO',
            b'RIFF': 'RIFF (WAV/AVI)',
            b'\x7fELF': 'ELF',
            b'MZ': 'PE/DOS',
            b'\xca\xfe\xba\xbe': 'Mach-O (Fat)',
            b'\xfe\xed\xfa\xce': 'Mach-O (32-bit)',
            b'\xfe\xed\xfa\xcf': 'Mach-O (64-bit)',
        }
        
        for sig, name in signatures.items():
            if data.startswith(sig):
                return name
        
        # 检查是否为文本
        try:
            data[:1000].decode('utf-8')
            return "UTF-8 文本"
        except:
            pass
        
        try:
            data[:1000].decode('ascii')
            return "ASCII 文本"
        except:
            pass
        
        return "未知二进制"
    
    def try_gzip_decompress(self):
        """尝试GZIP解压缩"""
        print("\n=== 尝试 GZIP 解压缩 ===")
        
        methods = [
            ("直接解压", lambda data: gzip.decompress(data)),
            ("跳过头部", lambda data: gzip.decompress(data[10:])),  # 跳过可能的头部
            ("从偏移开始", lambda data: gzip.decompress(data[16:])),
        ]
        
        for method_name, decompress_func in methods:
            try:
                decompressed = decompress_func(self.payload_data)
                if decompressed:
                    self._save_result("gzip_{}".format(method_name.replace(" ", "_")), decompressed, "GZIP - {}".format(method_name))
                    print("  ✓ {} 成功: {} bytes".format(method_name, len(decompressed)))
            except Exception as e:
                print("  ✗ {} 失败: {}".format(method_name, str(e)[:50]))
    
    def try_zlib_decompress(self):
        """尝试ZLIB解压缩"""
        print("\n=== 尝试 ZLIB 解压缩 ===")
        
        methods = [
            ("直接解压", lambda data: zlib.decompress(data)),
            ("跳过头部", lambda data: zlib.decompress(data[2:])),
            ("原始deflate", lambda data: zlib.decompress(data, -zlib.MAX_WBITS)),
            ("从偏移开始", lambda data: zlib.decompress(data[16:], -zlib.MAX_WBITS)),
        ]
        
        for method_name, decompress_func in methods:
            try:
                decompressed = decompress_func(self.payload_data)
                if decompressed:
                    self._save_result("zlib_{}".format(method_name.replace(" ", "_")), decompressed, "ZLIB - {}".format(method_name))
                    print("  ✓ {} 成功: {} bytes".format(method_name, len(decompressed)))
            except Exception as e:
                print("  ✗ {} 失败: {}".format(method_name, str(e)[:50]))
    
    def try_zip_decompress(self):
        """尝试ZIP解压缩"""
        print("\n=== 尝试 ZIP 解压缩 ===")
        
        # 保存为临时文件进行ZIP解压
        temp_zip = os.path.join(self.output_dir, 'temp_payload.zip')
        try:
            with open(temp_zip, 'wb') as f:
                f.write(self.payload_data)
            
            with zipfile.ZipFile(temp_zip, 'r') as zf:
                file_list = zf.namelist()
                print("  发现 {} 个文件: {}".format(len(file_list), file_list[:5]))
                
                for filename in file_list:
                    try:
                        data = zf.read(filename)
                        self._save_result("zip_{}".format(filename.replace('/', '_')), data, "ZIP - {}".format(filename))
                        print("  ✓ 提取文件 {}: {} bytes".format(filename, len(data)))
                    except Exception as e:
                        print("  ✗ 提取文件 {} 失败: {}".format(filename, e))
                        
        except Exception as e:
            print("  ✗ ZIP 解压失败: {}".format(e))
        finally:
            if os.path.exists(temp_zip):
                os.remove(temp_zip)
    
    def try_bzip2_decompress(self):
        """尝试BZIP2解压缩"""
        print("\n=== 尝试 BZIP2 解压缩 ===")
        
        methods = [
            ("直接解压", lambda data: bz2.decompress(data)),
            ("跳过头部", lambda data: bz2.decompress(data[10:])),
        ]
        
        for method_name, decompress_func in methods:
            try:
                decompressed = decompress_func(self.payload_data)
                if decompressed:
                    self._save_result("bzip2_{}".format(method_name.replace(" ", "_")), decompressed, "BZIP2 - {}".format(method_name))
                    print("  ✓ {} 成功: {} bytes".format(method_name, len(decompressed)))
            except Exception as e:
                print("  ✗ {} 失败: {}".format(method_name, str(e)[:50]))
    
    def try_lzma_decompress(self):
        """尝试LZMA/XZ解压缩"""
        print("\n=== 尝试 LZMA/XZ 解压缩 ===")
        
        methods = [
            ("LZMA直接解压", lambda data: lzma.decompress(data)),
            ("XZ格式", lambda data: lzma.decompress(data, format=lzma.FORMAT_XZ)),
            ("LZMA格式", lambda data: lzma.decompress(data, format=lzma.FORMAT_ALONE)),
            ("原始格式", lambda data: lzma.decompress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1}])),
        ]
        
        for method_name, decompress_func in methods:
            try:
                decompressed = decompress_func(self.payload_data)
                if decompressed:
                    self._save_result("lzma_{}".format(method_name.replace(" ", "_")), decompressed, "LZMA - {}".format(method_name))
                    print("  ✓ {} 成功: {} bytes".format(method_name, len(decompressed)))
            except Exception as e:
                print("  ✗ {} 失败: {}".format(method_name, str(e)[:50]))
    
    def try_lz4_decompress(self):
        """尝试LZ4解压缩"""
        if not HAS_LZ4:
            print("\n=== 跳过 LZ4 解压缩 (库未安装) ===")
            return
            
        print("\n=== 尝试 LZ4 解压缩 ===")
        
        methods = [
            ("Frame格式", lambda data: lz4.frame.decompress(data)),
            ("跳过头部", lambda data: lz4.frame.decompress(data[4:])),
        ]
        
        for method_name, decompress_func in methods:
            try:
                decompressed = decompress_func(self.payload_data)
                if decompressed:
                    self._save_result("lz4_{}".format(method_name.replace(" ", "_")), decompressed, "LZ4 - {}".format(method_name))
                    print("  ✓ {} 成功: {} bytes".format(method_name, len(decompressed)))
            except Exception as e:
                print("  ✗ {} 失败: {}".format(method_name, str(e)[:50]))
    
    def try_zstd_decompress(self):
        """尝试ZSTD解压缩"""
        if not HAS_ZSTD:
            print("\n=== 跳过 ZSTD 解压缩 (库未安装) ===")
            return
            
        print("\n=== 尝试 ZSTD 解压缩 ===")
        
        try:
            dctx = zstd.ZstdDecompressor()
            decompressed = dctx.decompress(self.payload_data)
            if decompressed:
                self._save_result("zstd_direct", decompressed, "ZSTD - 直接解压")
                print("  ✓ 直接解压成功: {} bytes".format(len(decompressed)))
        except Exception as e:
            print("  ✗ ZSTD 解压失败: {}".format(e))
    
    def try_tar_decompress(self):
        """尝试TAR解压缩"""
        print("\n=== 尝试 TAR 解压缩 ===")
        
        # 保存为临时文件进行TAR解压
        temp_tar = os.path.join(self.output_dir, 'temp_payload.tar')
        try:
            with open(temp_tar, 'wb') as f:
                f.write(self.payload_data)
            
            # 尝试不同的TAR格式
            formats = ['', 'gz', 'bz2', 'xz']
            for fmt in formats:
                try:
                    mode = 'r' if not fmt else 'r:{}'.format(fmt)
                    with tarfile.open(temp_tar, mode) as tf:
                        members = tf.getnames()
                        print("  发现 {} 个文件 ({}): {}".format(len(members), fmt or 'plain', members[:5]))
                        
                        for member in members:
                            try:
                                data = tf.extractfile(member).read()
                                self._save_result("tar_{}_{}".format(fmt or 'plain', member.replace('/', '_')), data, "TAR({}) - {}".format(fmt or 'plain', member))
                                print("  ✓ 提取文件 {}: {} bytes".format(member, len(data)))
                            except Exception as e:
                                print("  ✗ 提取文件 {} 失败: {}".format(member, e))
                        break  # 成功一种格式就退出
                except Exception as e:
                    if fmt == formats[-1]:  # 最后一个格式也失败
                        print("  ✗ TAR 解压失败: {}".format(e))
                        
        except Exception as e:
            print("  ✗ TAR 处理失败: {}".format(e))
        finally:
            if os.path.exists(temp_tar):
                os.remove(temp_tar)
    
    def _save_result(self, name, data, description):
        """保存解压结果"""
        if not data:
            return
            
        # 保存二进制数据
        output_file = os.path.join(self.output_dir, "{}.bin".format(name))
        with open(output_file, 'wb') as f:
            f.write(data)
        
        # 分析数据
        entropy = self.calculate_entropy(data)
        file_type = self.detect_file_type(data)
        md5_hash = hashlib.md5(data).hexdigest()
        
        result = {
            'name': name,
            'description': description,
            'file_path': output_file,
            'size': len(data),
            'entropy': entropy,
            'file_type': file_type,
            'md5': md5_hash,
            'preview': data[:100].hex() if len(data) >= 100 else data.hex()
        }
        
        self.results.append(result)
        
        # 如果是文本，也保存文本版本
        if 'text' in file_type.lower() or 'utf' in file_type.lower():
            try:
                text_content = data.decode('utf-8', errors='ignore')
                text_file = os.path.join(self.output_dir, "{}.txt".format(name))
                with open(text_file, 'w', encoding='utf-8') as f:
                    f.write(text_content)
                result['text_file'] = text_file
            except:
                pass
    
    def generate_report(self):
        """生成解压缩报告"""
        if not self.results:
            print("\n没有成功的解压缩结果")
            return
        
        print("\n=== 解压缩结果报告 ===")
        print("总共成功解压: {} 个文件".format(len(self.results)))
        
        report_file = os.path.join(self.output_dir, 'decompression_report.txt')
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("8BitDo固件载荷解压缩报告\n")
            f.write("=" * 50 + "\n\n")
            f.write("原始载荷: {}\n".format(self.payload_path))
            f.write("载荷大小: {} bytes\n".format(len(self.payload_data)))
            f.write("成功解压: {} 个文件\n\n".format(len(self.results)))
            
            for i, result in enumerate(self.results, 1):
                f.write("{}. {}\n".format(i, result['description']))
                f.write("   文件: {}\n".format(result['file_path']))
                f.write("   大小: {} bytes\n".format(result['size']))
                f.write("   熵值: {:.2f}\n".format(result['entropy']))
                f.write("   类型: {}\n".format(result['file_type']))
                f.write("   MD5: {}\n".format(result['md5']))
                f.write("   预览: {}...\n".format(result['preview'][:64]))
                if 'text_file' in result:
                    f.write("   文本: {}\n".format(result['text_file']))
                f.write("\n")
        
        print("报告已保存: {}".format(report_file))
        
        # 打印摘要
        for result in self.results:
            print("  ✓ {}: {} bytes, 熵值={:.2f}, 类型={}".format(
                result['description'], result['size'], result['entropy'], result['file_type']))
    
    def run_decompression(self):
        """运行所有解压缩尝试"""
        print("8BitDo固件载荷解压缩工具")
        print("=" * 40)
        
        if not self.load_payload():
            return False
        
        self.create_output_dir()
        
        print("\n=== 原始载荷信息 ===")
        print("文件路径: {}".format(self.payload_path))
        print("文件大小: {} bytes".format(len(self.payload_data)))
        print("原始熵值: {:.2f}".format(self.calculate_entropy(self.payload_data)))
        print("文件类型: {}".format(self.detect_file_type(self.payload_data)))
        print("前32字节: {}".format(self.payload_data[:32].hex()))
        
        # 尝试各种解压缩方法
        self.try_gzip_decompress()
        self.try_zlib_decompress()
        self.try_zip_decompress()
        self.try_bzip2_decompress()
        self.try_lzma_decompress()
        self.try_lz4_decompress()
        self.try_zstd_decompress()
        self.try_tar_decompress()
        
        # 生成报告
        self.generate_report()
        
        return len(self.results) > 0

def main():
    if len(sys.argv) != 2:
        print("用法: python payload_decompressor.py <payload_file>")
        print("示例: python payload_decompressor.py firmware_downloads/USB\\ Adapter/1.25/fwupd_parsed/payload.bin")
        sys.exit(1)
    
    payload_path = sys.argv[1]
    
    if not os.path.exists(payload_path):
        print("错误: 文件不存在 - {}".format(payload_path))
        sys.exit(1)
    
    decompressor = PayloadDecompressor(payload_path)
    success = decompressor.run_decompression()
    
    if success:
        print("\n✓ 解压缩完成，发现可用数据")
    else:
        print("\n✗ 未能成功解压缩任何数据")
        sys.exit(1)

if __name__ == '__main__':
    main()