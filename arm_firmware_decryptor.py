#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import hashlib
import binascii
from collections import Counter

class ARMFirmwareDecryptor:
    def __init__(self, payload_path, target_address=0x08003400):
        self.payload_path = payload_path
        self.target_address = target_address
        self.payload_data = None
        self.output_dir = "arm_decrypted_results"
        self.load_payload()
        self.create_output_dir()
    
    def load_payload(self):
        """加载载荷文件"""
        try:
            with open(self.payload_path, 'rb') as f:
                self.payload_data = f.read()
            print("✓ 载荷文件加载成功: {} bytes".format(len(self.payload_data)))
            print("目标地址: 0x{:08x}".format(self.target_address))
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
    
    def check_arm_signatures(self, data):
        """检查ARM相关的文件签名"""
        signatures = []
        
        # ARM向量表检查（前8个字节应该是栈指针和复位向量）
        if len(data) >= 8:
            stack_ptr = struct.unpack('<I', data[0:4])[0]
            reset_vector = struct.unpack('<I', data[4:8])[0]
            
            # 检查栈指针是否在合理范围内（通常在RAM区域）
            if 0x20000000 <= stack_ptr <= 0x20020000:
                signatures.append("ARM Stack Pointer")
            
            # 检查复位向量是否在Flash区域且为奇数（Thumb模式）
            if 0x08000000 <= reset_vector <= 0x08100000 and reset_vector & 1:
                signatures.append("ARM Reset Vector (Thumb)")
        
        # 检查ARM指令模式
        if self.check_arm_instructions(data):
            signatures.append("ARM Instructions")
        
        return signatures
    
    def check_arm_instructions(self, data):
        """检查是否包含ARM指令"""
        if len(data) < 100:
            return False
        
        # 统计可能的ARM Thumb指令
        thumb_patterns = 0
        
        for i in range(0, min(1000, len(data) - 1), 2):
            if i + 1 < len(data):
                instruction = struct.unpack('<H', data[i:i+2])[0]
                
                # 检查常见的Thumb指令模式
                if (
                    (instruction & 0xF800) == 0x4800 or  # LDR (literal)
                    (instruction & 0xF800) == 0x4000 or  # Data processing
                    (instruction & 0xE000) == 0x2000 or  # MOV/CMP immediate
                    (instruction & 0xF000) == 0xD000 or  # Conditional branch
                    (instruction & 0xF800) == 0xE000     # Unconditional branch
                ):
                    thumb_patterns += 1
        
        # 如果超过10%的指令看起来像Thumb指令，认为可能是ARM代码
        return thumb_patterns > 50
    
    def try_address_based_xor(self):
        """尝试基于地址的XOR解密"""
        print("\n=== 尝试基于地址的XOR解密 ===")
        
        results = []
        
        # 使用目标地址的不同部分作为密钥
        address_keys = [
            # 完整地址
            struct.pack('<I', self.target_address),
            struct.pack('>I', self.target_address),
            
            # 地址的高16位和低16位
            struct.pack('<H', self.target_address & 0xFFFF),
            struct.pack('<H', (self.target_address >> 16) & 0xFFFF),
            struct.pack('>H', self.target_address & 0xFFFF),
            struct.pack('>H', (self.target_address >> 16) & 0xFFFF),
            
            # 地址的字节
            bytes([self.target_address & 0xFF]),
            bytes([(self.target_address >> 8) & 0xFF]),
            bytes([(self.target_address >> 16) & 0xFF]),
            bytes([(self.target_address >> 24) & 0xFF]),
            
            # 地址的变换
            struct.pack('<I', self.target_address ^ 0xFFFFFFFF),
            struct.pack('<I', self.target_address + 0x1000),
            struct.pack('<I', self.target_address - 0x1000),
        ]
        
        for key in address_keys:
            try:
                decrypted = self.xor_decrypt(self.payload_data, key)
                entropy = self.calculate_entropy(decrypted)
                strings = self.extract_strings(decrypted)
                arm_sigs = self.check_arm_signatures(decrypted)
                
                # ARM固件的判断标准
                if entropy < 7.0 and (len(strings) > 5 or arm_sigs):
                    result = {
                        'key': key,
                        'key_hex': binascii.hexlify(key).decode(),
                        'entropy': entropy,
                        'strings_count': len(strings),
                        'strings': strings[:10],
                        'arm_signatures': arm_sigs,
                        'data': decrypted
                    }
                    results.append(result)
                    
                    print("✓ 地址密钥 {} 解密成功! 熵值: {:.2f}, 字符串: {}, ARM签名: {}".format(
                        binascii.hexlify(key).decode(), entropy, len(strings), arm_sigs))
            
            except Exception as e:
                continue
        
        return results
    
    def try_incremental_xor(self):
        """尝试递增XOR解密"""
        print("\n=== 尝试递增XOR解密 ===")
        
        results = []
        
        # 尝试不同的递增模式
        patterns = [
            # 基于地址的递增
            lambda i: ((self.target_address + i) >> 0) & 0xFF,
            lambda i: ((self.target_address + i) >> 8) & 0xFF,
            lambda i: ((self.target_address + i) >> 16) & 0xFF,
            lambda i: ((self.target_address + i) >> 24) & 0xFF,
            
            # 简单递增
            lambda i: i & 0xFF,
            lambda i: (i + 1) & 0xFF,
            lambda i: (i * 2) & 0xFF,
            lambda i: (i ^ 0xFF) & 0xFF,
            
            # 基于位置的模式
            lambda i: ((i + self.target_address) ^ i) & 0xFF,
            lambda i: ((i << 1) ^ (i >> 1)) & 0xFF,
            
            # 周期性模式
            lambda i: ((self.target_address >> (i % 4 * 8)) & 0xFF),
        ]
        
        for pattern_idx, pattern_func in enumerate(patterns):
            try:
                decrypted = bytearray()
                for i, byte in enumerate(self.payload_data):
                    key_byte = pattern_func(i)
                    decrypted.append(byte ^ key_byte)
                
                entropy = self.calculate_entropy(decrypted)
                strings = self.extract_strings(decrypted)
                arm_sigs = self.check_arm_signatures(decrypted)
                
                if entropy < 7.0 and (len(strings) > 5 or arm_sigs):
                    result = {
                        'pattern': pattern_idx,
                        'entropy': entropy,
                        'strings_count': len(strings),
                        'strings': strings[:10],
                        'arm_signatures': arm_sigs,
                        'data': bytes(decrypted)
                    }
                    results.append(result)
                    
                    print("✓ 递增模式 {} 解密成功! 熵值: {:.2f}, 字符串: {}, ARM签名: {}".format(
                        pattern_idx, entropy, len(strings), arm_sigs))
            
            except Exception as e:
                continue
        
        return results
    
    def try_checksum_based_xor(self):
        """尝试基于校验和的XOR解密"""
        print("\n=== 尝试基于校验和的XOR解密 ===")
        
        results = []
        
        # 计算不同的校验和
        checksums = [
            sum(self.payload_data) & 0xFF,
            sum(self.payload_data) & 0xFFFF,
            sum(self.payload_data) & 0xFFFFFFFF,
            len(self.payload_data) & 0xFF,
            len(self.payload_data) & 0xFFFF,
            (sum(self.payload_data) ^ len(self.payload_data)) & 0xFF,
        ]
        
        for checksum in checksums:
            # 尝试不同长度的密钥
            for key_len in [1, 2, 4]:
                try:
                    if key_len == 1:
                        key = bytes([checksum & 0xFF])
                    elif key_len == 2:
                        key = struct.pack('<H', checksum & 0xFFFF)
                    else:
                        key = struct.pack('<I', checksum & 0xFFFFFFFF)
                    
                    decrypted = self.xor_decrypt(self.payload_data, key)
                    entropy = self.calculate_entropy(decrypted)
                    strings = self.extract_strings(decrypted)
                    arm_sigs = self.check_arm_signatures(decrypted)
                    
                    if entropy < 7.0 and (len(strings) > 5 or arm_sigs):
                        result = {
                            'key': key,
                            'key_hex': binascii.hexlify(key).decode(),
                            'checksum': checksum,
                            'entropy': entropy,
                            'strings_count': len(strings),
                            'strings': strings[:10],
                            'arm_signatures': arm_sigs,
                            'data': decrypted
                        }
                        results.append(result)
                        
                        print("✓ 校验和密钥 {} 解密成功! 熵值: {:.2f}, 字符串: {}, ARM签名: {}".format(
                            binascii.hexlify(key).decode(), entropy, len(strings), arm_sigs))
                
                except Exception as e:
                    continue
        
        return results
    
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
                f.write("目标地址: 0x{:08x}\n".format(self.target_address))
                f.write("解密方法: {}\n".format(method_name))
                
                if 'key' in result:
                    f.write("密钥: {}\n".format(result['key_hex']))
                if 'pattern' in result:
                    f.write("模式: {}\n".format(result['pattern']))
                if 'checksum' in result:
                    f.write("校验和: 0x{:x}\n".format(result['checksum']))
                
                f.write("数据大小: {} bytes\n".format(len(result['data'])))
                f.write("熵值: {:.2f}\n".format(result['entropy']))
                f.write("字符串数量: {}\n".format(result['strings_count']))
                
                if result['arm_signatures']:
                    f.write("ARM签名: {}\n".format(', '.join(result['arm_signatures'])))
                
                if result['strings']:
                    f.write("\n发现的字符串:\n")
                    for s in result['strings']:
                        f.write("  {}\n".format(s))
                
                # 显示前64字节的十六进制
                f.write("\n前64字节 (十六进制):\n")
                hex_data = binascii.hexlify(result['data'][:64]).decode()
                for j in range(0, len(hex_data), 32):
                    f.write("  {}\n".format(hex_data[j:j+32]))
            
            print("  保存: {} (数据) 和 {} (报告)".format(filepath, report_filepath))
    
    def run_decryption(self):
        """运行解密过程"""
        print("=== ARM固件解密器 ===")
        print("文件: {}".format(self.payload_path))
        print("大小: {} bytes".format(len(self.payload_data)))
        print("目标地址: 0x{:08x}".format(self.target_address))
        
        # 原始数据信息
        entropy = self.calculate_entropy(self.payload_data)
        print("原始熵值: {:.2f}".format(entropy))
        
        all_results = []
        
        # 尝试基于地址的XOR
        address_results = self.try_address_based_xor()
        if address_results:
            all_results.extend(address_results)
            self.save_results(address_results, "Address_XOR")
        
        # 尝试递增XOR
        incremental_results = self.try_incremental_xor()
        if incremental_results:
            all_results.extend(incremental_results)
            self.save_results(incremental_results, "Incremental_XOR")
        
        # 尝试基于校验和的XOR
        checksum_results = self.try_checksum_based_xor()
        if checksum_results:
            all_results.extend(checksum_results)
            self.save_results(checksum_results, "Checksum_XOR")
        
        if all_results:
            print("\n✓ 找到 {} 个可能的解密结果".format(len(all_results)))
            print("结果已保存到: {}".format(os.path.abspath(self.output_dir)))
            
            # 显示最佳结果
            best_result = min(all_results, key=lambda x: x['entropy'])
            print("\n最佳结果 (最低熵值 {:.2f}):".format(best_result['entropy']))
            if 'key' in best_result:
                print("  密钥: {}".format(best_result['key_hex']))
            if best_result['arm_signatures']:
                print("  ARM签名: {}".format(', '.join(best_result['arm_signatures'])))
            if best_result['strings']:
                print("  发现字符串: {}".format(', '.join(best_result['strings'][:5])))
        else:
            print("\n✗ 未找到有效的解密结果")
            print("建议尝试其他解密方法或分析工具")

def main():
    if len(sys.argv) < 2:
        print("用法: {} <payload_file> [target_address]".format(sys.argv[0]))
        print("默认目标地址: 0x08003400")
        sys.exit(1)
    
    payload_file = sys.argv[1]
    if not os.path.exists(payload_file):
        print("错误: 文件不存在 - {}".format(payload_file))
        sys.exit(1)
    
    target_address = 0x08003400
    if len(sys.argv) > 2:
        try:
            target_address = int(sys.argv[2], 0)  # 支持十六进制输入
        except ValueError:
            print("错误: 无效的目标地址 - {}".format(sys.argv[2]))
            sys.exit(1)
    
    decryptor = ARMFirmwareDecryptor(payload_file, target_address)
    decryptor.run_decryption()

if __name__ == "__main__":
    main()