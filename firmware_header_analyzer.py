#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8BitDo固件头部分析器
分析sub_100006CCA函数的固件头部处理逻辑
"""

import struct
import os
from pathlib import Path

class FirmwareHeaderAnalyzer:
    def __init__(self):
        # 字节重排模式 (xmmword_10002F030)
        self.shuffle_pattern = bytes([
            0x03, 0x02, 0x01, 0x00,  # 字节0-3重排
            0x07, 0x06, 0x05, 0x04,  # 字节4-7重排
            0x0B, 0x0A, 0x09, 0x08,  # 字节8-11重排
            0x0F, 0x0E, 0x0D, 0x0C   # 字节12-15重排
        ])
        
        # 固件类型常量
        self.FIRMWARE_TYPE_261 = 261  # dword_10004A2A4
        self.PID_THRESHOLD_LOW = 0x88  # 136
        self.PID_THRESHOLD_HIGH = 0x1F6  # 502
        self.PID_SPECIAL = 502
        
        # 魔术数字
        self.MAGIC_1 = 12806  # 0x3206
        self.MAGIC_2 = 11720  # 0x2DC8
    
    def read_firmware_header(self, firmware_path):
        """
        读取固件文件的28字节头部
        模拟sub_100006CCA函数的头部读取逻辑
        """
        try:
            with open(firmware_path, 'rb') as f:
                header = f.read(28)
                if len(header) != 28:
                    print(f"错误: 头部长度不足28字节，实际读取{len(header)}字节")
                    return None
                return header
        except Exception as e:
            print(f"读取文件失败: {e}")
            return None
    
    def parse_header_fields(self, header):
        """
        解析28字节头部的各个字段
        """
        if len(header) < 28:
            return None
            
        # 解析前16字节的关键字段
        pid = struct.unpack('<H', header[0:2])[0]  # Product ID (前2字节)
        field_4_7 = struct.unpack('<I', header[4:8])[0]  # 字节4-7
        
        # 解析其他可能的字段
        fields = {
            'pid': pid,
            'bytes_0_1': struct.unpack('<H', header[0:2])[0],
            'bytes_2_3': struct.unpack('<H', header[2:4])[0],
            'bytes_4_7': field_4_7,
            'bytes_8_11': struct.unpack('<I', header[8:12])[0],
            'bytes_12_15': struct.unpack('<I', header[12:16])[0],
            'raw_header': header.hex()
        }
        
        return fields
    
    def apply_byte_shuffle(self, header):
        """
        应用字节重排逻辑 (模拟_mm_shuffle_epi8)
        """
        if len(header) < 16:
            return header
            
        # 只对前16字节进行重排
        original = header[:16]
        shuffled = bytearray(16)
        
        # 应用重排模式
        for i in range(16):
            if i < len(self.shuffle_pattern):
                src_idx = self.shuffle_pattern[i]
                if src_idx < len(original):
                    shuffled[i] = original[src_idx]
        
        # 返回重排后的前16字节 + 原始的剩余字节
        return bytes(shuffled) + header[16:]
    
    def check_firmware_support(self, header, firmware_type=None, firmware_subtype=None):
        """
        检查固件是否支持
        模拟sub_100006CCA中的固件支持检查逻辑
        """
        fields = self.parse_header_fields(header)
        if not fields:
            return False, "头部解析失败"
            
        pid = fields['pid']
        
        # 检查是否为特定固件类型 (261)
        if firmware_type == self.FIRMWARE_TYPE_261:
            if firmware_subtype is not None:
                if firmware_subtype > 1:
                    # 子类型2的特殊检查
                    if firmware_subtype == 2:
                        if (pid >= self.PID_THRESHOLD_HIGH and 
                            (pid != self.PID_SPECIAL or pid < 0x10000)):
                            return True, "固件支持 (类型261, 子类型2, PID检查通过)"
                    return False, f"固件不支持 (类型261, 子类型{firmware_subtype}, PID检查失败)"
                else:
                    # 子类型0或1的检查
                    if pid <= self.PID_THRESHOLD_LOW:
                        return False, f"固件不支持 (类型261, 子类型{firmware_subtype}, PID {pid} <= {self.PID_THRESHOLD_LOW})"
        
        return True, "固件支持检查通过"
    
    def check_magic_numbers(self, device_vid, device_pid):
        """
        检查设备的VID/PID魔术数字
        模拟sub_10002DB0C和sub_10002DBB9的返回值检查
        """
        # 检查是否匹配特定的魔术数字组合
        if device_pid == self.MAGIC_1 and device_vid == self.MAGIC_2:
            return True, "魔术数字匹配，需要应用字节重排"
        else:
            return False, f"魔术数字不匹配 (VID:{device_vid}, PID:{device_pid})"
    
    def analyze_firmware_file(self, firmware_path, device_vid=None, device_pid=None, 
                            firmware_type=None, firmware_subtype=None):
        """
        完整分析固件文件
        """
        print(f"\n=== 分析固件文件: {firmware_path} ===")
        
        # 读取头部
        header = self.read_firmware_header(firmware_path)
        if header is None:
            return
        
        print(f"成功读取28字节头部")
        
        # 解析头部字段
        fields = self.parse_header_fields(header)
        if fields:
            print(f"\n头部字段解析:")
            print(f"  PID (字节0-1): 0x{fields['pid']:04X} ({fields['pid']})")
            print(f"  字节2-3: 0x{fields['bytes_2_3']:04X}")
            print(f"  字节4-7: 0x{fields['bytes_4_7']:08X}")
            print(f"  字节8-11: 0x{fields['bytes_8_11']:08X}")
            print(f"  字节12-15: 0x{fields['bytes_12_15']:08X}")
            print(f"  原始头部: {fields['raw_header'][:56]}...")  # 显示前28字节
        
        # 检查固件支持
        supported, reason = self.check_firmware_support(header, firmware_type, firmware_subtype)
        print(f"\n固件支持检查: {'✓' if supported else '✗'} {reason}")
        
        # 检查魔术数字 (如果提供了设备信息)
        if device_vid is not None and device_pid is not None:
            magic_match, magic_reason = self.check_magic_numbers(device_vid, device_pid)
            print(f"魔术数字检查: {'✓' if magic_match else '✗'} {magic_reason}")
            
            # 如果魔术数字匹配，应用字节重排
            if magic_match:
                shuffled_header = self.apply_byte_shuffle(header)
                shuffled_fields = self.parse_header_fields(shuffled_header)
                print(f"\n字节重排后的头部:")
                print(f"  重排后头部: {shuffled_header[:28].hex()}")
                if shuffled_fields:
                    print(f"  重排后PID: 0x{shuffled_fields['pid']:04X} ({shuffled_fields['pid']})")
        
        return fields
    
    def batch_analyze_directory(self, directory_path):
        """
        批量分析目录中的所有.dat固件文件
        """
        directory = Path(directory_path)
        if not directory.exists():
            print(f"目录不存在: {directory_path}")
            return
        
        dat_files = list(directory.rglob('*.dat'))
        if not dat_files:
            print(f"在目录 {directory_path} 中未找到.dat文件")
            return
        
        print(f"\n=== 批量分析 {len(dat_files)} 个固件文件 ===")
        
        results = []
        for dat_file in dat_files[:10]:  # 限制分析前10个文件
            try:
                result = self.analyze_firmware_file(str(dat_file))
                if result:
                    results.append({
                        'file': str(dat_file),
                        'pid': result['pid'],
                        'fields': result
                    })
            except Exception as e:
                print(f"分析文件 {dat_file} 时出错: {e}")
        
        # 统计分析结果
        if results:
            print(f"\n=== 分析统计 ===")
            pids = [r['pid'] for r in results]
            unique_pids = set(pids)
            print(f"发现 {len(unique_pids)} 个不同的PID: {sorted(unique_pids)}")
            
            # PID分布
            for pid in sorted(unique_pids):
                count = pids.count(pid)
                print(f"  PID 0x{pid:04X} ({pid}): {count} 个文件")

def main():
    analyzer = FirmwareHeaderAnalyzer()
    
    # 分析固件下载目录
    firmware_dir = "/Volumes/evo2T/8bitdo-firmware/firmware_downloads"
    
    if os.path.exists(firmware_dir):
        print("开始批量分析固件文件...")
        analyzer.batch_analyze_directory(firmware_dir)
    else:
        print(f"固件目录不存在: {firmware_dir}")
    
    # 示例: 分析特定文件
    print("\n=== 示例分析 ===")
    
    # 模拟不同的设备和固件类型
    test_cases = [
        {
            'device_vid': 11720,  # MAGIC_2
            'device_pid': 12806,  # MAGIC_1
            'firmware_type': 261,
            'firmware_subtype': 1,
            'description': '魔术数字匹配的设备'
        },
        {
            'device_vid': 1234,
            'device_pid': 5678,
            'firmware_type': 261,
            'firmware_subtype': 2,
            'description': '普通设备'
        }
    ]
    
    # 查找一个示例固件文件进行测试
    firmware_dir_path = Path(firmware_dir)
    if firmware_dir_path.exists():
        sample_files = list(firmware_dir_path.rglob('*.dat'))[:1]
        if sample_files:
            sample_file = sample_files[0]
            print(f"\n使用示例文件: {sample_file}")
            
            for case in test_cases:
                print(f"\n--- {case['description']} ---")
                analyzer.analyze_firmware_file(
                    str(sample_file),
                    device_vid=case['device_vid'],
                    device_pid=case['device_pid'],
                    firmware_type=case['firmware_type'],
                    firmware_subtype=case['firmware_subtype']
                )

if __name__ == "__main__":
    main()