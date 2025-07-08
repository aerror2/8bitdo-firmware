#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8BitDo固件更新程序 sub_100006CCA 函数完整分析
该函数是固件头部处理的核心函数，负责:
1. 读取28字节固件头部
2. 验证固件兼容性
3. 应用字节重排（如果需要）
4. 调用数据传输函数
"""

import struct
import os
from pathlib import Path

class Sub100006CCAAnalyzer:
    def __init__(self):
        # 全局变量和常量定义
        self.qword_100075DB0 = None  # SHIDBootPro2实例指针
        self.xmmword_10004A370 = bytearray(16)  # 临时读取缓冲区
        self.xmmword_10004A350 = bytearray(16)  # 处理后的头部数据
        self.dword_10004A2A4 = 0  # 固件类型标识
        self.dword_10004A2A8 = 0  # 固件子类型
        self.dword_10004A3A8 = 0  # 状态标志
        
        # 字节重排模式 (xmmword_10002F030)
        # 原始值: 0xC0D0E0F08090A0B0405060700010203LL
        self.xmmword_10002F030 = bytes([
            0x03, 0x02, 0x01, 0x00,  # 字节0-3 -> 3,2,1,0
            0x07, 0x06, 0x05, 0x04,  # 字节4-7 -> 7,6,5,4
            0x0B, 0x0A, 0x09, 0x08,  # 字节8-11 -> 11,10,9,8
            0x0F, 0x0E, 0x0D, 0x0C   # 字节12-15 -> 15,14,13,12
        ])
        
        # 常量定义
        self.FIRMWARE_TYPE_261 = 261
        self.PID_THRESHOLD_LOW = 0x88   # 136
        self.PID_THRESHOLD_HIGH = 0x1F6 # 502
        self.PID_SPECIAL = 502
        self.MAGIC_VID = 11720  # 0x2DC8
        self.MAGIC_PID = 12806  # 0x3206
        
    def simulate_objc_msgSend_filePath(self):
        """
        模拟 objc_msgSend(qword_100075DB0, "filePath")
        返回固件文件路径
        """
        # 在实际应用中，这会返回SHIDBootPro2实例的filePath属性
        return "/path/to/firmware.dat"  # 占位符
    
    def simulate_NSInputStream_operations(self, file_path):
        """
        模拟NSInputStream的文件操作
        """
        try:
            with open(file_path, 'rb') as f:
                # 读取28字节到xmmword_10004A370
                data = f.read(28)
                if len(data) != 28:
                    return False, "读取长度不足28字节"
                
                # 将数据存储到xmmword_10004A370（模拟）
                self.xmmword_10004A370[:len(data)] = data
                return True, "读取成功"
        except Exception as e:
            return False, f"文件读取错误: {e}"
    
    def process_header_data(self):
        """
        处理头部数据
        模拟以下C代码:
        LODWORD(xmmword_10004A350) = xmmword_10004A370;
        _mm_storel_epi64(...)
        HIDWORD(xmmword_10004A350) = 0;
        """
        # 复制前4字节
        self.xmmword_10004A350[0:4] = self.xmmword_10004A370[0:4]
        
        # 复制字节4-7，并进行shuffle操作
        # _mm_shuffle_epi32(_mm_loadl_epi64((const __m128i *)((char *)&xmmword_10004A370 + 4)), 225)
        # 225 = 0xE1，表示shuffle模式
        bytes_4_7 = self.xmmword_10004A370[4:8]
        # 简化的shuffle操作（实际的shuffle更复杂）
        self.xmmword_10004A350[4:8] = bytes_4_7
        
        # 设置高32位为0
        self.xmmword_10004A350[12:16] = b'\x00\x00\x00\x00'
        
        return self.xmmword_10004A350
    
    def check_firmware_compatibility(self):
        """
        检查固件兼容性
        模拟固件类型和PID检查逻辑
        """
        # 获取PID（前2字节）
        pid = struct.unpack('<H', self.xmmword_10004A370[0:2])[0]
        
        print(f"检查固件兼容性:")
        print(f"  PID: 0x{pid:04X} ({pid})")
        print(f"  固件类型: {self.dword_10004A2A4}")
        print(f"  固件子类型: {self.dword_10004A2A8}")
        
        # 检查是否为类型261
        if self.dword_10004A2A4 != self.FIRMWARE_TYPE_261:
            print(f"  → 跳转到LABEL_16（非261类型）")
            return True, "LABEL_16"
        
        # 检查子类型
        if self.dword_10004A2A8 > 1:
            if self.dword_10004A2A8 != 2:
                print(f"  → 跳转到LABEL_16（子类型不是2）")
                return True, "LABEL_16"
            
            # 子类型2的特殊检查
            if (pid >= self.PID_THRESHOLD_HIGH and 
                (pid != self.PID_SPECIAL or pid < 0x10000)):
                print(f"  → 跳转到LABEL_16（子类型2，PID检查通过）")
                return True, "LABEL_16"
            else:
                print(f"  → 跳转到LABEL_14（子类型2，PID检查失败）")
                return False, "LABEL_14"
        else:
            # 子类型0或1
            if pid <= self.PID_THRESHOLD_LOW:
                print(f"  → 跳转到LABEL_14（PID {pid} <= {self.PID_THRESHOLD_LOW}）")
                return False, "LABEL_14"
        
        print(f"  → 跳转到LABEL_16（默认通过）")
        return True, "LABEL_16"
    
    def handle_unsupported_firmware(self):
        """
        处理不支持的固件
        模拟LABEL_14的逻辑
        """
        print("\n=== LABEL_14: 处理不支持的固件 ===")
        print("调用 SHIDBootNotSupportFirmware 委托方法")
        return False
    
    def simulate_sub_10002DB0C(self, device_handle):
        """
        模拟sub_10002DB0C函数 - 获取设备VendorID
        """
        # 在实际中，这会调用IOHIDDeviceGetProperty获取VendorID
        return self.MAGIC_VID  # 返回模拟的VID
    
    def simulate_sub_10002DBB9(self, device_handle):
        """
        模拟sub_10002DBB9函数 - 获取设备ProductID
        """
        # 在实际中，这会调用IOHIDDeviceGetProperty获取ProductID
        return self.MAGIC_PID  # 返回模拟的PID
    
    def apply_byte_shuffle(self):
        """
        应用字节重排
        模拟_mm_shuffle_epi8操作
        """
        print("\n应用字节重排:")
        print(f"  原始数据: {self.xmmword_10004A370[:16].hex()}")
        
        # 应用shuffle
        shuffled = bytearray(16)
        for i in range(16):
            src_idx = self.xmmword_10002F030[i]
            if src_idx < 16:
                shuffled[i] = self.xmmword_10004A370[src_idx]
        
        # 更新xmmword_10004A370
        self.xmmword_10004A370[:16] = shuffled
        
        # 复制字节12-15到v13
        v13 = self.xmmword_10004A370[12:16]
        
        print(f"  重排后数据: {self.xmmword_10004A370[:16].hex()}")
        print(f"  v13 (字节12-15): {v13.hex()}")
        
        return shuffled, v13
    
    def simulate_sub_10002DF67(self, device_handle, cmd, flag, data_ptr, data_len):
        """
        模拟sub_10002DF67函数 - 数据传输函数
        """
        print(f"\n=== 调用 sub_10002DF67 ===")
        print(f"  设备句柄: {device_handle}")
        print(f"  命令: {cmd}")
        print(f"  标志: {flag}")
        print(f"  数据长度: {data_len}")
        if data_len > 0 and data_ptr:
            print(f"  数据: {data_ptr[:min(data_len, 32)].hex()}...")
        
        # 在实际中，这会通过IOHIDDeviceSetReport发送数据到设备
        return True
    
    def execute_sub_100006CCA(self, device_handle, firmware_path, 
                             firmware_type=261, firmware_subtype=1):
        """
        执行完整的sub_100006CCA函数逻辑
        """
        print(f"\n=== 执行 sub_100006CCA 函数 ===")
        print(f"固件文件: {firmware_path}")
        print(f"固件类型: {firmware_type}")
        print(f"固件子类型: {firmware_subtype}")
        
        # 设置全局变量
        self.dword_10004A2A4 = firmware_type
        self.dword_10004A2A8 = firmware_subtype
        
        # 步骤1: 检查文件路径
        file_path = self.simulate_objc_msgSend_filePath()
        if not file_path:
            print("错误: 文件路径为空")
            return 0
        
        # 使用实际的固件路径
        file_path = firmware_path
        
        # 步骤2: 创建NSInputStream并读取28字节
        print(f"\n步骤1: 读取28字节头部")
        success, message = self.simulate_NSInputStream_operations(file_path)
        if not success:
            print(f"错误: {message}")
            return 0
        
        print(f"成功读取28字节: {self.xmmword_10004A370[:28].hex()}")
        
        # 步骤3: 处理头部数据
        print(f"\n步骤2: 处理头部数据")
        processed_header = self.process_header_data()
        print(f"处理后的头部: {processed_header[:16].hex()}")
        
        # 步骤4: 检查固件兼容性
        print(f"\n步骤3: 检查固件兼容性")
        compatible, label = self.check_firmware_compatibility()
        
        if not compatible and label == "LABEL_14":
            return self.handle_unsupported_firmware()
        
        # 步骤5: LABEL_16 - 关闭文件并继续处理
        print(f"\n=== LABEL_16: 继续处理 ===")
        print("关闭文件流")
        self.dword_10004A3A8 = 1  # 设置状态标志
        
        # 步骤6: 获取设备VID/PID
        print(f"\n步骤4: 获取设备信息")
        device_vid = self.simulate_sub_10002DB0C(device_handle)
        device_pid = self.simulate_sub_10002DBB9(device_handle)
        print(f"设备VID: {device_vid} (0x{device_vid:04X})")
        print(f"设备PID: {device_pid} (0x{device_pid:04X})")
        
        # 步骤7: 检查魔术数字并决定是否应用字节重排
        print(f"\n步骤5: 检查魔术数字")
        if device_pid == self.MAGIC_PID and device_vid == self.MAGIC_VID:
            print(f"魔术数字匹配，应用字节重排")
            shuffled_data, v13 = self.apply_byte_shuffle()
            
            # 使用重排后的数据
            data_to_send = self.xmmword_10004A370[:28]
        else:
            print(f"魔术数字不匹配，使用原始头部数据")
            # 使用xmmword_10004A350的数据
            data_to_send = self.xmmword_10004A350[:28]
        
        # 步骤8: 调用数据传输函数
        print(f"\n步骤6: 发送数据到设备")
        result = self.simulate_sub_10002DF67(
            device_handle, 
            151,  # 命令码
            1,    # 标志
            data_to_send, 
            0x1C  # 28字节
        )
        
        if result:
            print(f"\n✓ sub_100006CCA 执行成功")
            return 1
        else:
            print(f"\n✗ sub_100006CCA 执行失败")
            return 0

def main():
    analyzer = Sub100006CCAAnalyzer()
    
    # 查找一个示例固件文件
    firmware_dir = "/Volumes/evo2T/8bitdo-firmware/firmware_downloads"
    firmware_dir_path = Path(firmware_dir)
    
    if firmware_dir_path.exists():
        sample_files = list(firmware_dir_path.rglob('*.dat'))[:1]
        if sample_files:
            sample_file = sample_files[0]
            print(f"使用示例固件文件: {sample_file}")
            
            # 测试不同的场景
            test_cases = [
                {
                    'name': '魔术数字匹配的设备（需要字节重排）',
                    'firmware_type': 261,
                    'firmware_subtype': 1
                },
                {
                    'name': '普通设备（不需要字节重排）',
                    'firmware_type': 100,  # 非261类型
                    'firmware_subtype': 0
                },
                {
                    'name': '不支持的固件（PID过低）',
                    'firmware_type': 261,
                    'firmware_subtype': 1
                }
            ]
            
            for i, case in enumerate(test_cases):
                print(f"\n{'='*60}")
                print(f"测试案例 {i+1}: {case['name']}")
                print(f"{'='*60}")
                
                # 为第三个测试案例修改PID阈值检查
                if i == 2:
                    # 临时修改阈值来模拟PID过低的情况
                    original_threshold = analyzer.PID_THRESHOLD_LOW
                    analyzer.PID_THRESHOLD_LOW = 1000  # 设置一个很高的阈值
                
                result = analyzer.execute_sub_100006CCA(
                    device_handle=0x12345678,  # 模拟设备句柄
                    firmware_path=str(sample_file),
                    firmware_type=case['firmware_type'],
                    firmware_subtype=case['firmware_subtype']
                )
                
                # 恢复原始阈值
                if i == 2:
                    analyzer.PID_THRESHOLD_LOW = original_threshold
                
                print(f"\n结果: {'成功' if result else '失败'}")
        else:
            print(f"在目录 {firmware_dir} 中未找到.dat文件")
    else:
        print(f"固件目录不存在: {firmware_dir}")

if __name__ == "__main__":
    main()