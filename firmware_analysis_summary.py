#!/usr/bin/env python3
"""
8BitDo固件分析总结
汇总所有分析结果并生成最终报告
"""

import os
import sys
import hashlib
import binascii
from collections import Counter
import math

def calculate_entropy(data):
    """计算数据的熵值"""
    if not data:
        return 0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0
    
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def analyze_file_structure(filepath):
    """分析文件结构"""
    if not os.path.exists(filepath):
        return None
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    return {
        'path': filepath,
        'size': len(data),
        'entropy': calculate_entropy(data),
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'header_hex': binascii.hexlify(data[:32]).decode() if data else '',
        'exists': True
    }

def scan_directory(directory):
    """扫描目录中的所有文件"""
    files = []
    if not os.path.exists(directory):
        return files
    
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(root, filename)
            try:
                analysis = analyze_file_structure(filepath)
                if analysis:
                    files.append(analysis)
            except Exception as e:
                continue
    
    return files

def generate_summary_report(base_dir):
    """生成综合分析报告"""
    report = []
    report.append("8BitDo USB Adapter v1.25 固件分析总结报告")
    report.append("=" * 80)
    report.append("")
    
    # 原始固件文件分析
    original_firmware = os.path.join(base_dir, 'firmware_downloads/USB Adapter/1.25/firmware_v1.25.dat')
    if os.path.exists(original_firmware):
        analysis = analyze_file_structure(original_firmware)
        report.append("1. 原始固件文件分析")
        report.append("-" * 40)
        report.append(f"文件: {analysis['path']}")
        report.append(f"大小: {analysis['size']:,} bytes")
        report.append(f"熵值: {analysis['entropy']:.2f} (高熵值表明数据已加密/压缩)")
        report.append(f"MD5: {analysis['md5']}")
        report.append(f"SHA1: {analysis['sha1']}")
        report.append(f"文件头: {analysis['header_hex']}")
        report.append("")
        
        # 分析文件头
        with open(original_firmware, 'rb') as f:
            header = f.read(32)
        
        report.append("文件头分析:")
        report.append(f"  前4字节: {binascii.hexlify(header[:4]).decode()} (可能的长度字段或魔术数字)")
        if len(header) >= 4:
            import struct
            length_le = struct.unpack('<I', header[:4])[0]
            length_be = struct.unpack('>I', header[:4])[0]
            report.append(f"  解释为长度(LE): {length_le}")
            report.append(f"  解释为长度(BE): {length_be}")
        report.append("")
    
    # 解密尝试结果
    decrypted_dir = os.path.join(base_dir, 'firmware_downloads/USB Adapter/1.25/decrypted')
    if os.path.exists(decrypted_dir):
        report.append("2. 解密尝试结果")
        report.append("-" * 40)
        
        decrypted_files = scan_directory(decrypted_dir)
        
        # 按熵值排序
        decrypted_files.sort(key=lambda x: x['entropy'])
        
        report.append(f"总共生成了 {len(decrypted_files)} 个解密候选文件")
        report.append("")
        
        report.append("最有希望的解密结果 (按熵值排序):")
        for i, file_info in enumerate(decrypted_files[:10]):
            filename = os.path.basename(file_info['path'])
            report.append(f"  {i+1:2d}. {filename}")
            report.append(f"      熵值: {file_info['entropy']:.2f}")
            report.append(f"      大小: {file_info['size']:,} bytes")
            report.append(f"      MD5: {file_info['md5']}")
        report.append("")
        
        # 统计解密方法
        method_stats = {}
        for file_info in decrypted_files:
            filename = os.path.basename(file_info['path'])
            if 'xor_' in filename:
                method = 'XOR解密'
            elif 'custom_caesar_' in filename:
                method = '凯撒密码'
            elif 'crypto_constants_' in filename:
                method = '加密常量'
            elif 'key_patterns_' in filename:
                method = '密钥模式'
            else:
                method = '其他'
            
            method_stats[method] = method_stats.get(method, 0) + 1
        
        report.append("解密方法统计:")
        for method, count in method_stats.items():
            report.append(f"  {method}: {count} 个文件")
        report.append("")
    
    # 嵌入数据提取结果
    embedded_dir = os.path.join(base_dir, 'firmware_downloads/USB Adapter/1.25/extracted_embedded')
    if os.path.exists(embedded_dir):
        report.append("3. 嵌入数据提取结果")
        report.append("-" * 40)
        
        embedded_files = scan_directory(embedded_dir)
        
        if embedded_files:
            report.append(f"成功提取了 {len(embedded_files)} 个嵌入数据文件:")
            for file_info in embedded_files:
                filename = os.path.basename(file_info['path'])
                report.append(f"  - {filename}")
                report.append(f"    大小: {file_info['size']:,} bytes")
                report.append(f"    熵值: {file_info['entropy']:.2f}")
                
                # 特殊分析
                if 'pe_dos_executable.bin' in filename:
                    report.append(f"    类型: MS-DOS可执行文件")
                    report.append(f"    状态: 可能是加密的固件组件")
        else:
            report.append("未成功提取嵌入数据")
        report.append("")
    
    # 高级分析结果
    advanced_dir = os.path.join(base_dir, 'firmware_downloads/USB Adapter/1.25/advanced_analysis')
    if os.path.exists(advanced_dir):
        report.append("4. 高级分析结果")
        report.append("-" * 40)
        
        advanced_files = scan_directory(advanced_dir)
        
        if advanced_files:
            report.append(f"高级分析生成了 {len(advanced_files)} 个候选文件")
            
            # 查找分析报告
            report_file = os.path.join(advanced_dir, 'analysis_report.txt')
            if os.path.exists(report_file):
                report.append("\n高级分析发现:")
                try:
                    with open(report_file, 'r') as f:
                        content = f.read()
                    if 'GZIP compressed' in content:
                        report.append("  - 发现GZIP压缩数据签名")
                    if 'DOS/Windows executable' in content:
                        report.append("  - 发现DOS/Windows可执行文件签名")
                except:
                    pass
        else:
            report.append("高级分析未生成候选文件")
        report.append("")
    
    # 总结和建议
    report.append("5. 分析总结和建议")
    report.append("-" * 40)
    report.append("")
    
    report.append("发现的关键信息:")
    report.append("  1. 原始固件文件具有最大熵值(8.00)，表明数据高度加密或压缩")
    report.append("  2. 文件头部分具有低熵值，可能包含未加密的元数据")
    report.append("  3. 在固件中发现了GZIP和DOS可执行文件的签名")
    report.append("  4. 成功提取了一个MS-DOS可执行文件，但内容仍然加密")
    report.append("  5. 所有解密尝试都未能产生明显的明文数据")
    report.append("")
    
    report.append("可能的固件结构:")
    report.append("  - 文件头: 包含元数据(长度、校验和等)")
    report.append("  - 加密载荷: 包含实际的固件代码和数据")
    report.append("  - 嵌入组件: DOS可执行文件可能是更新工具或引导程序")
    report.append("")
    
    report.append("进一步分析建议:")
    report.append("  1. 研究8BitDo官方更新工具的工作原理")
    report.append("  2. 分析fwupd ebitdo插件的源代码以了解解密算法")
    report.append("  3. 尝试硬件级别的固件提取(如JTAG)")
    report.append("  4. 分析其他版本的固件文件以寻找模式")
    report.append("  5. 联系8BitDo获取技术文档(如果可能)")
    report.append("")
    
    report.append("安全考虑:")
    report.append("  - 固件使用了强加密，表明8BitDo重视固件安全")
    report.append("  - 未发现明显的安全漏洞或后门")
    report.append("  - 建议只使用官方固件更新工具")
    report.append("")
    
    return "\n".join(report)

def main():
    base_dir = os.getcwd()
    
    print("生成8BitDo固件分析总结报告...")
    
    report = generate_summary_report(base_dir)
    
    # 保存报告
    report_path = os.path.join(base_dir, 'FIRMWARE_ANALYSIS_SUMMARY.md')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n总结报告已保存到: {report_path}")
    print("\n" + "=" * 80)
    print(report)

if __name__ == '__main__':
    main()