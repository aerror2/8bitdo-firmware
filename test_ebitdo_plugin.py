#!/usr/bin/env python3
"""
8BitDo插件测试脚本
验证fwupd的ebitdo插件是否正确安装和工作
"""

import subprocess
import sys
import json

def run_command(cmd):
    """运行命令并返回结果"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def test_fwupd_version():
    """测试fwupd版本"""
    print("1. 测试fwupd版本...")
    code, stdout, stderr = run_command("fwupdtool --version")
    if code == 0:
        print("   ✓ fwupd已安装")
        # 提取版本信息
        for line in stdout.split('\n'):
            if 'org.freedesktop.fwupd' in line and 'runtime' in line:
                version = line.split()[-1]
                print(f"   版本: {version}")
                break
        return True
    else:
        print("   ✗ fwupd未安装或无法运行")
        return False

def test_ebitdo_plugin():
    """测试ebitdo插件"""
    print("\n2. 测试ebitdo插件...")
    code, stdout, stderr = run_command("fwupdtool get-plugins | grep -A 5 -B 2 ebitdo")
    if code == 0 and 'ebitdo:' in stdout:
        print("   ✓ ebitdo插件已安装")
        if 'Ready' in stdout:
            print("   ✓ ebitdo插件状态: Ready")
            return True
        else:
            print("   ⚠ ebitdo插件状态异常")
            print(f"   状态信息: {stdout}")
            return False
    else:
        print("   ✗ ebitdo插件未找到")
        return False

def test_ebitdo_device_detection():
    """测试ebitdo设备检测"""
    print("\n3. 测试ebitdo设备检测...")
    code, stdout, stderr = run_command("fwupdtool get-devices --plugins ebitdo")
    if code == 0:
        print("   ✓ ebitdo插件可以正常运行")
        if 'No detected devices' in stdout:
            print("   ℹ 当前没有连接8BitDo设备")
        else:
            print("   ✓ 检测到8BitDo设备:")
            print(f"   {stdout}")
        return True
    else:
        print("   ✗ ebitdo插件运行失败")
        print(f"   错误: {stderr}")
        return False

def test_firmware_install_capability():
    """测试固件安装能力"""
    print("\n4. 测试固件安装能力...")
    # 检查是否可以使用install命令
    code, stdout, stderr = run_command("fwupdtool install --help")
    if code == 0:
        print("   ✓ 支持固件安装功能")
        return True
    else:
        print("   ✗ 固件安装功能不可用")
        return False

def show_plugin_info():
    """显示插件详细信息"""
    print("\n5. 插件详细信息...")
    code, stdout, stderr = run_command("fwupdtool get-plugins --verbose | grep -A 10 -B 2 ebitdo")
    if code == 0:
        print("   ebitdo插件详细信息:")
        print(f"   {stdout}")
    
    # 显示所有可用插件
    print("\n   所有可用插件:")
    code, stdout, stderr = run_command("fwupdtool get-plugins | grep ':'")
    if code == 0:
        plugins = [line.strip().replace(':', '') for line in stdout.split('\n') if line.strip().endswith(':')]
        for plugin in plugins:
            if plugin:
                print(f"   - {plugin}")

def main():
    print("8BitDo插件测试报告")
    print("=" * 50)
    
    tests = [
        test_fwupd_version,
        test_ebitdo_plugin,
        test_ebitdo_device_detection,
        test_firmware_install_capability
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    show_plugin_info()
    
    print("\n" + "=" * 50)
    print(f"测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("\n🎉 8BitDo插件已正确安装并可以使用!")
        print("\n使用说明:")
        print("1. 连接8BitDo设备到USB端口")
        print("2. 运行: fwupdtool get-devices --plugins ebitdo")
        print("3. 如果检测到设备，可以使用以下命令安装固件:")
        print("   fwupdtool install firmware_file.dat --plugins ebitdo")
    else:
        print("\n⚠️  部分测试失败，请检查fwupd安装")
    
    print("\n注意事项:")
    print("- 确保8BitDo设备处于固件更新模式")
    print("- 某些设备可能需要特定的USB连接方式")
    print("- 建议使用官方固件文件")

if __name__ == '__main__':
    main()