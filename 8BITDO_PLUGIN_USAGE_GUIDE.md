# 8BitDo插件使用指南

## 插件状态确认

✅ **8BitDo插件已成功安装并可以使用！**

- fwupd版本: 2.0.12
- ebitdo插件状态: Ready
- 插件功能: 正常

## 基本使用方法

### 1. 检查插件状态
```bash
# 查看所有插件
fwupdtool get-plugins

# 查看ebitdo插件状态
fwupdtool get-plugins | grep -A 5 ebitdo
```

### 2. 检测8BitDo设备
```bash
# 检测连接的8BitDo设备
fwupdtool get-devices --plugins ebitdo

# 显示所有设备信息
fwupdtool get-devices --show-all --plugins ebitdo
```

### 3. 安装固件
```bash
# 安装固件到检测到的设备
fwupdtool install firmware_file.dat --plugins ebitdo

# 强制安装（跳过版本检查）
fwupdtool install firmware_file.dat --plugins ebitdo --force

# 安装时显示详细信息
fwupdtool install firmware_file.dat --plugins ebitdo --verbose
```

### 4. 获取设备信息
```bash
# 获取设备详细信息
fwupdtool get-details DEVICE_ID --plugins ebitdo

# 获取设备固件版本
fwupdtool get-firmware-types DEVICE_ID --plugins ebitdo
```

## 设备准备步骤

### 对于8BitDo USB适配器:
1. **进入固件更新模式**:
   - 断开USB连接
   - 按住配对按钮
   - 插入USB线缆
   - 保持按住配对按钮3-5秒
   - 释放按钮

2. **验证设备模式**:
   - 设备LED应该显示特定的闪烁模式
   - 运行 `fwupdtool get-devices --plugins ebitdo` 应该能检测到设备

### 对于8BitDo手柄:
1. **进入固件更新模式**:
   - 关闭手柄
   - 同时按住 `Start + Y` 按钮
   - 连接USB线缆
   - 保持按住按钮直到进入更新模式

## 固件文件准备

### 使用现有固件文件
```bash
# 使用已下载的固件文件
fwupdtool install firmware_downloads/USB\ Adapter/1.25/firmware_v1.25.dat --plugins ebitdo
```

### 验证固件文件
```bash
# 检查固件文件信息
file firmware_v1.25.dat

# 查看文件大小和校验和
ls -la firmware_v1.25.dat
md5sum firmware_v1.25.dat
```

## 故障排除

### 常见问题

1. **设备未检测到**
   ```bash
   # 检查USB连接
   lsusb | grep -i 8bitdo
   
   # 检查设备权限
   sudo fwupdtool get-devices --plugins ebitdo
   ```

2. **固件安装失败**
   ```bash
   # 使用强制模式
   fwupdtool install firmware.dat --plugins ebitdo --force
   
   # 检查设备是否在正确模式
   fwupdtool get-devices --plugins ebitdo --verbose
   ```

3. **权限问题**
   ```bash
   # 添加用户到相关组（Linux）
   sudo usermod -a -G plugdev $USER
   
   # 重新登录或重启
   ```

### 调试命令

```bash
# 详细日志模式
fwupdtool --verbose get-devices --plugins ebitdo

# JSON输出格式
fwupdtool --json get-devices --plugins ebitdo

# 显示所有信息
fwupdtool get-devices --show-all --plugins ebitdo
```

## 支持的设备

根据fwupd文档，ebitdo插件支持以下8BitDo设备:
- USB Adapter (各版本)
- USB Adapter 2
- USB Adapter for PS Classic
- Pro 2 系列手柄
- SN30 Pro+ 手柄
- 其他兼容的8BitDo设备

## 安全注意事项

⚠️ **重要警告**:
- 固件更新过程中不要断开设备连接
- 确保使用正确的固件文件
- 建议备份当前固件版本信息
- 只使用官方或可信的固件文件

## 示例工作流程

```bash
# 1. 检查插件状态
fwupdtool get-plugins | grep ebitdo

# 2. 连接设备并进入更新模式
# (按照设备说明操作)

# 3. 检测设备
fwupdtool get-devices --plugins ebitdo

# 4. 安装固件
fwupdtool install firmware_v1.25.dat --plugins ebitdo

# 5. 验证安装
fwupdtool get-devices --plugins ebitdo
```

## 相关资源

- [fwupd官方文档](https://fwupd.org/)
- [8BitDo官方支持](https://support.8bitdo.com/)
- [fwupd GitHub仓库](https://github.com/fwupd/fwupd)
- [8BitDo固件下载工具](./8bitdo-firmware.py)

---

**状态**: 8BitDo插件已安装并可用 ✅  
**最后更新**: $(date)  
**fwupd版本**: 2.0.12