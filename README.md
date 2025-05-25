# VMX Password Cracker - 支持全版本VMware VMX文件的密码爆破工具

## 简介

本工具结合了pyvmx-cracker和VMwareVMX模块的功能，可以对新旧版本的VMware VMX加密文件进行密码爆破。支持字典攻击方式，可以处理AES-256和XTS-AES-256加密算法。

## 特点

- 支持新旧版本VMware的VMX文件格式
- 支持AES-256和XTS-AES-256加密算法
- 使用字典攻击方式进行密码爆破
- 显示详细的密钥安全信息
- 支持详细模式，显示更多破解进度信息

## 安装

1. 确保已安装Python 3.6或更高版本
2. 安装必要的依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

```bash
python vmx-password-cracker.py -v <VMX文件路径> -d <密码字典文件路径> [--verbose]
```

### 参数说明

- `-v, --vmx`: VMX文件路径（必需）
- `-d, --dict`: 密码字典文件路径（必需）
- `--verbose`: 显示详细信息（可选）

### 示例

```bash
python vmx-password-cracker.py -v "Deepin 23.vmx" -d wordlist.txt
```

## 运行结果示例

```
==================================================
  VMX Password Cracker - 支持全版本VMware VMX文件
  版本: 1.0.0
==================================================

[*] VMX文件: Deepin 23.vmx
[*] 密码字典: wordlist.txt

[*] 密钥安全信息...
	ID = 300ddf0a871d84d7
	哈希算法 = PBKDF2-HMAC-SHA-1
	加密算法 = AES-256
	哈希轮数 = 10000
	盐值 = f64c6bfb17aaa38c4fcfdb6d3d951514
	配置哈希 = HMAC-SHA-1

[*] 开始暴力破解...
	已测试 20 个密码...
	已测试 40 个密码...
	已测试 111 个密码...
	已测试 128 个密码...

[+] 密码找到 = Password123

[+] 破解成功!
[+] VMX密码: Password123
```

## 技术背景

本工具基于以下两个项目的技术实现：

1. [pyvmx-cracker](https://github.com/axcheron/pyvmx-cracker) - 支持旧版本VMware VMX文件的密码爆破工具
2. [VMwareVMX](https://github.com/RF3/VMwareVMX) - 支持新版本VMware VMX文件的加密/解密模块

通过结合这两个项目的优点，本工具能够支持全版本VMware VMX文件的密码爆破。

## 许可证

MIT License