# VMX Password Cracker GUI - 支持全版本VMware VMX文件的密码爆破工具

## 简介

本工具是VMX Password Cracker的图形界面版本，结合了pyvmx-cracker和VMwareVMX模块的功能，可以对新旧版本的VMware VMX加密文件进行密码爆破。支持字典攻击方式，可以处理AES-256和XTS-AES-256加密算法。

## 功能特点

- 图形化用户界面，操作简单直观
- 支持全版本VMware VMX文件的密码爆破
- 实时显示破解进度和详细日志
- 可自定义更新间隔，优化性能
- 支持中断破解过程
- 可保存破解结果到文件
- 多线程设计，界面响应流畅

## 系统要求

- Python 3.6+
- PyQt5
- pycryptodome 或 pycrypto

## 安装依赖

```bash
pip install PyQt5 pycryptodome
```

## 使用方法

1. 运行程序：

```bash
python vmx-password-cracker-gui.py
```

2. 在界面上选择VMX文件和密码字典文件
3. 点击「解析VMX」按钮解析VMX文件
4. 查看密钥安全信息
5. 点击「开始破解」按钮开始破解过程
6. 破解成功后可以保存结果

## 界面说明

- **文件选择区域**：选择VMX文件和密码字典文件
- **选项区域**：设置详细输出和更新间隔
- **密钥安全信息区域**：显示解析出的VMX加密信息
- **日志输出区域**：显示程序运行日志
- **进度条**：显示破解进度
- **结果区域**：显示找到的密码
- **按钮区域**：
  - 解析VMX：解析VMX文件信息
  - 开始破解：开始密码破解过程
  - 停止破解：中断当前破解过程
  - 保存结果：将破解结果保存到文件

## 注意事项

- 密码字典文件应为文本文件，每行一个密码
- 破解过程可能需要较长时间，取决于密码字典大小和计算机性能
- 可以随时中断破解过程
- 建议使用较小的更新间隔值以获得更流畅的界面响应

## 许可证

MIT License

## 致谢

本工具基于以下项目开发：
- pyvmx-cracker (by axcheron)
- VMwareVMX (by Robert Federle)