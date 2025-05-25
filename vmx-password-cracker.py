#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
vmx-password-cracker.py: 支持全版本VMware VMX文件的密码爆破工具

本工具结合了pyvmx-cracker和VMwareVMX模块的功能，可以对新旧版本的VMware VMX加密文件进行密码爆破。
支持字典攻击方式，可以处理AES-256和XTS-AES-256加密算法。
"""

__author__ = 'Trae AI (基于axcheron的pyvmx-cracker和Robert Federle的VMwareVMX)'
__license__ = 'MIT License'
__version__ = '1.0.0'

import argparse
import hashlib
import hmac
import random
import re
import sys
from base64 import b64decode
from binascii import hexlify
from urllib.parse import unquote

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto import Random
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad
        from Cryptodome import Random
    except ImportError:
        print("错误: 请安装 pycryptodome 或 pycrypto 库")
        print("使用命令: pip install pycryptodome")
        sys.exit(1)

# 常量定义
HASH_ROUNDS_DEFAULT = 10000
IDENTIFIER_SIZE = 8
SALT_SIZE = 16
AES_IV_SIZE = AES.block_size
AES_KEY_SIZE = 32  # AES-256 (256 // 8)
XTS_KEY_SIZE = AES_KEY_SIZE * 2  # XTS-AES-256
HASH_SIZE = 20  # SHA-1

# 正则表达式模式
KS_RE_OLD = '.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\\)'
KS_RE_NEW = '.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\\)'
# 添加对VMware Workstation 16及更高版本的支持
KS_RE_NEWER = 'vmware:key/list/\\(pair/\\(phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\\)\\)'

# 密钥安全结构
ks_struct = {
    'id': None,
    'password_hash': None,
    'password_cipher': None,
    'hash_round': None,
    'salt': None,
    'config_hash': None,
    'dict': None
}


def print_banner():
    """打印工具横幅"""
    print("\n==================================================")
    print("  VMX Password Cracker - 支持全版本VMware VMX文件")
    print("  版本: " + __version__)
    print("==================================================")


def print_ksdata(keysafe):
    """打印密钥安全信息"""
    print("\n[*] 密钥安全信息...")
    print("\tID = %s" % keysafe['id'])
    print("\t哈希算法 = %s" % keysafe['password_hash'])
    print("\t加密算法 = %s" % keysafe['password_cipher'])
    print("\t哈希轮数 = %d" % keysafe['hash_round'])
    print("\t盐值 = %s" % hexlify(keysafe['salt']).decode())
    print("\t配置哈希 = %s" % keysafe['config_hash'])


def parse_keysafe(file):
    """解析VMX文件中的密钥安全信息
    
    Args:
        file: VMX文件路径
        
    Returns:
        解析后的密钥安全结构
    """
    try:
        with open(file, 'r', encoding='utf-8', errors='ignore') as data:
            lines = data.readlines()
    except (OSError, IOError) as e:
        sys.exit(f'[-] 无法读取文件 {file}: {str(e)}')

    keysafe_line = None
    for line in lines:
        if 'encryption.keySafe' in line:
            keysafe_line = line
            break
    
    if not keysafe_line:
        sys.exit('[-] 无效的VMX文件或VMX文件未加密')

    keysafe_line = unquote(keysafe_line)
    
    # 尝试匹配新旧格式
    match = re.match(KS_RE_OLD, keysafe_line) or re.match(KS_RE_NEW, keysafe_line) or re.match(KS_RE_NEWER, keysafe_line)
    if not match:
        msg = '不支持的encryption.keySafe行格式:\n' + keysafe_line
        raise ValueError(msg)

    vmx_ks = ks_struct.copy()

    # 解析密钥安全信息
    vmx_ks['id'] = hexlify(b64decode(match.group(1))).decode()
    vmx_ks['password_hash'] = match.group(2)
    vmx_ks['password_cipher'] = match.group(3)
    vmx_ks['hash_round'] = int(match.group(4))
    vmx_ks['salt'] = b64decode(unquote(match.group(5)))
    vmx_ks['config_hash'] = match.group(6)
    vmx_ks['dict'] = b64decode(match.group(7))

    return vmx_ks


def crack_keysafe(keysafe, dict_file, verbose=False):
    """尝试破解密钥安全信息
    
    Args:
        keysafe: 密钥安全结构
        dict_file: 密码字典文件路径
        verbose: 是否显示详细信息
        
    Returns:
        成功时返回密码，失败时返回None
    """
    try:
        wordlist = open(dict_file, 'r', encoding='utf-8', errors='ignore')
    except IOError as e:
        print(f'[-] 无法打开密码字典 ({dict_file}): {str(e)}')
        exit(1)

    count = 0
    print("\n[*] 开始暴力破解...")

    # 确定密钥大小
    if keysafe['password_cipher'] == 'AES-256':
        key_size = AES_KEY_SIZE
    elif keysafe['password_cipher'] == 'XTS-AES-256':
        key_size = XTS_KEY_SIZE
    else:
        print(f"[-] 不支持的加密算法: {keysafe['password_cipher']}")
        return None

    for line in wordlist.readlines():
        password = line.rstrip()
        
        # 使用PBKDF2-HMAC-SHA-1生成字典密钥
        dict_key = hashlib.pbkdf2_hmac('sha1', password.encode(), keysafe['salt'],
                                      keysafe['hash_round'], key_size)

        # 提取AES IV并解密字典
        dict_aes_iv = keysafe['dict'][:AES_IV_SIZE]
        cipher = AES.new(dict_key[:AES_KEY_SIZE], AES.MODE_CBC, dict_aes_iv)
        dict_dec = cipher.decrypt(keysafe['dict'][AES_IV_SIZE:-HASH_SIZE])

        # 每测试一定数量的密码显示进度
        if verbose or random.randint(1, 20) == 12:
            print(f"\t已测试 {count} 个密码...")
        count += 1

        try:
            # 检查解密后的字典是否包含预期的字符串
            dict_str = dict_dec.decode('ascii', errors='ignore')
            if 'type=key:cipher=AES-256:key=' in dict_str or 'type=key:cipher=XTS-AES-256:key=' in dict_str:
                print(f"\n[+] 密码找到 = {password}")
                wordlist.close()
                return password
        except UnicodeDecodeError:
            pass

    print("\n[-] 未找到密码。请尝试其他字典。")
    wordlist.close()
    return None


def check_files(vmx_file, dict_file):
    """检查文件是否有效
    
    Args:
        vmx_file: VMX文件路径
        dict_file: 密码字典文件路径
    """
    try:
        with open(vmx_file, 'r', encoding='utf-8', errors='ignore') as data:
            lines = data.readlines()
    except (OSError, IOError) as e:
        sys.exit(f'[-] 无法读取文件 {vmx_file}: {str(e)}')

    encryption_found = False
    for line in lines:  # 检查整个文件
        if 'encryption.keySafe' in line:
            encryption_found = True
            break

    if not encryption_found:
        sys.exit('[-] 无效的VMX文件或VMX文件未加密')

    try:
        with open(dict_file, 'rb') as _:
            pass
    except IOError as e:
        print(f'[-] 无法打开密码字典 ({dict_file}): {str(e)}')
        exit(1)


def main(vmx_file, dict_file, verbose=False):
    """主函数
    
    Args:
        vmx_file: VMX文件路径
        dict_file: 密码字典文件路径
        verbose: 是否显示详细信息
    """
    print_banner()
    print(f"\n[*] VMX文件: {vmx_file}")
    print(f"[*] 密码字典: {dict_file}")

    # 检查文件
    check_files(vmx_file, dict_file)
    
    # 解析密钥安全信息
    try:
        parsed_ks = parse_keysafe(vmx_file)
        # 打印信息
        print_ksdata(parsed_ks)
        # 破解密钥安全信息
        password = crack_keysafe(parsed_ks, dict_file, verbose)
        
        if password:
            print("\n[+] 破解成功!")
            print(f"[+] VMX密码: {password}")
            return 0
        else:
            print("\n[-] 破解失败!")
            return 1
    except Exception as e:
        print(f"\n[-] 错误: {str(e)}")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="支持全版本VMware VMX文件的密码爆破工具")

    # 添加参数
    parser.add_argument("-v", "--vmx", dest="vmx", action="store",
                        help="VMX文件路径", type=str, required=True)

    parser.add_argument("-d", "--dict", dest="dict", action="store",
                        help="密码字典文件路径", type=str, required=True)
                        
    parser.add_argument("--verbose", dest="verbose", action="store_true",
                        help="显示详细信息", default=False)

    args = parser.parse_args()

    sys.exit(main(args.vmx, args.dict, args.verbose))