# P2P加密聊天软件

本项目是一个基于 Rust 语言的端到端加密聊天软件，集成了图形化界面（eframe/egui），支持点对点安全通信。主要功能包括自定义密钥生成、消息加解密、自动同步密钥、支持本地/远程 IPv6连接，以及历史消息记录和消息高亮显示。

## 功能简介

- **端到端AES128加密**：所有消息通过AES-CBC模式加密，确保通信安全。
- **动态密钥生成与解析**：每次启动自动生成连接密钥，支持密钥解析校验。
- **自动异步连接**：支持主动连接和被动接受连接，采用tokio异步实现网络通信。
- **本地/远程IPv6端口自定义**：可自定义本地/远程IP和端口，支持随机端口生成。
- **图形化界面**：使用egui开发，支持深色主题、消息历史滚动、富文本显示和多行输入。
- **对端密码自动同步与校验**：消息流中自动携带并同步对端密钥，支持密码校验提示。
- **兼容多平台**：理论支持Windows、Linux、macOS。

## 使用方法

### 1. 下载压缩包并解压缩双击或使用命令行启动  

加密软件必须命名为jiamiapp并和可执行文件在同一目录内

### 2. 加密核心（可替换为 Python 示例）

本软件依赖于加密程序（默认为 Rust 版 `jiamiapp`），你也可以使用 Python 版本。Python 版示例代码如下：
python版本需要修改软件使用python来启动文件或直接编译python文件为可执行文件  
```python
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def get_key_iv(password):
    # 密码做SHA256，前16字节为key，后16字节为iv
    digest = hashlib.sha256(password.encode()).digest()
    return digest[:16], digest[16:]

if __name__ == "__main__":
    import sys
    args = sys.argv
    if len(args) >= 2:
        mima = args[1]
    else:
        mima = "默认"
    input_text = sys.stdin.read().strip()
    key, iv = get_key_iv(mima)
    vi = base64.b64encode(iv).decode()
    if input_text.startswith("he:"):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(input_text.encode(), AES.block_size))
        encoded = base64.b64encode(encrypted).decode()
        print(f"{encoded}:::::::::{vi}{mima}")
    else:
        try:
            encrypted = base64.b64decode(input_text)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size).decode()
            print(f"{decrypted}:::::::::{vi}{mima}")
        except Exception as e:
            print(f"解密失败: {e}")
```

> 依赖：`pip install pycryptodome`

- 启动方式：  
  `python jiamiapp.py 密码`
- 标准输入接受明文，输出加密或解密结果
- 以 `he:` 开头判断加密/解密，输出格式为：密文（或明文）`:::::::::`下次密钥（base64+密码）

### 3. 连接流程

1. 启动软件，填写本地IP与端口（端口可设为0自动生成），输入密码。
2. 点击“生成连接密钥”，将密钥发送给对方。
3. 对方粘贴密钥并点击“解析连接密钥”完成连接，密码不匹配会有提示。
4. 连接成功后，界面进入聊天模式，可输入消息并发送。

### 4. 消息加解密流程

- 消息发送前自动加密，接收后自动解密。
- 密钥和iv由密码和当天0点时间戳SHA256计算获得，保证每日更换。
- 消息体携带密钥，自动同步双方密码。

### 5. UI界面

- 支持富文本高亮、错误提示、历史消息滚动。
- 多行输入区域，支持回车发送。
- 密钥、IP、端口输入均有引导说明。

## 主要依赖

- [eframe](https://github.com/emilk/egui)
- [egui](https://github.com/emilk/egui)
- [tokio](https://github.com/tokio-rs/tokio)
- [aes](https://github.com/RustCrypto/block-ciphers)
- [base64](https://github.com/marshallpierce/rust-base64)
- [block-modes](https://github.com/RustCrypto/block-ciphers)
- [chrono](https://github.com/chronotope/chrono)
- [num-bigint](https://github.com/rust-num/num-bigint)
- [sha2](https://github.com/RustCrypto/hashes)
- [rand](https://github.com/rust-random/rand)

## 注意事项

- 请确保加密程序（如 jiamiapp 或 Python 版 jiamiapp.py）可执行文件与聊天程序在同一目录。
- 默认密码为“默认”，建议及时修改。
- 本软件仅为学习与交流用途，不建议用于生产环境或敏感通信。
- 无历史记录文件若想保存历史记录需要用户自行复制粘贴。
- 该软件无内网隧穿功能需使用ipv6建立连接(IPv6不需要[])例：1234::b8fa:d36c:83a6:3e50非fe开头ipv6

