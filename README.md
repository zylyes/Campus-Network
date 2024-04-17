### 校园网自动登录系统

#### 简介
本程序是一个基于Python和Tkinter构建的校园网自动登录应用，旨在帮助用户在校园网环境下自动或手动进行网络登录。程序支持保存用户登录信息，自动登录，以及多种网络服务提供商的选择等功能。

#### 功能特点
1. **图形用户界面**：使用Tkinter构建简洁直观的操作界面。
2. **自动登录**：支持开机自动登录校园网。
3. **多运营商支持**：支持中国电信、中国移动、中国联通及校园网等多种ISP登录。
4. **密码保护**：用户密码加密存储，确保安全。
5. **日志记录**：详细记录运行日志，方便故障排查。
6. **配置文件管理**：通过配置文件管理用户设置。
7. **系统托盘功能**：最小化到系统托盘运行，不干扰用户其他操作。
8. **错误处理与反馈**：提供错误日志记录和用户反馈机制。

#### 开发环境
- Python版本：3.x
- 主要依赖库：tkinter, requests, cryptography, json, logging, threading, pickle等。

#### 安装指南
1. 确保已安装Python 3.x。
2. 安装必要的Python库：（不全）
   ```bash
   pip install requests cryptography pillow pystray
   ```
3. 下载程序源码到本地目录。
4. 运行程序：
   ```bash
   python 校园网.py
   ```

#### 使用说明
1. **首次使用**：运行程序后，输入用户名和密码，选择运营商，点击“登录”进行网络登录。
2. **自动登录**：在设置中勾选“自动登录”和“开机时自动启动”，程序将在系统启动时自动连接网络。
3. **密码管理**：首次输入密码后选择“记住账号和密码”，程序将加密并保存登录信息。
4. **日志查看**：查看`logs`目录下生成的日志文件来获取程序运行详情。
5. **配置修改**：可通过编辑`config.json`文件手动更改配置。
6. **建议与反馈**：通过“提交建议”功能提交用户反馈。

#### 文件结构
```
校园网.py                 # 主程序文件
config.json               # 配置文件
logs/                     # 日志目录
  └─ campus_net_login_app.log    # 日志文件
ico/                      # 存放图标的目录
  └─ ...                  # 各类图标文件
key.key                   # 加密密钥文件
credentials.pkl           # 加密存储的用户凭据文件
```

#### 注意事项
- 确保所有依赖库版本兼容。
- 在修改配置文件或源码后，需要重启程序以应用更改。
- 使用加密功能时，请不要删除`key.key`文件，否则将无法解密已保存的密码。

通过以上指南，用户可以方便地设置和使用校园网自动登录系统，享受便捷的网络连接体验。
