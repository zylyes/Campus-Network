# 校园网自动登录系统

## 目录
- [简介](#简介)
- [功能特点](#功能特点)
- [技术栈](#技术栈)
- [环境依赖](#环境依赖)
- [安装指南](#安装指南)
- [使用说明](#使用说明)
  - [注意事项](#注意事项)
- [问题反馈与建议](#问题反馈与建议)
- [开发者和贡献者](#开发者和贡献者)
- [版权和许可信息](#版权和许可信息)

## 简介

本项目是一个Python编写的校园网自动登录应用，旨在帮助用户自动化登录校园网络的过程，提供图形用户界面（GUI），支持多种网络服务商选择，自动保存登录信息等功能。它主要使用了Tkinter库来构建用户界面，requests库处理网络请求，并用cryptography库对用户凭据进行加密处理，以保护用户数据安全。

## 功能特点

- **用户界面友好**：提供图形用户界面，方便用户输入和保存登录信息。
- **多线程登录**：登录操作在独立的线程中执行，确保界面不会因为登录操作而冻结。
- **密码保护**：使用加密技术安全存储用户密码。
- **支持多ISP**：用户可选择不同的互联网服务提供商（ISP），如中国电信、中国移动等。
- **自动登录**：支持配置自动登录，简化用户操作。
- **系统托盘集成**：最小化到系统托盘，不占用任务栏空间。
- **日志记录**：详细记录应用运行和网络请求的日志，便于问题追踪和调试。
- **错误处理与反馈**：提供错误日志记录和用户反馈机制。

## 技术栈

- **Python**：整个应用的编程语言。
- **Tkinter**：构建图形用户界面。
- **requests**：处理HTTP请求。
- **cryptography**：加密用户密码。
- **json、pickle**：数据序列化。
- **logging**：应用日志记录。

## 环境依赖

- Python 3.6+
- 需要的Python库：tkinter, requests, cryptography, json, pickle, logging, subprocess, socket, threading, time, base64, webbrowser, pystray, PIL, os, sys

## 安装指南

1. 确保Python版本为3.6或以上。
2. 安装必要的Python库：
   ```bash
   pip install tkinter requests cryptography pickle logging pywin32 winshell pystray Pillow webbrowser logging
   ```

3. 克隆项目到本地：
   ```bash
   git clone zylyes/Campus-Network
   ```
4. 运行应用：
   ```bash
   python campus_network_login.py
   ```
   建议使用的打包命令：
   ```bash
   pyinstaller --onefile --windowed --icon=campus_network_icon.ico -n 校园网登录程序 campus_network_login.py
   ```
   程序的重启部分使用了这个文件名，如需更换打包后的名字，请连同程序部分一起修改

   当然你也可以直接使用释放中打包好的exe

## 项目结构和文件组织

- `campus_network_login.py`：主要的脚本文件。
- `config.json`：用于存储用户配置的文件。
- `encrypted_credentials.pkl`：加密保存用户凭据的文件。
- `encryption_key.key`：用于加密和解密凭据的密钥文件。
- `logs`：存放日志文件的目录。
- `icons`：存放图标文件的目录。

## 使用说明

1. 启动应用后，如果未设置自动登录或首次使用，会显示登录界面。
2. 输入用户名和密码，选择服务提供商，点击“登录”按钮进行登录。
3. 可以选择“记住账号和密码”来在下次自动填充登录信息。
4. “设置”按钮允许配置自动登录和开机自启等选项。
5. 系统托盘图标提供快速访问和管理功能，包括打开主界面、退出应用等。
6. 登录过程中的所有信息都会在应用所在的日志文件中记录。
7. 配置修改可通过编辑`config.json`文件手动更改配置。

### 使用说明书
本程序提供了两版说明书分别是[校园网登录程序使用说明书.docx](https://github.com/zylyes/Campus-Network/blob/main/%E6%A0%A1%E5%9B%AD%E7%BD%91%E7%99%BB%E5%BD%95%E7%A8%8B%E5%BA%8F%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%E4%B9%A6.docx)和[校园网登录程序使用说明书.md](https://github.com/zylyes/Campus-Network/blob/main/%E6%A0%A1%E5%9B%AD%E7%BD%91%E7%99%BB%E5%BD%95%E7%A8%8B%E5%BA%8F%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%E4%B9%A6.md)
- 你可以选择其中的任意一篇查看
- 校园网登录程序使用说明书.md可以在线查看
- 校园网登录程序使用说明书.docx需下载后查看

### 注意事项
- 确保所有依赖库版本兼容。
- 在修改配置文件或源码后，需要重启程序以应用更改。
- 使用加密功能时，请不要删除`encryption_key.key`文件，否则将无法解密已保存的密码。
- 使用该程序之前，请确保你有权使用相应的校园网账号，并已获得合法授权。
- 本程序仅为方便学生使用校园网，对因使用不当导致的任何问题，开发者不承担任何责任。
- 请不要在没有授权的环境下保存他人的账号信息。
- 使用该软件时，请合理遵守当地校园网络管理的相关规定及法律法规。

## 问题反馈与建议

- 如果在使用过程中遇到任何问题或有任何改进建议，欢迎您通过 [GitHub Issues](https://github.com/zylyes/Campus-Network/issues) 提交反馈。

- 如果你着急的话，请用`E-mail`联系我：[Formaldehyde-zyl@outlook.com](mailto:Formaldehyde-zyl@outlook.com)，当然要我使用PC时才能处理。

- 请尽量附上相关的日志文件、问题描述文件或具体建议内容，以便开发者更有效地解决问题。

### 常见问题与解答

- **问**: 如何查看日志文件？
- **答**: 日志文件默认存放在应用目录下的`logs`文件夹中。

- **问**: 如果我忘记密码，应该怎么办？
- **答**: 您需要联系网络管理中心重置密码。

- **问**: 如果应用无法自动登录怎么办？
- **答**: 请检查网络连接是否正常，并参考日志文件中的错误信息。

- **问**: 登录失败如何处理？
- **答**: 检查网络连接，用户名及密码是否输入正确，且选择了正确的运营商。确认无误后重新尝试。

- **问**: 遇到其他使用问题怎么办？
- **答**: 可以通过"报告问题"功能向我们提交具体的错误信息，我们会尽快对其进行处理并反馈。

- **问**: 如何关闭自动登录？
- **答**: 打开设置界面，取消选中“自动登录”的复选框后保存设置。

- **问**: 如何更改API URL？
- **答**: 打开设置界面，可以看到API URL的输入框，更换之后记得保存设置。

## 未来计划



## 贡献指南

如果您想为此项目做出贡献，请按照以下步骤操作：

1. Fork该仓库并克隆到本地。
2. 根据需求修改代码。
3. 提交Pull Request以供审核。

### 提交代码的标准

提交的代码应遵循PEP8编码规范，并附有适当的注释和文档。

## 开发者和贡献者

- **周咏霖**：主要开发者，负责应用的设计与开发。

## 版权和许可信息

本项目采用MIT许可证。有关详细条款，请参阅项目根目录下的 `LICENSE` 文件。
