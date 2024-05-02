# 校园网自动登录系统

## 目录
- [简介](#简介)
- [功能特点](#功能特点)
- [技术栈](#技术栈)
- [环境依赖](#环境依赖)
- [安装指南](#安装指南)
- [项目结构和文件组织](#项目结构和文件组织)
- [版本更新记录](#版本更新记录)
  - v0.9.0
  - v1.0.0
  - v1.1.0
  - v1.2.0
  - v1.2.1
  - v1.3.0
  - v1.4.0(最新版)
  - v1.4.1(预发布版)
  - v1.4.2(计划中)
- [未来计划](#未来计划)
- [使用说明](#使用说明)
  - [使用说明书](#使用说明书)
  - [注意事项](#注意事项)
- [问题反馈与建议](#问题反馈与建议)
  - [常见问题与解答](#常见问题与解答)
- [贡献指南](#贡献指南)
  - [提交代码的标准](#提交代码的标准)
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
- 需要的Python库：tkinter, requests, cryptography, json, pickle, logging, subprocess, socket, threading, time, base64, webbrowser, pystray, PIL, os, sys, packaging

## 安装指南

1. 确保Python版本为3.6或以上。
2. 安装必要的Python库：
   ```bash
   pip install requests cryptography pywin32 winshell pystray Pillow packaging
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

## 版本更新记录：

| 版本号 | 发布日期  | 更新内容 | 链接 |
|:------:|:---------:|----------|------|
| 0.9.0  | 2024-04-13 | # 初始版本发布，包括以下功能：<br> - 提供图形用户界面，支持用户输入和保存登录信息。<br>  - 支持多种网络服务商选择，包括中国电信、中国移动等。<br>  - 实现自动登录功能，用户可以选择是否自动登录。<br>  - 提供系统托盘集成，最小化到系统托盘，方便用户管理。<br>  - 记录应用运行和网络请求的日志，便于问题追踪和调试。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V0.9) |
| 1.0.0  | 2024-04-14 | # 新增功能：<br>  - 将程序缩小到托盘功能。<br> # 优化：<br>  - 优化界面显示，提升用户体验。<br>  - 改进自动登录机制，提高登录成功率。<br>  - 进行了一些代码结构上的优化，以提高应用性能和可维护性。<br> # 修复：<br>  - 修复了一些已知的 Bug，提升了应用的稳定性。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V1.0) |
| 1.1.0  | 2024-04-15 | # 新增功能：<br>  - 添加了一部分登录失败后的逻辑，增加了更多失败情况的预案。<br> # 优化：<br>  - 进一步优化代码结构，提高应用性能和可维护性。<br> # 修复：<br>  - 修复了一些用户反馈的问题，提升了用户体验。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V1.1) |
| 1.2.0  | 2024-04-17 | # 新增功能：<br>  - 改变了一些文件的命名方式，使文件夹更简洁明了。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V1.2) |
| 1.2.1  | 2024-04-20 | # 新增功能：<br>  - 将配置文件的部分程序从主类中分离成一个新的配置类<br> `CampusNetSettingsManager`中。<br>  - 增加了代码的复用，对配置保存次数进行了修改，减少了配置写入次数。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V1.2.1) |
| 1.3.0  | 2024-04-24 | # 新增功能：<br>  - 添加了安装和卸载功能，方便用户进行后续升级。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V1.3.0) |
| 1.4.0  | 2024-05-02 | # 新增功能：<br>  - 调整了登录返回值的评估<br>  - 并可通过编辑`login_responses.json`文件来更改登录判断。<br>  - 增加了禁止应用重复启动的功能。<br> # 优化：<br>  - 进一步优化代码结构，提高应用性能和可维护性。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V1.4.0) |
| 1.4.1  | 2024-05-03 | # 新增功能：<br>  - 添加了一个选项，可以选择是否要保留系统托盘<br>  - 并对设置界面进行了美化。 | [查看](https://github.com/zylyes/Campus-Network/releases/tag/V1.4.1) |
| 1.4.2  |   计划中   | # 新增功能：<br>  - 调整主界面创建方式，使之能更好地适配各种显示条件。 | [待定](https://github.com/zylyes/Campus-Network/releases/tag/V1.4.0) |

## 未来计划：

1. **界面优化和适配**：将界面由像素界面改为图片界面，并且支持动态调整分辨率以适配不同的显示屏和显示倍率。计划在下一个版本中实现，预计完成时间为 2024 年 5 月。优先级：高。

2. **自动更新功能**：添加自动更新功能以及在安装时静默卸载旧版本。计划在下一个版本中实现，预计完成时间为 2024 年 5 月。优先级：中。

3. **报错情况和处理方法**：继续添加报错情况和处理方法，以提高应用的容错性和用户体验。计划在未来几个版本中陆续实现，预计完成时间为 2024 年 6 月。优先级：中。

4. **代码结构优化**：将与 GUI 不直接相关的功能进一步抽象和封装到类中，使代码更具可维护性和扩展性。计划在未来几个版本中陆续实现，预计完成时间为 2024 年 6 月。优先级：高。

5. **性能提升**：优化程序结构，提高运行效率，减少资源占用。计划在未来几个版本中陆续实现，预计完成时间为 2024 年 7 月。优先级：中。

## 使用说明

1. 启动应用后，如果未设置自动登录或首次使用，会显示登录界面。
2. 输入用户名和密码，选择服务提供商，点击“登录”按钮进行登录。
3. 可以选择“记住账号和密码”来在下次自动填充登录信息。
4. “设置”按钮允许配置自动登录和开机自启等选项。
5. 系统托盘图标提供快速访问和管理功能，包括打开主界面、退出应用等。
6. 登录过程中的所有信息都会在应用所在的日志文件中记录。
7. 配置修改可通过编辑`config.json`文件手动更改配置。

### 使用说明书（旧版）

本程序提供了两版说明书分别是[校园网登录程序使用说明书（旧版）.docx](https://github.com/zylyes/Campus-Network/blob/main/%E6%A0%A1%E5%9B%AD%E7%BD%91%E7%99%BB%E5%BD%95%E7%A8%8B%E5%BA%8F%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%E4%B9%A6.docx)和[校园网登录程序使用说明书（旧版）.md](https://github.com/zylyes/Campus-Network/blob/main/%E6%A0%A1%E5%9B%AD%E7%BD%91%E7%99%BB%E5%BD%95%E7%A8%8B%E5%BA%8F%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%E4%B9%A6.md)
- 你可以选择其中的任意一篇查看
- 校园网登录程序使用说明书.md可以在线查看
- 校园网登录程序使用说明书.docx需下载后查看

### 使用说明书（新版）



### 注意事项
- 确保所有依赖库版本兼容。
- 在修改配置文件或源码后，需要重启程序以应用更改。
- 使用加密功能时，请不要删除`encryption_key.key`文件，否则将无法解密已保存的密码。
- 使用该程序之前，请确保你有权使用相应的校园网账号，并已获得合法授权。
- 本程序仅为方便学生使用校园网，对因使用不当导致的任何问题，开发者不承担任何责任。
- 请不要在没有授权的环境下保存他人的账号信息。
- 使用该软件时，请合理遵守当地校园网络管理的相关规定及法律法规。
绝对没错，用户的安全至关重要。以下是针对安全性的提示添加到使用说明中：

- **密码安全性**：在使用本程序时，请务必注意保护好您的校园网账号密码。
特别是，避免将密码以明文形式保存在任何地方，包括配置文件或代码中。
我们强烈建议使用本程序提供的加密功能来存储密码，并确保您的加密密钥文件 `encryption_key.key` 不被泄露。

- **保护 encryption_key.key 文件**：加密密钥文件 `encryption_key.key` 是用于加密和解密用户密码的关键文件。
请确保该文件不被未授权的访问者获取。任何人都不应该获得或使用您的加密密钥文件，以免导致密码泄露和账户安全问题。

- **定期更改密码**：为了提高账户安全性，建议您定期更改校园网账号的密码，并确保新密码具有足够的复杂性和难以猜测性。
定期更改密码有助于防止潜在的密码泄露和未经授权的访问。

- **网络安全性**：请确保您的网络连接安全，并在使用本程序时避免连接到不受信任的网络。
公共网络或未加密的 Wi-Fi 可能存在安全风险，建议在安全的网络环境下使用本程序以保护您的账号信息和个人隐私。

## 问题反馈与建议

如果您在使用过程中遇到任何问题或有任何改进建议，欢迎通过以下方式联系我们：

- GitHub Issues：您可以在 [GitHub Issues](https://github.com/zylyes/Campus-Network/issues) 提交反馈和建议。

- 电子邮件：您可以通过邮件联系我们：[Formaldehyde-zyl@outlook.com](mailto:Formaldehyde-zyl@outlook.com)。

- 社交媒体：您也可以通过我们的社交媒体账号直接联系我们，我们会尽快回复您的消息。

- 请尽量附上相关的日志文件、问题描述文件或具体建议内容，以便开发者更有效地解决问题。

我们期待听到您的声音，您的反馈和建议对于改进项目至关重要！

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

## 贡献指南

我们欢迎各种形式的贡献，包括但不限于以下方面：

- **功能开发**：如果您有新的功能想法或者改进建议，欢迎提交相关的代码或者提出您的想法。

- **文档改进**：文档是项目的重要组成部分，如果您发现文档有任何错误、遗漏或者可以改进的地方，请随时提交修复或者提出改进建议。

- **Bug 修复**：如果您发现了任何已知或者新的 Bug，请通过 [GitHub Issues](https://github.com/zylyes/Campus-Network/issues) 提交问题报告，并且欢迎提交修复方案。

- **代码优化**：如果您发现代码中存在任何冗余、低效或者不规范的地方，欢迎提交优化方案或者代码重构。

- **测试**：测试是保障代码质量的重要手段，如果您对测试有经验，可以帮助我们编写更全面的测试用例。运行测试的步骤如下：

  1. 确保您已安装了项目的所有依赖项。
  2. 在项目根目录下运行测试命令，例如：
     ```bash
     python -m unittest tests.test_login
     ```
  3. 确保所有的测试用例都通过了，并且没有出现错误或者失败的情况。

- **代码审查**：我们鼓励所有的贡献者参与到代码审查中来，确保代码的质量和一致性。如果您对代码审查有任何疑问，可以随时向其他贡献者或者项目维护者寻求帮助。

- **界面设计**：如果您擅长界面设计，欢迎为项目设计更美观、用户友好的界面。

无论您是有经验的开发者还是刚入门的新手，都可以为项目做出贡献。我们相信每一个贡献都将为项目的发展和改进带来积极的影响。感谢您的支持和参与！

### 提交代码的标准

提交的代码应遵循PEP8编码规范，并附有适当的注释和文档。
为了确保代码符合规范，我们建议使用代码风格检查工具，如flake8、black和pylint。
在提交代码之前，请确保通过这些工具进行代码检查，并根据检查结果进行必要的修正。

如果您想要贡献其他形式的内容，请直接在 [GitHub Issues](https://github.com/zylyes/Campus-Network/issues) 中提出您的建议或者问题报告。

### 代码风格检查工具的使用建议

在进行代码编写和修改时，建议使用代码风格检查工具来确保代码的一致性和规范性。以下是使用black进行代码风格检查的简要步骤：

1. 安装black：

   ```bash
   pip install black
   ```

2. 在项目根目录下运行black：

   ```bash
   black campus_network_login.py
   ```

   black将扫描项目中的所有Python文件，并显示与PEP8规范不符合的部分，以便您进行修改和优化。

### 贡献者提交代码的具体步骤

1. Fork 本仓库并克隆到本地：

   ```bash
   git clone https://github.com/zylyes/Campus-Network.git
   ```

2. 创建一个新的分支，并切换到该分支：

   ```bash
   git checkout -b feature_branch
   ```

3. 进行您的改动，并确保通过了项目的测试。

4. 使用black等代码风格检查工具对代码进行检查，并根据检查结果进行必要的修正。

5. 在本地提交您的改动：

   ```bash
   git add .
   git commit -m "Your commit message"
   ```

6. 推送您的分支到远程仓库：

   ```bash
   git push origin feature_branch
   ```

7. 在 GitHub 上创建一个新的 Pull Request，详细描述您的改动以及改动的原因。

8. 等待代码审查和反馈。在代码审查过程中，可能会提出一些改进意见或者修正建议，请根据审查结果进行相应的修改。

9. 一切就绪后，您的代码将被合并到主分支中，并成为项目的一部分。

通过以上步骤，您就可以向项目贡献您的代码了。感谢您的支持和参与！

## 开发者和贡献者

### 主要开发者

- **周咏霖**：主要开发者，负责应用的设计与开发。

### 其他贡献者

- 暂无

如果您已经为项目做出了贡献，但尚未在此处列出，请提供您的名字和贡献内容，我们将非常感谢您的支持并在此处表彰您的贡献。

## 版权和许可信息

本项目采用[MIT许可证](https://github.com/zylyes/Campus-Network/blob/main/LICENSE)。有关详细条款，请参阅项目根目录下的 `LICENSE` 文件。
