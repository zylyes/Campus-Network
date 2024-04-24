# campus_network_login.py
# 时间：2024/04/24
# 作者：周咏霖
# 版本：V1.3.0

import tkinter as tk  # 导入tkinter库用于GUI界面创建
from tkinter import (
    messagebox,
    ttk,
)  # 从tkinter导入messagebox和ttk，用于图形界面中的对话框和高级组件
import requests  # 导入requests库用于处理HTTP请求
import os  # 导入os库用于处理操作系统级别的接口，如文件管理
import json  # 导入json库用于处理JSON数据格式
from cryptography.fernet import Fernet  # 从cryptography库导入Fernet用于加密
import pickle  # 导入pickle库用于对象的序列化和反序列化
import logging  # 导入logging库用于记录日志
from logging.handlers import (
    TimedRotatingFileHandler,
)  # 从logging.handlers导入TimedRotatingFileHandler，用于按时间轮转记录日志到文件
import subprocess  # 导入subprocess库用于调用外部进程
import socket  # 导入socket库用于网络通信
import threading  # 导入threading库用于多线程编程
import time  # 导入time库用于时间操作
import win32api  # 导入win32api库用于Windows API操作
import win32con  # 导入win32con库用于Windows常量定义
import win32gui  # 导入win32gui库用于Windows GUI操作
import base64  # 导入base64库用于编码和解码base64数据
import webbrowser  # 导入webbrowser用于在浏览器中打开URL
import winshell  # 导入winshell库用于Windows快捷方式操作
import pywintypes  # 确保导入pywintypes
import urllib.parse  # 导入urllib.parse模块
import pystray  # 导入pystray库
from pystray import MenuItem as item  # 从pystray库中导入MenuItem类并将其重命名为item
from PIL import Image  # 导入PIL库中的Image类
from packaging import version  # 导入packaging库


# 定义一个自定义的日志过滤器类PasswordFilter
class PasswordFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        if "user_password=" in message:  # 如果日志信息中包含'user_password='
            new_message = message.replace(
                message.split("user_password=")[1].split("&")[0], "********"
            )  # 将密码部分替换为'********'
            record.msg = new_message
            record.args = ()  # 清空args以避免格式化错误
        return True


# 用于缓存配置的全局变量
cached_config = {}


def setup_logging():
    """根据环境变量设置日志记录器的配置"""
    # 获取日志级别，默认为DEBUG
    log_level = os.getenv("LOG_LEVEL", "DEBUG").upper()
    # 设置日志格式
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # 确保日志目录存在
    log_directory = "logs"  # 日志文件夹名称
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)  # 如果目录不存在，则创建它

    # 创建日志记录器
    logger = logging.getLogger()  # 获取全局日志记录器对象
    logger.setLevel(log_level)  # 设置日志记录器的日志级别

    # 创建TimedRotatingFileHandler处理程序，每天生成一个新日志文件，最多保留7个日志文件
    log_file_path = os.path.join(
        log_directory, "campus_net_login_app.log"
    )  # 将日志文件放在logs目录下
    handler = TimedRotatingFileHandler(
        log_file_path, when="midnight", interval=1, backupCount=7
    )  # 创建按时间滚动的文件处理程序

    # 设置日志格式
    formatter = logging.Formatter(log_format)  # 创建日志格式对象
    handler.setFormatter(formatter)  # 将格式应用到handler
    # 将handler添加到logger中
    logger.addHandler(handler)  # 将handler添加到logger以记录日志信息

    # 控制台输出
    console_handler = logging.StreamHandler()  # 创建控制台输出handler
    console_handler.setFormatter(formatter)  # 设置控制台输出的日志格式
    logger.addHandler(console_handler)  # 将控制台输出handler添加到logger中

    # 创建日志过滤器并添加到handler
    pwd_filter = PasswordFilter()  # 创建密码过滤器对象
    handler.addFilter(pwd_filter)  # 将密码过滤器添加到文件输出handler
    console_handler.addFilter(pwd_filter)  # 将密码过滤器添加到控制台输出handler

    # 隐藏PIL的DEBUG日志消息
    pil_logger = logging.getLogger("PIL")  # 获取PIL模块的日志记录器
    pil_logger.setLevel(
        logging.INFO
    )  # 将PIL的日志级别设置为INFO，这样就不会显示DEBUG消息


def on_main_close(root, settings_manager):
    if messagebox.askokcancel(
        "退出", "确定要退出应用吗？"
    ):  # 弹出确认对话框，用户确认退出应用
        settings_manager.save_config_to_disk()  # 确保退出前保存配置到磁盘
        root.destroy()  # 销毁主窗口，退出应用


setup_logging()  # 调用日志设置函数

config_lock = threading.Lock()  # 创建一个线程锁


class CampusNetSettingsManager:
    def __init__(self, config_file="config.json", default_config=None):
        self.config_lock = threading.Lock()
        self.cached_config = {}
        self.config_file = config_file
        self.default_config = default_config or {
            "api_url": "http://172.21.255.105:801/eportal/",
            "icons": {
                "already": "./icons/Internet.ico",
                "success": "./icons/Check.ico",
                "fail": "./icons/Cross.ico",
                "unknown": "./icons/Questionmark.ico",
            },
            "auto_login": False,
            "isp": "campus",
            "auto_start": False,
        }

    # 程序当前版本
    CURRENT_VERSION = "1.3.0"

    def load_or_create_config(self):
        if self.cached_config:
            return self.cached_config

        logging.debug("尝试加载配置文件...")

        with self.config_lock:
            if not os.path.exists(self.config_file):
                logging.info("配置文件不存在，创建默认配置文件。")
                with open(self.config_file, "w") as config_file:
                    json.dump(self.default_config, config_file)
            else:
                logging.info("配置文件加载成功。")
            with open(self.config_file, "r") as config_file:
                self.cached_config = json.load(config_file)

        return self.cached_config

    def save_config_to_disk(self):
        logging.debug("保存配置到文件中...")
        with self.config_lock:
            with open(self.config_file, "w") as config_file:
                json.dump(self.cached_config, config_file)
        logging.info("配置已保存到磁盘")

    def save_config(self, config):
        self.cached_config.update(config)
        logging.info("配置已更新到缓存")


class CampusNetLoginApp:

    def __init__(self, master, settings_manager, show_ui=True):
        self.master = master  # 初始化主窗口
        self.config_lock = threading.Lock()  # 初始化线程锁用于保护配置文件的读写
        self.settings_manager = settings_manager
        self.config = self.settings_manager.load_or_create_config()  # 加载配置文件
        self.key, self.cipher_suite = self.load_or_generate_key()  # 获取加密密钥

        self.eye_open_icon = tk.PhotoImage(
            file="./icons/eye_open.png"
        )  # 导入眼睛图标-打开状态
        self.eye_closed_icon = tk.PhotoImage(
            file="./icons/eye_closed.png"
        )  # 导入眼睛图标-关闭状态
        self.password_visible = False  # 跟踪密码是否可见的标志

        # 初始化ISP下拉列表的变量，并使用配置文件中的ISP设置，如果没有则默认为"campus"
        self.isp_var = tk.StringVar(value=self.config.get("isp", "campus"))

        self.show_ui = show_ui  # 是否显示UI界面的标志
        if show_ui:
            self.setup_ui()  # 初始化UI界面
        self.auto_login()  # 执行自动登录操作

    def load_config(self):
        # 定义加载配置的函数，使用load_or_create_config函数来加载配置
        return self.settings_manager.load_or_create_config()

    def load_or_generate_key(self):
        # 定义加载或生成密钥的函数
        key_file = "encryption_key.key"
        if os.path.exists(key_file):  # 如果密钥文件已存在
            with open(key_file, "rb") as file:
                key = file.read()  # 从文件中读取密钥
        else:  # 如果密钥文件不存在
            key = Fernet.generate_key()  # 生成新的密钥
            with open(key_file, "wb") as file:
                file.write(key)  # 将新生成的密钥写入文件
            messagebox.showinfo(
                "密钥生成", "新的加密密钥已生成并保存。"
            )  # 弹出提示框显示密钥已生成
        return key, Fernet(key)  # 返回密钥及使用该密钥初始化的Fernet对象

    def get_ip(self):
        # 获取本机IP地址
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建套接字对象
        try:
            s.connect(("8.8.8.8", 80))  # 连接到谷歌DNS服务器，获取本机IP地址
            ip = s.getsockname()[0]  # 获取本机IP地址
        finally:
            s.close()  # 关闭套接字连接
        return ip  # 返回本机IP地址

    def save_credentials(self, username, password, remember):
        # 保存用户凭据信息
        if password is None:
            logging.error(
                "尝试保存的密码为None。"
            )  # 记录错误信息：尝试保存的密码为None
            return  # 直接返回，避免进一步处理None类型的密码

        encrypted_password = self.cipher_suite.encrypt(password.encode())  # 加密密码
        # 组装凭据信息，包括运营商
        credentials = {
            "username": username,
            "password": encrypted_password,
            "isp": self.isp_var.get(),
            "remember": remember,
        }
        with open("encrypted_credentials.pkl", "wb") as file:
            pickle.dump(credentials, file)  # 将凭据信息序列化保存到文件中

        logging.info(
            f"保存凭据：用户名 {username}, 记住密码：{'是' if remember else '否'}, 运营商：{self.isp_var.get()}"
        )  # 记录保存凭据的信息

        # 保存运营商选择
        isp_reverse_mapping = {
            "中国电信": "telecom",
            "中国移动": "cmcc",
            "中国联通": "unicom",
            "campus": "校园网",
        }  # 定义运营商映射关系
        self.config["isp"] = isp_reverse_mapping.get(
            self.isp_var.get(), "campus"
        )  # 获取用户选择的运营商映射值，默认为校园网
        self.settings_manager.save_config(self.config)  # 保存配置信息

    def load_credentials(self):
        try:
            # 尝试打开名为'encrypted_credentials.pkl'的文件
            with open("encrypted_credentials.pkl", "rb") as file:
                # 从文件中加载凭据
                credentials = pickle.load(file)
                # 获取用户名和解密后的密码
                username = credentials["username"]
                password = self.cipher_suite.decrypt(credentials["password"]).decode()
                isp = credentials.get("isp", "campus")  # 默认运营商为校园网
                remember = credentials.get("remember", False)  # 默认不记住密码
                return username, password, isp, remember
        except FileNotFoundError:
            # 若文件未找到，则返回空值
            return "", "", "campus", False

    def clear_saved_credentials(self):
        try:
            # 尝试删除名为'encrypted_credentials.pkl'的文件
            os.remove("encrypted_credentials.pkl")
        except FileNotFoundError:
            # 若文件未找到，则忽略异常
            pass

    def login(self):
        # 从输入框获取用户名和密码
        username = self.username_entry.get()  # 从用户名输入框获取用户名
        password = self.password_entry.get()  # 从密码输入框获取密码
        if self.validate_credentials(
            username, password
        ):  # 调用验证函数检查用户名和密码是否为空
            # 启动后台线程执行登录操作，并传递用户名和密码
            login_thread = threading.Thread(
                target=self.perform_login, args=(username, password, False)
            )
            login_thread.start()
        else:
            messagebox.showwarning(
                "验证失败", "用户名或密码为空，请按要求填写。"
            )  # 显示警告框，提示用户名或密码为空

    def validate_credentials(self, username, password):
        """验证用户名和密码是否为空"""
        if not username or not password:  # 如果用户名或密码为空
            logging.warning("验证失败：用户名或密码为空")
            # 用户名或密码为空
            return False
        return True

    def decode_base64_message(self, b64message):
        """解码Base64消息"""
        try:
            return base64.b64decode(b64message).decode(
                "utf-8"
            )  # 尝试解码Base64消息并以utf-8编码返回
        except Exception as e:
            logging.error(
                f"Base64消息解码失败:{e}"
            )  # 记录错误日志，提示Base64消息解码失败
            return None

    def perform_login(self, username, password, auto=False):
        logging.debug(f"开始登录流程，用户名: {username}, 自动登录: {str(auto)}")
        # 运营商标识映射
        isp_codes = {
            "中国电信": "@telecom",
            "中国移动": "@cmcc",
            "中国联通": "@unicom",
            "校园网": "@campus",
        }
        selected_isp_code = isp_codes.get(self.isp_var.get(), "@campus")  # 默认为校园网

        logging.info(
            f"尝试登录：用户名 {username}，运营商：{self.isp_var.get()}，密码已提交"
        )
        remember = self.remember_var.get() == 1 if not auto else True

        # URL编码用户名和密码
        encoded_username = urllib.parse.quote(username)
        encoded_password = urllib.parse.quote(password)

        # 拼接完整的登录参数
        sign_parameter = f"{self.config['api_url']}?c=Portal&a=login&callback=dr1004&login_method=1&user_account={encoded_username}{selected_isp_code}&user_password={encoded_password}&wlan_user_ip={self.get_ip()}"
        try:
            # 发送登录请求并获取响应
            response = requests.get(sign_parameter, timeout=5).text
            logging.info(f"登录请求发送成功，响应: {response}")
            response_dict = json.loads(
                response[response.find("{") : response.rfind("}") + 1]
            )  # 提取JSON字符串并转换成字典

            result = response_dict.get("result")
            message = response_dict.get("msg")
            ret_code = response_dict.get("ret_code")

            if result == "1":
                # 登录成功的处理
                logging.info(f"用户 {username} 使用“正确密码”登录成功")
                # 显示通知
                self.master.after(
                    0,
                    lambda: self.show_notification(
                        "登录成功", "校园网状态", self.config["icons"]["success"]
                    ),
                )
                if remember:
                    # 保存凭据
                    self.master.after(
                        0, lambda: self.save_credentials(username, password, remember)
                    )
                self.master.after(0, self.hide_window)
            elif result == "0" and ret_code == 2:
                # 用户已经登录的处理
                logging.info(f"用户 {username} 已经登录")
                # 显示通知
                self.master.after(
                    0,
                    lambda: self.show_notification(
                        "校园网已连接", "校园网状态", self.config["icons"]["already"]
                    ),
                )
                if remember:
                    # 保存凭据
                    self.master.after(
                        0, lambda: self.save_credentials(username, password, remember)
                    )
                self.master.after(0, self.hide_window)
            elif result == "0" and ret_code == 1:
                # 处理登录失败情况
                # 需要解码msg字段以确定具体的错误类型
                decoded_message = self.decode_base64_message(message)
                if "ldap auth error" in decoded_message:
                    # 处理密码错误情况
                    logging.warning(
                        f"用户 {username} 密码错误，尝试的错误密码为：{password}"
                    )
                    # 显示密码错误通知
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "密码错误，请重新尝试",
                            self.config["icons"]["fail"],
                        ),
                    )
                    self.clear_saved_credentials()  # 清除无效凭据
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败", "自动登录失败，密码错误，请重新尝试。"
                            ),
                        )
                elif "userid error1" in decoded_message:
                    # 处理账号或运营商错误情况
                    logging.warning(
                        f"账号或运营商错误，尝试的错误账号为：{username}，错误运营商为：{self.isp_var.get()}"
                    )
                    # 显示账号或运营商错误通知
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "账号或运营商错误，请重新尝试",
                            self.config["icons"]["fail"],
                        ),
                    )
                    self.clear_saved_credentials()
                    self.clear_input_fields()  # 清空输入框的调用
                    self.clear_saved_credentials()  # 清除无效凭据
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，账号或运营商错误，请重新尝试。",
                            ),
                        )
                elif (
                    "Rad:Oppp error: code[062]:num: m[2/0] s[2/2]" in decoded_message
                    or "Reject by concurrency control" in decoded_message
                ):
                    # 处理当前在线设备超过两个情况
                    logging.warning("当前在线设备超过两个")
                    # 打开网页提示用户退出设备
                    self.master.after(
                        0,
                        lambda: webbrowser.open("http://172.30.1.100:8080/Self/login/"),
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "当前在线设备超过两个，请退出部分设备后重新尝试",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，当前在线设备超过两个，请退出部分设备后重新尝试。",
                            ),
                        )
                elif "The subscriber status is incorrect" in decoded_message:
                    # 处理手机欠费停机或宽带到期情况
                    logging.warning("手机欠费停机或宽带到期")
                    # 打开网页提示用户充值或续费
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "手机欠费停机或宽带到期，请及时充值或续费",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，手机欠费停机或宽带到期，请及时充值或续费。",
                            ),
                        )
                elif "The subscriber is expired" in decoded_message:
                    # 处理宽带到期情况
                    logging.warning("宽带到期")
                    # 打开网页提示用户充值或续费
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "宽带到期，请及时充值或续费",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，宽带到期，请及时充值或续费。",
                            ),
                        )
                elif "The subscriber is deregistered or the passw" in decoded_message:
                    # 处理手机号或宽带密码绑定错误或过期情况
                    logging.warning("手机号或宽带密码绑定错误或宽带密码过期")
                    # 打开网页提示用户核查账号信息
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "手机号或宽带密码绑定错误或宽带密码过期，请核查账号信息",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，手机号或宽带密码绑定错误或宽带密码过期，请核查账号信息。",
                            ),
                        )
                elif "Authentication fail" in decoded_message:
                    # 处理AC认证失败情况
                    logging.warning("AC认证失败")
                    # 打开网页提示用户联系网络管理员
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "AC认证失败,请联系网络管理员",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，AC认证失败,请联系网络管理员。",
                            ),
                        )
                elif "系统繁忙" in decoded_message:
                    # 处理系统繁忙情况
                    logging.warning("系统繁忙")
                    # 打开网页提示用户稍后再试
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "系统繁忙，请稍后再试",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败", "自动登录失败，系统繁忙，请稍后再试。"
                            ),
                        )
                elif "注销失败" in decoded_message:
                    # 处理注销失败情况
                    logging.warning("注销失败")
                    # 打开网页提示用户重试
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败", "注销失败，请重试", self.config["icons"]["fail"]
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败", "自动登录失败，注销失败，请重试。"
                            ),
                        )
                elif "IP终端已在线" in decoded_message:
                    # 处理IP终端已在线情况
                    logging.warning("IP终端已在线")
                    # 打开网页提示用户重新登录
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "IP终端已在线,请重新登录",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，IP终端已在线,请重新登录。",
                            ),
                        )
                elif "Rad:Oppp error:" in decoded_message:
                    # 处理拨号建立隧道不成功情况
                    logging.warning("拨号建立隧道不成功")
                    # 打开网页提示用户重新登录
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "拨号建立隧道不成功，请重新登录",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，拨号建立隧道不成功，请重新登录。",
                            ),
                        )
                elif "Mac,Ip,NASip,PORT err(2)" in decoded_message:
                    # 处理运营商错误情况
                    logging.warning("运营商错误")
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "运营商错误，请确认您选择的运营商是否正确",
                            self.config["icons"]["fail"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，运营商错误，请确认您选择的运营商是否正确。",
                            ),
                        )
                else:
                    # 处理未知错误情况
                    logging.warning(f"未知错误：{decoded_message}")
                    # 打开网页提示用户重新登录
                    self.master.after(
                        0, lambda: webbrowser.open("http://172.21.255.105/")
                    )
                    # 尝试打开常见问题文档
                    self.master.after(
                        0, lambda: os.startfile(os.path.join(os.getcwd(), "FAQ.docx"))
                    )
                    self.master.after(
                        0,
                        lambda: self.show_notification(
                            "登录失败",
                            "未知错误，请去报告错误界面提交错误提示后重新尝试",
                            self.config["icons"]["unknown"],
                        ),
                    )
                    # 如果是自动登录且登录失败，考虑显示UI或通知用户
                    if self.show_ui:  # 如果允许显示UI，则重启UI流程
                        self.master.after(0, self.setup_ui)
                        self.master.after(
                            0,
                            lambda: self.show_error_message(
                                "自动登录失败",
                                "自动登录失败，未知错误，请去报告错误界面提交错误提示后重新尝试。",
                            ),
                        )
            else:
                # 记录不符合任一已定义条件的返回值
                logging.error(f"无法解码消息：{message}")
                # 打开网页提示用户重新登录
                self.master.after(0, lambda: webbrowser.open("http://172.21.255.105/"))
                # 尝试打开常见问题文档
                self.master.after(
                    0, lambda: os.startfile(os.path.join(os.getcwd(), "FAQ.docx"))
                )
                self.master.after(
                    0,
                    lambda: self.show_notification(
                        "登录失败",
                        "无法解码消息，请去报告错误界面提交错误提示后重新尝试",
                        self.config["icons"]["unknown"],
                    ),
                )
                # 如果是自动登录且登录失败，考虑显示UI或通知用户
                if self.show_ui:  # 如果允许显示UI，则重启UI流程
                    self.master.after(0, self.setup_ui)
                    self.master.after(
                        0,
                        lambda: self.show_error_message(
                            "自动登录失败",
                            "自动登录失败，无法解码消息，请去报告错误界面提交错误提示后重新尝试。",
                        ),
                    )
        except Exception as e:
            # 记录登录过程中的异常信息
            logging.error(f"登录过程中发生异常：{e}", exc_info=True)
            self.master.after(
                0,
                lambda: self.show_notification(
                    "登录过程中发生异常",
                    "发生未知网络错误。",
                    self.config["icons"]["unknown"],
                ),
            )
            # 如果是自动登录且登录失败，考虑显示UI或通知用户
            if self.show_ui:  # 如果允许显示UI，则重启UI流程
                self.master.after(0, self.setup_ui)
                self.master.after(
                    0,
                    lambda: self.show_error_message(
                        "自动登录失败", "登录过程中发生异常,发生未知网络错误。"
                    ),
                )

    def show_window(self, icon=None, item=None):
        """从托盘恢复窗口"""
        if icon:
            icon.stop()  # 停止托盘图标
        self.master.deiconify()  # 显示窗口
        self.setup_ui()  # 重新设置或刷新UI界面

    def hide_window(self):
        """隐藏窗口并显示托盘图标"""
        self.master.withdraw()  # 隐藏窗口

        def setup_system_tray():
            # 加载托盘图标
            icon_image = Image.open("./icons/ECUT.ico")

            # 创建托盘图标
            self.icon = pystray.Icon(
                "campus_net_login",
                icon=icon_image,
                title="校园网自动登录",
                menu=pystray.Menu(
                    item("打开", self.show_window, default=True),
                    item("退出", self.quit_app),
                ),
            )
            # 运行托盘图标
            self.icon.run_detached()  # 使用run_detached代替run以避免阻塞主线程

        # 在后台线程中设置系统托盘，防止阻塞主线程
        threading.Thread(target=setup_system_tray).start()

    def quit_app(self, icon, item=None):
        """安全退出应用程序"""
        icon.stop()  # 停止图标

        # 安排在主线程中执行的函数
        def quit_app_main_thread():
            self.master.quit()  # 结束Tkinter主事件循环
            self.settings_manager.save_config_to_disk()  # 确保退出前保存配置到磁盘
            self.master.after(0, self.master.destroy)

        self.master.after(
            0, quit_app_main_thread
        )  # 使用after方法来安排在主线程中执行退出应用的操作

    def show_error_message(self, title, message):
        """显示错误信息和用户指导"""
        messagebox.showerror(title, message)  # 弹出错误信息对话框，显示标题和消息

    def save_error_report(self, report):
        filename = "error_reports.txt"  # 错误报告保存到的文件名
        with open(filename, "a") as file:  # 以追加模式打开文件
            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime()
            )  # 获取当前时间戳
            file.write(f"{timestamp}: {report}\n\n")  # 将错误报告和时间戳写入文件

    def report_error(self):
        # 创建一个新的顶级窗口用于报告错误
        error_report_window = tk.Toplevel(self.master)
        error_report_window.title("报告错误")  # 设置窗口标题为"报告错误"

        # 添加标签提示用户描述问题或提供反馈
        tk.Label(error_report_window, text="请描述遇到的问题或提供反馈：").pack(
            padx=10, pady=5
        )
        error_text = tk.Text(error_report_window, height=10, width=50)
        error_text.pack(padx=10, pady=5)

        def submit_report():
            # 获取用户输入的错误描述并去除首尾空格
            report_content = error_text.get("1.0", "end").strip()
            if report_content:
                # 调用save_error_report方法保存错误报告
                self.save_error_report(report_content)
                messagebox.showinfo("报告错误", "您的反馈已提交，谢谢！")
                error_report_window.destroy()  # 销毁报告错误窗口
            else:
                messagebox.showwarning("报告错误", "错误描述不能为空。")

        # 添加提交按钮，点击提交按钮时执行submit_report函数
        tk.Button(error_report_window, text="提交", command=submit_report).pack(pady=5)

    def auto_login(self):
        if self.config.get("auto_login", False):  # 检查配置是否要求自动登录
            username, password, isp, remember = self.load_credentials()  # 加载凭据
            if username and password:
                self.isp_var.set(isp)  # 设置运营商变量
                # 使用加载的凭据进行登录
                self.perform_login(username, password, auto=True)
            else:
                # 如果没有有效的凭据，显示UI以便用户可以手动输入
                if self.show_ui:
                    self.setup_ui()
        else:
            # 如果配置中未启用自动登录，则总是显示UI
            self.setup_ui()

    def open_suggestion_box(self):
        suggestion_window = tk.Toplevel(self.master)  # 创建一个新的顶级窗口用于提交建议
        suggestion_window.title("提交建议")  # 设置窗口标题为"提交建议"

        tk.Label(suggestion_window, text="请分享您的建议或反馈：").pack(
            padx=10, pady=5
        )  # 在窗口中添加文本标签
        suggestion_text = tk.Text(
            suggestion_window, height=10, width=50
        )  # 创建一个文本框用于输入建议
        suggestion_text.pack(padx=10, pady=5)  # 将文本框放置在窗口中

        def submit_suggestion():
            suggestion_content = suggestion_text.get(
                "1.0", "end"
            ).strip()  # 获取用户输入的建议并去除首尾空格
            if suggestion_content:
                self.save_suggestion(
                    suggestion_content
                )  # 调用save_suggestion方法保存建议
                messagebox.showinfo(
                    "提交建议", "您的建议已提交，感谢您的反馈！"
                )  # 弹出信息提示框，确认建议已提交
                suggestion_window.destroy()  # 销毁提交建议窗口
            else:
                messagebox.showwarning(
                    "提交建议", "建议内容不能为空。"
                )  # 弹出警告提示框，提醒建议内容不能为空

        tk.Button(suggestion_window, text="提交", command=submit_suggestion).pack(
            pady=5
        )  # 在窗口中添加提交按钮，并设置点击事件为submit_suggestion函数

    def save_suggestion(self, suggestion):
        filename = "suggestions.txt"  # 建议保存到的文件名
        with open(filename, "a") as file:  # 打开文件并追加内容
            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime()
            )  # 获取当前时间戳
            file.write(f"{timestamp}: {suggestion}\n\n")  # 将建议和时间戳写入文件
        logging.info("用户建议已保存。")  # 记录日志信息

    def center_window(self, width=300, height=200):
        """将窗口置于屏幕中央"""
        # 获取屏幕宽度和高度
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()

        # 计算窗口在屏幕中央的位置
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2

        # 设置窗口的几何尺寸和位置
        self.master.geometry(f"{width}x{height}+{x}+{y}")

    def setup_ui(self):
        self.master.title("校园网自动登录")  # 设置窗口标题为"校园网自动登录"
        self.center_window(
            326, 286
        )  # 调用center_window方法将窗口居中，并设置窗口大小为326x236

        ttk.Label(self.master, text="用户名：").grid(
            row=0, column=0, padx=30, pady=20, sticky="w"
        )  # 创建用户名标签并设置位置和对齐方式
        self.username_entry = ttk.Entry(self.master)  # 创建用户名输入框
        self.username_entry.grid(
            row=0, column=1, padx=3, pady=5, sticky="ew"
        )  # 设置用户名输入框位置和对齐方式

        ttk.Label(self.master, text="密码：").grid(
            row=1, column=0, padx=30, pady=0, sticky="w"
        )  # 创建密码标签并设置位置和对齐方式
        self.password_entry = ttk.Entry(
            self.master, show="*"
        )  # 创建密码输入框，显示为*
        self.password_entry.grid(
            row=1, column=1, padx=3, pady=5, sticky="ew"
        )  # 设置密码输入框位置和对齐方式

        self.password_strength_label = ttk.Label(
            self.master, text=""
        )  # 创建用于显示密码强度的标签
        self.password_strength_label.grid(
            row=2, column=1, padx=10, sticky="w"
        )  # 设置密码强度标签位置

        # 密码可见性切换按钮
        self.toggle_password_btn = tk.Button(
            self.master,
            image=self.eye_closed_icon,
            command=self.toggle_password_visibility,
            borderwidth=0,
        )  # 创建密码可见性切换按钮
        self.toggle_password_btn.grid(
            row=1, column=2, sticky="e"
        )  # 设置密码可见性切换按钮位置

        self.remember_var = tk.IntVar()  # 创建用于记住账号和密码的变量
        ttk.Checkbutton(
            self.master, text="记住账号和密码", variable=self.remember_var
        ).grid(
            row=3, column=0, columnspan=1, padx=20, pady=5
        )  # 创建勾选框

        self.isp_var = tk.StringVar()  # 创建用于存储ISP选择的变量
        self.isp_combobox = ttk.Combobox(
            self.master, textvariable=self.isp_var, state="readonly", width=8
        )  # 创建ISP选择下拉框
        self.isp_combobox["values"] = (
            "中国电信",
            "中国移动",
            "中国联通",
            "校园网",
        )  # 设置ISP下拉框的选项
        self.isp_combobox.grid(row=3, column=1, pady=5, sticky="e")  # 设置ISP下拉框位置

        # 设置默认值
        isp_mapping = {
            "telecom": "中国电信",
            "cmcc": "中国移动",
            "unicom": "中国联通",
            "campus": "校园网",
        }
        self.isp_combobox.set(
            isp_mapping.get(self.config.get("isp", "campus"), "校园网")
        )  # 设置默认选项为校园网

        ttk.Button(self.master, text="登录", command=self.login).grid(
            row=4, columnspan=3, padx=32, pady=10, sticky="ew"
        )  # 创建登录按钮
        ttk.Button(self.master, text="设置", command=self.open_settings).grid(
            row=5, column=0, columnspan=3, padx=30, pady=10, sticky="ew"
        )  # 创建设置按钮
        ttk.Button(self.master, text="报告问题", command=self.report_error).grid(
            row=6, column=0, padx=30, pady=10, sticky="ew"
        )  # 创建报告问题按钮
        ttk.Button(self.master, text="提交建议", command=self.open_suggestion_box).grid(
            row=6, column=1, padx=6, pady=10, sticky="ew"
        )  # 创建提交建议按钮

        # 自动填充逻辑
        username, password, isp, remember = self.load_credentials()  # 加载保存的凭据
        if (
            username and password and remember
        ):  # 如果有保存的用户名、密码，并且选择了记住
            self.username_entry.insert(0, username)  # 自动填充到输入框
            self.password_entry.insert(0, password)
            self.isp_combobox.set(isp)  # 设置运营商下拉框
            self.remember_var.set(1)

    def toggle_password_visibility(self):
        """
        切换密码框中的密码可见性，并更新切换按钮的图标
        """
        if self.password_visible:
            # 如果密码可见，则将密码框中的字符显示为'*'
            self.password_entry.config(show="*")
            # 更新切换密码可见性按钮的图标为关闭眼睛图标
            self.toggle_password_btn.config(image=self.eye_closed_icon)
            # 更新密码可见性标志为False，密码不可见
            self.password_visible = False
        else:
            # 如果密码不可见，则将密码框中的字符显示为原文=
            self.password_entry.config(show="")
            # 更新切换密码可见性按钮的图标为打开眼睛图标
            self.toggle_password_btn.config(image=self.eye_open_icon)
            # 更新密码可见性标志为True，密码可见
            self.password_visible = True

    def open_settings(self):
        self.master.withdraw()  # 隐藏主窗口
        settings_window = tk.Toplevel(self.master)
        settings_window.title("设置")
        self.center_window_on_parent(
            settings_window, 290, 286
        )  # 调整设置窗口大小以适应新内容

        # 创建“开机时自动启动”复选框
        self.auto_start_var = tk.IntVar(value=self.config.get("auto_start", False))
        tk.Checkbutton(
            settings_window, text="开机时自动启动", variable=self.auto_start_var
        ).grid(row=2, column=1, columnspan=2, padx=10, pady=10, sticky="w")

        # 在设置窗口中添加“自动登录”复选框
        self.auto_login_var = tk.IntVar(value=self.config.get("auto_login", False))
        auto_login_checkbox = tk.Checkbutton(
            settings_window, text="自动登录", variable=self.auto_login_var
        )
        auto_login_checkbox.grid(
            row=1, column=1, columnspan=2, padx=10, pady=10, sticky="w"
        )

        # 创建API URL输入框
        tk.Label(settings_window, text="API URL:").grid(
            row=0, column=0, padx=10, pady=10, sticky="e"
        )
        api_url_entry = tk.Entry(settings_window)
        api_url_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        api_url_entry.insert(0, self.config.get("api_url", ""))

        def clear_key_and_credentials_wrapper():
            self.clear_key_and_credentials()
            settings_window.destroy()

        def clear_credentials_wrapper():
            self.clear_credentials()
            settings_window.destroy()

        # 创建清除密钥和用户凭证按钮
        clear_key_button = tk.Button(
            settings_window,
            text="清除密钥和用户凭证",
            command=clear_key_and_credentials_wrapper,
        )
        clear_key_button.grid(row=5, column=0, columnspan=2, pady=10)

        # 创建清除用户凭证按钮
        clear_credentials_button = tk.Button(
            settings_window, text="清除用户凭证", command=clear_credentials_wrapper
        )
        clear_credentials_button.grid(row=4, column=0, columnspan=2, pady=10)

        settings_window.grid_columnconfigure(1, weight=1)

        def save_settings_and_close(api_url):
            # 弹出确认对话框，询问用户是否确定要保存设置
            confirm = messagebox.askyesno("确认保存设置", "您确定要保存这些设置吗？")
            if confirm:
                self.config["api_url"] = api_url
                self.config["auto_start"] = bool(self.auto_start_var.get())
                self.config["auto_login"] = bool(
                    self.auto_login_var.get()
                )  # 更新自动登录的配置
                self.settings_manager.save_config(self.config)
                self.settings_manager.save_config_to_disk()  # 确保退出前保存配置到磁盘
                messagebox.showinfo("设置", "配置已保存。应用将重启以应用更改。")
                settings_window.destroy()
                self.apply_auto_start_setting()
                self.restart_app()
            else:
                # 如果用户选择不保存更改，则只关闭确认对话框，不执行后续操作
                return

        def save_settings_wrapper():
            save_settings_and_close(api_url_entry.get())

        # 创建保存和取消按钮
        buttons_frame = tk.Frame(settings_window)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(buttons_frame, text="保存", command=save_settings_wrapper).pack(
            side=tk.LEFT, padx=5
        )
        tk.Button(
            buttons_frame,
            text="取消",
            command=lambda: self.on_settings_close(settings_window),
        ).pack(side=tk.RIGHT, padx=5)

        # 将关闭窗口的功能绑定到窗口关闭事件
        settings_window.protocol(
            "WM_DELETE_WINDOW", lambda: self.on_settings_close(settings_window)
        )

    def on_settings_close(self, settings_window):
        settings_window.destroy()  # 关闭设置窗口
        self.master.deiconify()  # 重新显示主窗口

    def clear_key_and_credentials(self):
        """清除存储的加密密钥，如果找到，则清除用户凭证"""
        confirm = messagebox.askyesno(
            "确认清除", "这将清除所有保存的用户凭证和加密密钥。您确定要继续吗?"
        )
        if confirm:
            key_cleared = False
            credentials_cleared = False

            # 尝试删除密钥文件
            try:
                os.remove("encryption_key.key")
                logging.info("加密密钥已被清除。")
                key_cleared = True
            except FileNotFoundError:
                logging.warning("找不到密钥文件，无法删除。")

            # 尝试删除凭证文件
            try:
                os.remove("encrypted_credentials.pkl")
                logging.info("用户凭证已被清除。")
                credentials_cleared = True
            except FileNotFoundError:
                logging.warning("找不到凭证文件，无法删除。")

            # 根据文件清除的情况给出相应的提示
            if key_cleared and credentials_cleared:
                messagebox.showinfo("清除完成", "加密密钥和用户凭证均已被清除。")
            elif key_cleared:
                messagebox.showinfo("清除完成", "加密密钥已被清除，未找到用户凭证。")
            elif credentials_cleared:
                messagebox.showinfo("清除完成", "用户凭证已被清除，未找到加密密钥。")
            else:
                messagebox.showinfo(
                    "清除失败", "未找到加密密钥和用户凭证，无需进行清除。"
                )

            # 如果至少清除了一个文件，则重启应用
            if key_cleared or credentials_cleared:
                self.restart_app()

    def clear_credentials(self):
        """仅清除存储的用户凭证"""
        # 弹出确认对话框，让用户确认清除操作
        confirm = messagebox.askyesno(
            "确认清除", "这将清除所有保存的用户凭证。您确定要继续吗？"
        )
        if confirm:
            try:
                # 尝试删除存储用户凭证的文件
                os.remove("encrypted_credentials.pkl")
                logging.info("用户凭证已被清除。")  # 记录日志，说明用户凭证已被清除
                # 弹出信息提示框，告知用户凭证已被清除
                messagebox.showinfo("清除完成", "所有保存的用户凭证已被清除。")
                self.restart_app()  # 重新启动应用程序
            except FileNotFoundError:
                logging.warning(
                    "找不到凭证文件，无法删除。"
                )  # 记录警告日志，说明找不到凭证文件
                # 弹出信息提示框，告知用户未找到用户凭证文件，无需清除
                messagebox.showinfo("清除失败", "没有找到用户凭证文件，无需进行清除。")

    def apply_auto_start_setting(self):
        start_up_folder = winshell.startup()  # 获取Windows启动文件夹路径
        shortcut_path = os.path.join(
            start_up_folder, "CampusNetLoginApp.lnk"
        )  # 设置快捷方式路径和文件名
        if self.config.get("auto_start"):  # 检查配置中是否开启了自动启动
            if not os.path.exists(shortcut_path):  # 如果快捷方式不存在
                # 使用winshell创建快捷方式
                script_path = os.path.join(
                    os.getcwd(), "校园网登录程序.exe"
                )  # 设置可执行文件的路径
                with winshell.shortcut(shortcut_path) as shortcut:
                    shortcut.path = script_path  # 设置快捷方式的目标路径
                    shortcut.description = "自动登录校园网的应用"  # 设置快捷方式描述
                    shortcut.working_directory = os.getcwd()  # 设置工作目录为当前目录
        else:
            if os.path.exists(shortcut_path):  # 如果快捷方式存在
                # 删除快捷方式
                os.remove(shortcut_path)

    def restart_app(self):
        def restart():
            # 等待一小段时间，确保主进程有足够的时间退出
            time.sleep(1)
            # 使用subprocess启动新的应用实例
            subprocess.Popen(["校园网登录程序.exe"])
            # 退出当前应用
            self.master.quit()

        # 在后台线程中执行重启逻辑，以避免阻塞UI或其他处理
        threading.Thread(target=restart).start()

    def center_window_on_parent(self, child, width, height):
        """将子窗口置于父窗口中央"""
        # 获取父窗口的位置和大小
        parent_x = self.master.winfo_x()  # 获取父窗口的x坐标
        parent_y = self.master.winfo_y()  # 获取父窗口的y坐标
        parent_width = self.master.winfo_width()  # 获取父窗口的宽度
        parent_height = self.master.winfo_height()  # 获取父窗口的高度
        # 计算子窗口在父窗口中央的位置
        x = parent_x + (parent_width - width) // 2  # 计算子窗口的x坐标
        y = parent_y + (parent_height - height) // 2  # 计算子窗口的y坐标
        # 设置子窗口的位置和大小
        child.geometry(f"{width}x{height}+{x}+{y}")  # 设置子窗口的宽度、高度、和位置

    def show_notification(self, title, msg, icon_path=None):
        # 注册窗口类。
        wc = win32gui.WNDCLASS()
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpszClassName = "CampusNetLoginAppNotification"
        wc.lpfnWndProc = {
            win32con.WM_DESTROY: self.on_destroy
        }  # 可以添加更多消息处理。

        try:
            class_atom = win32gui.RegisterClass(wc)
        except pywintypes.error as e:
            if "类已存在。" in str(e):
                # 类已存在，可以继续使用
                pass
            else:
                raise  # 重新抛出其他类型的异常

        # 创建窗口。
        style = win32con.WS_OVERLAPPED | win32con.WS_SYSMENU
        self.hwnd = win32gui.CreateWindow(
            "CampusNetLoginAppNotification",
            "CampusNetLoginApp Notification Window",
            style,
            0,
            0,
            win32con.CW_USEDEFAULT,
            win32con.CW_USEDEFAULT,
            0,
            0,
            wc.hInstance,
            None,
        )
        win32gui.UpdateWindow(self.hwnd)

        # 显示通知。
        if icon_path and os.path.isfile(
            icon_path
        ):  # 检查是否有指定图标路径并且文件存在
            icon_flags = win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE
            hicon = win32gui.LoadImage(
                None, icon_path, win32con.IMAGE_ICON, 0, 0, icon_flags
            )  # 加载图标
        else:
            hicon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)  # 使用默认图标

        flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
        nid = (self.hwnd, 0, flags, win32con.WM_USER + 20, hicon, "Tooltip")
        win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, nid)  # 添加通知图标
        win32gui.Shell_NotifyIcon(
            win32gui.NIM_MODIFY,
            (
                self.hwnd,
                0,
                win32gui.NIF_INFO,
                win32con.WM_USER + 20,
                hicon,
                "Balloon Tooltip",
                msg,
                200,
                title,
            ),
        )  # 修改通知为气球提示
        timer = threading.Timer(5.0, self.clear_notification_icon)  # 5秒后执行清理
        timer.start()

    def clear_notification_icon(self):
        """清理通知图标的方法"""
        win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (self.hwnd, 0))

    def on_destroy(self, hwnd, msg, wparam, lparam):
        """处理窗口销毁消息"""
        self.settings_manager.save_config_to_disk()


if __name__ == "__main__":
    root = tk.Tk()  # 创建一个Tkinter的根窗口对象
    root.withdraw()  # 隐藏根窗口，不显示在屏幕上

    # 创建设置管理器实例
    settings_manager = CampusNetSettingsManager()
    # 创建应用程序实例
    app = CampusNetLoginApp(root, settings_manager=settings_manager, show_ui=True)

    # 传递 settings_manager 实例到关闭函数
    root.protocol("WM_DELETE_WINDOW", lambda: on_main_close(root, settings_manager))

    if app.show_ui:  # 如果需要显示UI界面
        root.deiconify()  # 显示根窗口

    root.mainloop()  # 进入Tkinter的主事件循环，等待用户交互```
