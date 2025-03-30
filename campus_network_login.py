# campus_network_login.py
# 时间：2024/05/10
# 作者：周咏霖
# 版本：V1.4.2

import tkinter as tk  # 导入tkinter库，用于GUI界面创建
from tkinter import (
    messagebox,
    ttk,
)  # 从tkinter导入messagebox和ttk，用于图形界面中的对话框和高级组件
import requests  # 导入requests库，用于处理HTTP请求
import os  # 导入os库，用于处理操作系统级别的接口，如文件管理
import json  # 导入json库，用于处理JSON数据格式
from cryptography.fernet import Fernet  # 从cryptography库导入Fernet，用于加密
import pickle  # 导入pickle库，用于对象的序列化和反序列化
import logging  # 导入logging库，用于记录日志
from logging.handlers import (
    TimedRotatingFileHandler,
)  # 从logging.handlers导入TimedRotatingFileHandler，用于按时间轮转记录日志到文件
import subprocess  # 导入subprocess库，用于调用外部进程
import socket  # 导入socket库，用于网络通信
import threading  # 导入threading库，用于多线程编程
import time  # 导入time库，用于时间操作
import win32api  # 导入win32api库，用于Windows API操作
import win32con  # 导入win32con库，用于Windows常量定义
import win32gui  # 导入win32gui库，用于Windows GUI操作
import base64  # 导入base64库，用于编码和解码base64数据
import webbrowser  # 导入webbrowser，用于在浏览器中打开URL
import winshell  # 导入winshell库用于Windows快捷方式操作
import pywintypes  # 导入pywintypes库，用于Windows API操作
import urllib.parse  # 导入urllib库，用于URL编码
import pystray  # 导入pystray库，用于系统托盘图标
from pystray import MenuItem as item  # 从pystray库中导入MenuItem类并将其重命名为item，用于托盘菜单
from PIL import Image  # 导入PIL库中的Image类，用于图像处理
from packaging import version  # 导入packaging库，用于版本号比较
import win32event  # 导入win32event模块，用于Windows事件操作
import winerror  # 导入winerror模块，用于Windows错误码
import sys  # 导入sys库，用于系统相关的操作


# 互斥锁管理类
class AppMutex:
    _instance = None
    
    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls.mutex = None
            cls.mutex_created = False
        return cls._instance
    
    def create(self):
        try:
            # 正确传递三个参数
            self.mutex = win32event.CreateMutex(
                None,           # 安全属性
                True,           # 立即拥有
                "Global\\CampusNetLoginAppMutex"  # 唯一名称
            )
            last_error = win32api.GetLastError()
            
            if last_error == winerror.ERROR_ALREADY_EXISTS:
                print("程序已在运行")
                self.cleanup()
                sys.exit(0)
            else:
                self.mutex_created = True
                print("互斥锁创建成功")
                
        except pywintypes.error as e:
            if e.winerror == winerror.ERROR_ACCESS_DENIED:
                logging.error("权限不足，无法创建互斥锁")
            else:
                logging.error(f"系统错误: {e.strerror} (代码 {e.winerror})")

    
    def cleanup(self):
        if self.mutex_created and self.mutex:
            win32event.ReleaseMutex(self.mutex)
            win32api.CloseHandle(self.mutex)
            self.mutex_created = False
            print("互斥锁已释放")


# 定义一个自定义的日志过滤器类PasswordFilter
class PasswordFilter(logging.Filter):  # 继承logging.Filter类
    def filter(self, record):  # 定义过滤器方法
        message = record.getMessage()  # 获取日志记录的消息
        if "user_password=" in message:  # 如果日志信息中包含'user_password='
            new_message = message.replace(
                message.split("user_password=")[1].split("&")[0], "********"
            )  # 将密码部分替换为'********'
            record.msg = new_message  # 更新日志记录的消息
            record.args = ()  # 清空args以避免格式化错误
        return True  # 返回True以允许记录消息


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
    if not os.path.exists(log_directory):  # 如果日志目录不存在
        os.makedirs(log_directory)  # 创建日志目录

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


def on_main_close(root, settings_manager):  # 主窗口关闭事件处理函数
    global mutex, mutex_created  # 声明全局变量mutex和mutex_created
    if messagebox.askokcancel(
        "退出", "确定要退出应用吗？"
    ):  # 弹出确认对话框，用户确认退出应用
        settings_manager.save_config_to_disk()  # 确保退出前保存配置到磁盘
        root.destroy()  # 销毁主窗口，退出应用
        if mutex and mutex_created:  # 如果互斥锁存在且已创建
            win32event.ReleaseMutex(mutex)  # 释放互斥锁
            win32api.CloseHandle(mutex)  # 关闭互斥锁的句柄
            mutex_created = False  # 重置互斥锁创建标志


setup_logging()  # 调用日志设置函数


config_lock = threading.Lock()  # 创建一个线程锁


class CampusNetSettingsManager:  # 定义一个校园网设置管理器类
    def __init__(self, config_file="config.json", default_config=None):  # 初始化方法
        self.config_lock = threading.Lock()  # 创建一个线程锁
        self.cached_config = {}  # 创建一个缓存配置的字典
        self.config_file = config_file  # 配置文件名
        self.default_config = {  # 默认配置
            "api_url": "http://172.21.255.105:801/eportal/",  # API URL
            "icons": {  # 图标
                "already": "./icons/Internet.ico",  # 已登录
                "success": "./icons/Check.ico",  # 成功
                "fail": "./icons/Cross.ico",  # 失败
                "unknown": "./icons/Questionmark.ico",  # 未知
            },
            "minimize_to_tray_on_login": True,  # 默认情况下登录成功后最小化到托盘
            "auto_login": False,  # 默认情况下不自动登录
            "isp": "campus",  # 默认运营商为校园网
            "auto_start": False,  # 默认情况下不自动启动
        }

    # 程序当前版本
    CURRENT_VERSION = "1.4.2"

    def load_or_create_config(self):  # 加载或创建配置
        if self.cached_config:  # 如果缓存配置存在
            return self.cached_config  # 直接返回缓存配置

        logging.debug("尝试加载配置文件...")  # 记录调试信息：尝试加载配置文件

        with self.config_lock:  # 使用线程锁
            if not os.path.exists(self.config_file):  # 如果配置文件不存在
                logging.info(
                    "配置文件不存在，创建默认配置文件。"
                )  # 记录信息：配置文件不存在，创建默认配置文件
                with open(
                    self.config_file, "w"
                ) as config_file:  # 以写入模式打开配置文件
                    json.dump(
                        self.default_config, config_file
                    )  # 将默认配置写入配置文件
            else:  # 如果配置文件存在
                logging.info("配置文件加载成功。")  # 记录信息：配置文件加载成功
            with open(self.config_file, "r") as config_file:  # 以只读模式打开配置文件
                self.cached_config = json.load(config_file)  # 加载配置文件到缓存配置

        return self.cached_config  # 返回缓存配置

    def save_config_to_disk(self):  # 保存配置到磁盘
        logging.debug("保存配置到文件中...")  # 记录调试信息：保存配置到文件中
        with self.config_lock:  # 使用线程锁
            with open(self.config_file, "w") as config_file:  # 以写入模式打开配置文件
                json.dump(self.cached_config, config_file)  # 将缓存配置保存到配置文件
        logging.info("配置已保存到磁盘")  # 记录信息：配置已保存到磁盘

    def save_config(self, config):  # 保存配置
        self.cached_config.update(config)  # 更新缓存配置
        logging.info("配置已更新到缓存")  # 记录信息：配置已更新到缓存


class CampusNetLoginApp:  # 定义一个校园网登录应用类

    def __init__(self, master, settings_manager, show_ui=True):  # 初始化方法
        self.master = master  # 初始化主窗口
        self.config_lock = threading.Lock()  # 初始化线程锁用于保护配置文件的读写
        self.settings_manager = settings_manager  # 初始化设置管理器
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

    def load_config(self):  # 加载配置
        # 定义加载配置的函数，使用load_or_create_config函数来加载配置
        return self.settings_manager.load_or_create_config()

    @staticmethod  # 静态方法
    def load_or_generate_key():  # 加载或生成密钥
        # 定义加载或生成密钥的函数
        key_file = "encryption_key.key"  # 密钥文件名
        if os.path.exists(key_file):  # 如果密钥文件已存在
            with open(key_file, "rb") as file:  # 以二进制读取模式打开密钥文件
                key = file.read()  # 从文件中读取密钥
        else:  # 如果密钥文件不存在
            key = Fernet.generate_key()  # 生成新的密钥
            logging.debug("新建密钥文件")  # 记录调试信息：新建密钥文件
            with open(key_file, "wb") as file:  # 以二进制写入模式打开密钥文件
                file.write(key)  # 将新生成的密钥写入文件
            messagebox.showinfo(
                "密钥生成", "新的加密密钥已生成并保存。"
            )  # 弹出提示框显示密钥已生成
        return key, Fernet(key)  # 返回密钥及使用该密钥初始化的Fernet对象

    @staticmethod  # 静态方法
    def get_ip():
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
            "username": username,  # 用户名
            "password": encrypted_password,  # 加密后的密码
            "isp": self.isp_var.get(),  # 运营商
            "remember": remember,  # 是否记住密码
        }
        with open(
            "encrypted_credentials.pkl", "wb"
        ) as file:  # 以二进制写入模式打开文件
            pickle.dump(credentials, file)  # 将凭据信息序列化保存到文件中

        logging.info(
            f"保存凭据：用户名 {username}, 记住密码：{'是' if remember else '否'}, 运营商：{self.isp_var.get()}"
        )  # 记录保存凭据的信息

        # 保存运营商选择
        isp_reverse_mapping = {
            "中国电信": "telecom",  # 中国电信
            "中国移动": "cmcc",  # 中国移动
            "中国联通": "unicom",  # 中国联通
            "campus": "校园网",  # 校园网
        }  # 定义运营商映射关系
        self.config["isp"] = isp_reverse_mapping.get(
            self.isp_var.get(), "campus"
        )  # 获取用户选择的运营商映射值，默认为校园网
        self.settings_manager.save_config(self.config)  # 保存配置信息

    def load_credentials(self):  # 加载凭据
        try:
            # 尝试打开名为'encrypted_credentials.pkl'的文件
            with open(
                "encrypted_credentials.pkl", "rb"
            ) as file:  # 以二进制读取模式打开文件
                # 从文件中加载凭据
                credentials = pickle.load(file)
                # 获取用户名和解密后的密码
                username = credentials["username"]
                password = self.cipher_suite.decrypt(credentials["password"]).decode()
                isp = credentials.get("isp", "campus")  # 默认运营商为校园网
                remember = credentials.get("remember", False)  # 默认不记住密码
                return (
                    username,
                    password,
                    isp,
                    remember,
                )  # 返回用户名、密码、运营商和是否记住密码
        except FileNotFoundError:  # 处理文件未找到异常
            # 若文件未找到，则返回空值
            return "", "", "campus", False

    @staticmethod  # 静态方法
    def clear_saved_credentials():  # 清除保存的凭据
        try:
            # 尝试删除名为'encrypted_credentials.pkl'的文件
            os.remove("encrypted_credentials.pkl")
        except FileNotFoundError:
            # 若文件未找到，则忽略异常
            pass

    def login(self):  # 登录
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
            login_thread.start()  # 启动登录线程
        else:  # 如果用户名或密码为空
            messagebox.showwarning(
                "验证失败", "用户名或密码为空，请按要求填写。"
            )  # 显示警告框，提示用户名或密码为空

    @staticmethod  # 静态方法
    def validate_credentials(username, password):
        """验证用户名和密码是否为空"""
        if not username or not password:  # 如果用户名或密码为空
            logging.warning("验证失败：用户名或密码为空")
            # 记录警告信息：用户名或密码为空
            return False  # 返回False
        return True  # 返回True

    @staticmethod  # 静态方法
    def decode_base64_message(b64message):
        """解码Base64消息"""
        try:
            return base64.b64decode(b64message).decode(
                "utf-8"
            )  # 尝试解码Base64消息并以utf-8编码返回
        except Exception as e:  # 处理Base64消息解码异常
            logging.error(
                f"Base64消息解码失败:{e}"
            )  # 记录错误日志，提示Base64消息解码失败
            return None

    @staticmethod  # 静态方法
    def load_login_responses():
        # 加载登录响应配置
        config_file_path = "./login_responses.json"  # 配置文件路径
        try:
            with open(
                config_file_path, "r", encoding="utf-8"
            ) as file:  # 以只读模式打开配置文件
                login_responses = json.load(file)  # 从文件中加载JSON数据
            return login_responses  # 返回加载的JSON数据
        except IOError as e:
            # 文件打开失败的处理代码
            print(f"Error opening the configuration file: {e}")  # 打印错误信息
        except json.JSONDecodeError as e:
            # JSON解码失败的处理代码
            print(f"Error parsing the configuration file: {e}")  # 打印错误信息

    # 处理登录结果
    def handle_login_result(self, response_dict, username, password, remember):
        # 从JSON文件加载响应配置
        response_config = self.load_login_responses()

        result = response_dict.get("result")  # 获取响应中的结果
        ret_code = response_dict.get("ret_code")  # 获取响应中的返回码
        msg = response_dict.get("msg")  # 获取响应中的消息

        # 根据结果和返回码确定结果
        outcome = ""  # 初始化结果
        if result == "1":  # 如果结果为"1"，表示成功
            outcome = "success"  # 结果为成功
        elif result == "0" and ret_code == 2:  # 如果结果为"0"且返回码为2,表示已经登录
            outcome = "already_logged_in"  # 结果为已经登录
        elif result == "0" and ret_code == 1:  # 如果结果为"0"且返回码为1,表示登录失败
            decode_msg = self.decode_base64_message(msg)  # 解码消息
            outcome = decode_msg  # 结果为解码后的消息
        else:
            # 未知登录错误
            logging.error(f"未知登录错误：{response_dict}")
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
                    "未知登录错误，请去报告错误界面提交错误提示后重新尝试",
                    self.config["icons"]["unknown"],
                ),
            )  # 显示通知
            return  # 返回

        response = response_config.get(outcome)  # 根据结果获取相应的响应配置

        if response:  # 如果存在响应配置
            # 执行相应的操作
            message1 = response["message1"]  # 获取通知
            message2 = response["message2"]  # 获取解决方案
            icon = response["icon"]  # 获取图标
            action = response["action"]  # 获取操作
        else:
            # 获取未知的登录失败的响应配置
            message1 = "未知错误"  # 获取通知
            message2 = (
                "未知错误，请去报告错误界面提交错误提示后重新尝试"  # 获取解决方案
            )
            icon = "unknown"  # 获取图标
            action = "unknown error"  # 获取操作

        self.execute_response_action(
            outcome, message1, message2, icon, action, username, password, remember
        )  # 执行响应的操作

    # 根据响应配置执行相应操作
    def execute_response_action(
        self, outcome, message1, message2, icon, action, username, password, remember
    ):
        self.show_notification(
            message1, "校园网状态", self.config["icons"][icon]
        )  # 显示通知
        if action == "already_logged_in" or action == "success":  # 用户已经登录的处理
            if remember:  # 如果记住密码
                # 保存凭据
                self.master.after(
                    0, lambda: self.save_credentials(username, password, remember)
                )
            if action == "already_logged_in":  # 如果操作为用户已经登录
                logging.info(f"用户 {username} 已经登录")  # 记录信息：用户已经登录
            elif action == "success":  # 如果操作为登录成功
                logging.info(f"用户 {username} 登录成功")  # 记录信息：用户登录成功
                # 根据配置决定是最小化到托盘还是退出程序
                if self.config.get("minimize_to_tray_on_login", True):
                    self.master.after(
                        0, self.hide_window
                    )  # 如果配置为 True 则最小化到托盘
                else:
                    self.master.after(0, self.quit_app)  # 如果配置为 False 则退出程序
        else:  # 处理各种失败情况
            self.show_error_message("登录失败", message2)  # 显示错误消息
            if action == "show_web1":  # 如果操作为打开网页1
                self.master.after(
                    0, lambda: webbrowser.open("http://172.30.1.100:8080/Self/login/")
                )  # 打开网页1
            elif action == "clear_credentials1":  # 如果操作为处理密码错误情况
                logging.warning(
                    f"用户 {username} 密码错误，尝试的错误密码为：{password}"
                )  # 记录警告：用户密码错误
                self.clear_saved_credentials()  # 清除保存的凭据
            elif action == "clear_credentials2":  # 如果操作为处理账号或运营商错误情况
                logging.warning(
                    f"账号或运营商错误，尝试的错误账号为：{username}，错误运营商为：{self.isp_var.get()}"
                )  # 记录警告：账号或运营商错误
                self.clear_saved_credentials()  # 清除保存的凭据
            elif action == "show_web2":  # 如果操作为打开网页2
                self.master.after(
                    0, lambda: webbrowser.open("http://172.21.255.105/")
                )  # 打开网页2
            else:  # 处理未知错误情况
                logging.warning(f"未知错误：{outcome}")
                # 打开网页提示用户重新登录
                self.master.after(0, lambda: webbrowser.open("http://172.21.255.105/"))
                # 尝试打开常见问题文档
                self.master.after(
                    0, lambda: os.startfile(os.path.join(os.getcwd(), "FAQ.docx"))
                )

    # 加载登录响应配置
    def perform_login(self, username, password, auto=False):
        logging.debug(
            f"开始登录流程，用户名: {username}, 自动登录: {str(auto)}"
        )  # 记录调试信息
        # 运营商标识映射
        isp_codes = {
            "中国电信": "@telecom",  # 中国电信
            "中国移动": "@cmcc",  # 中国移动
            "中国联通": "@unicom",  # 中国联通
            "校园网": "@campus",  # 校园网
        }
        selected_isp_code = isp_codes.get(self.isp_var.get(), "@campus")  # 默认为校园网

        logging.info(
            f"尝试登录：用户名 {username}，运营商：{self.isp_var.get()}，密码已提交"
        )  # 记录信息：尝试登录
        remember = self.remember_var.get() == 1 if not auto else True  # 记住密码

        # URL编码用户名和密码
        encoded_username = urllib.parse.quote(username)
        encoded_password = urllib.parse.quote(password)

        # 拼接完整的登录参数
        sign_parameter = f"{self.config['api_url']}?c=Portal&a=login&callback=dr1004&login_method=1&user_account={encoded_username}{selected_isp_code}&user_password={encoded_password}&wlan_user_ip={self.get_ip()}"

        try:
            # 发送登录请求并将响应存储在名为'response'的变量中
            response = requests.get(sign_parameter, timeout=5).text
            logging.info(
                f"登录请求发送成功，响应: {response}"
            )  # 记录信息：登录请求发送成功
            response_dict = json.loads(
                response[response.find("{") : response.rfind("}") + 1]
            )  # 解析响应为字典形式

            self.handle_login_result(
                response_dict, username, password, remember
            )  # 处理登录结果的函数调用

        except Exception as e:  # 处理登录请求异常
            # 记录登录过程中的异常信息
            logging.error(f"登录过程中发生异常：{e}", exc_info=True)
            self.master.after(
                0,
                lambda: self.show_notification(
                    "登录过程中发生异常",
                    "发生未知网络错误。",
                    self.config["icons"]["unknown"],
                ),
            )  # 显示通知

    def show_window(self, icon=None, item=None):
        """从托盘恢复窗口"""
        if icon:  # 如果提供了icon参数
            icon.stop()  # 停止托盘图标
        self.master.deiconify()  # 显示窗口
        self.setup_ui()  # 重新设置或刷新UI界面

    def hide_window(self):
        """隐藏窗口并显示托盘图标"""
        self.master.withdraw()  # 隐藏窗口

        def setup_system_tray():  # 设置系统托盘
            # 加载托盘图标
            icon_image = Image.open("./icons/ECUT.ico")

            # 创建托盘图标
            self.icon = pystray.Icon(
                "campus_net_login",  # 托盘图标的名称
                icon=icon_image,  # 托盘图标的图像
                title="校园网自动登录",  # 托盘图标的标题
                menu=pystray.Menu(
                    item("打开", self.show_window, default=True),
                    item("退出", lambda icon, item: self.quit_app(icon)),
                ),  # 托盘图标的菜单
            )
            # 运行托盘图标
            self.icon.run_detached()

        # 在后台线程中设置系统托盘，防止阻塞主线程
        threading.Thread(target=setup_system_tray).start()

    def quit_app(self, icon=None, item=None):  # 退出应用
        if icon:  # 如果提供了icon参数
            icon.stop()  # 停止托盘图标
        # 保存配置，清理资源，退出程序的其余步骤
        self.master.quit()
        # 可能有必要的清理步骤
        self.master.destroy()

    @staticmethod  # 静态方法
    def show_error_message(title, message):
        """显示错误信息和用户指导"""
        messagebox.showerror(title, message)  # 弹出错误信息对话框，显示标题和消息

    @staticmethod  # 静态方法
    def save_error_report(report):  # 保存错误报告
        filename = "error_reports.txt"  # 错误报告保存到的文件名
        with open(filename, "a") as file:  # 以追加模式打开文件
            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime()
            )  # 获取当前时间戳
            file.write(f"{timestamp}: {report}\n\n")  # 将错误报告和时间戳写入文件

    def report_error(self):
        # 创建一个新的顶级窗口用于报告错误
        error_report_window = tk.Toplevel(self.master)  # 创建一个新的顶级窗口
        error_report_window.title("报告错误")  # 设置窗口标题为"报告错误"

        # 添加标签提示用户描述问题或提供反馈
        tk.Label(error_report_window, text="请描述遇到的问题或提供反馈：").pack(
            padx=10, pady=5
        )
        error_text = tk.Text(error_report_window, height=10, width=50)  # 创建文本框
        error_text.pack(padx=10, pady=5)  # 将文本框放置在窗口中

        def submit_report():  # 提交错误报告
            # 获取用户输入的错误描述并去除首尾空格
            report_content = error_text.get("1.0", "end").strip()
            if report_content:  # 如果错误描述不为空
                # 调用save_error_report方法保存错误报告
                self.save_error_report(report_content)
                messagebox.showinfo(
                    "报告错误", "您的反馈已提交，谢谢！"
                )  # 弹出信息提示框
                error_report_window.destroy()  # 销毁报告错误窗口
            else:  # 如果错误描述为空
                messagebox.showwarning(
                    "报告错误", "错误描述不能为空。"
                )  # 弹出警告提示框

        # 添加提交按钮，点击提交按钮时执行submit_report函数
        tk.Button(error_report_window, text="提交", command=submit_report).pack(pady=5)

    def auto_login(self):  # 自动登录
        if self.config.get("auto_login", False):  # 检查配置是否要求自动登录
            username, password, isp, remember = self.load_credentials()  # 加载凭据
            if username and password:  # 如果用户名和密码存在
                self.isp_var.set(isp)  # 设置运营商变量
                # 使用加载的凭据进行登录
                self.perform_login(username, password, auto=True)
            else:
                # 如果没有有效的凭据，显示UI以便用户可以手动输入
                if self.show_ui:  # 如果配置中启用了自动登录
                    self.setup_ui()  # 显示UI
        else:
            # 如果配置中未启用自动登录，则总是显示UI
            self.setup_ui()

    def open_suggestion_box(self):  # 打开建议框
        suggestion_window = tk.Toplevel(self.master)  # 创建一个新的顶级窗口用于提交建议
        suggestion_window.title("提交建议")  # 设置窗口标题为"提交建议"

        tk.Label(suggestion_window, text="请分享您的建议或反馈：").pack(
            padx=10, pady=5
        )  # 在窗口中添加文本标签
        suggestion_text = tk.Text(
            suggestion_window, height=10, width=50
        )  # 创建一个文本框用于输入建议
        suggestion_text.pack(padx=10, pady=5)  # 将文本框放置在窗口中

        def submit_suggestion():  # 提交建议
            suggestion_content = suggestion_text.get(
                "1.0", "end"
            ).strip()  # 获取用户输入的建议并去除首尾空格
            if suggestion_content:  # 如果建议内容不为空
                self.save_suggestion(
                    suggestion_content
                )  # 调用save_suggestion方法保存建议
                messagebox.showinfo(
                    "提交建议", "您的建议已提交，感谢您的反馈！"
                )  # 弹出信息提示框，确认建议已提交
                suggestion_window.destroy()  # 销毁提交建议窗口
            else:  # 如果建议内容为空
                messagebox.showwarning(
                    "提交建议", "建议内容不能为空。"
                )  # 弹出警告提示框，提醒建议内容不能为空

        tk.Button(suggestion_window, text="提交", command=submit_suggestion).pack(
            pady=5
        )  # 在窗口中添加提交按钮，并设置点击事件为submit_suggestion函数

    @staticmethod  # 静态方法
    def save_suggestion(suggestion):  # 保存建议
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

    def setup_ui(self):  # 设置UI
        self.master.title("校园网自动登录")  # 设置窗口标题
        self.center_window(width=296, height=228)  # 将窗口置于屏幕中央

        main_frame = ttk.Frame(self.master)  # 创建一个新的框架
        main_frame.pack(
            padx=10, pady=10, expand=True, fill=tk.BOTH
        )  # 将框架放置在窗口中

        ttk.Label(main_frame, text="用户名：", anchor="w").grid(
            row=0, column=0, padx=5, pady=5, sticky="ew"
        )  # 在框架中添加标签
        self.username_entry = ttk.Entry(main_frame)  # 创建一个输入框
        self.username_entry.grid(
            row=0, column=1, padx=5, pady=5, sticky="ew"
        )  # 将输入框放置在框架中

        ttk.Label(main_frame, text="密码：", anchor="w").grid(
            row=1, column=0, padx=5, pady=5, sticky="ew"
        )  # 在框架中添加标签
        self.password_entry = ttk.Entry(main_frame, show="*")  # 创建一个密码输入框
        self.password_entry.grid(
            row=1, column=1, padx=5, pady=5, sticky="ew"
        )  # 将密码输入框放置在框架中

        self.toggle_password_btn = tk.Button(
            main_frame,
            image=self.eye_closed_icon,
            command=self.toggle_password_visibility,
            borderwidth=0,
        )  # 创建一个按钮
        self.toggle_password_btn.grid(
            row=1, column=2, padx=5, pady=5, sticky="w"
        )  # 将按钮放置在框架中

        self.remember_var = tk.IntVar()  # 创建一个整型变量
        ttk.Checkbutton(
            main_frame, text="记住账号和密码", variable=self.remember_var
        ).grid(
            row=2, column=0, columnspan=3, padx=5, pady=5, sticky="w"
        )  # 在框架中添加复选框

        self.isp_combobox = ttk.Combobox(
            main_frame, textvariable=self.isp_var, state="readonly", width=12
        )  # 创建一个下拉框
        self.isp_combobox["values"] = (
            "中国电信",
            "中国移动",
            "中国联通",
            "校园网",
        )  # 设置下拉框的选项
        self.isp_combobox.grid(
            row=2, column=1, columnspan=2, padx=5, pady=5, sticky="e"
        )  # 将下拉框放置在框架中

        # 登录按钮
        ttk.Button(main_frame, text="登录", command=self.login).grid(
            row=3, column=0, columnspan=3, padx=5, pady=5, sticky="ew"
        )  # 在框架中添加按钮

        # 设置按钮
        ttk.Button(main_frame, text="设置", command=self.open_settings).grid(
            row=4, column=0, columnspan=3, padx=5, pady=5, sticky="ew"
        )  # 在框架中添加按钮

        # 报告问题和提交建议按钮
        ttk.Button(main_frame, text="报告问题", command=self.report_error).grid(
            row=5, column=0, columnspan=1, padx=5, pady=5, sticky="ew"
        )  # 在框架中添加按钮
        ttk.Button(main_frame, text="提交建议", command=self.open_suggestion_box).grid(
            row=5, column=1, columnspan=2, padx=5, pady=5, sticky="ew"
        )  # 在框架中添加按钮

        # 加载保存的用户名和密码，如果设置了记住我
        username, password, isp, remember = self.load_credentials()  # 加载凭据
        if username and password and remember:  # 如果用户名和密码存在且记住密码
            self.username_entry.insert(0, username)  # 在用户名输入框中插入用户名
            self.password_entry.insert(0, password)  # 在密码输入框中插入密码
            self.isp_combobox.set(isp)  # 设置运营商下拉框
            self.remember_var.set(1)  # 设置记住密码复选框为选中状态

        # 配置列权重
        main_frame.columnconfigure(1, weight=1)  # 第二列应在需要时扩展
        main_frame.columnconfigure(
            0, minsize=70
        )  # 第一列设置最小宽度，确保标签不会被压缩

        self.master.update()  # 更新主窗口，以便下面的代码能获取到最新的尺寸信息

        report_button = ttk.Button(
            main_frame, text="报告问题", command=self.report_error
        )  # 创建报告问题按钮
        suggest_button = ttk.Button(
            main_frame, text="提交建议", command=self.open_suggestion_box
        )  # 创建提交建议按钮
        report_button.grid(
            row=5, column=0, padx=5, pady=5, sticky="ew"
        )  # 报告问题按钮放置在框架中
        suggest_button.grid(
            row=5, column=1, columnspan=2, padx=5, pady=5, sticky="ew"
        )  # 提交建议按钮放置在框架中

        # 设置按钮让它们在同一行中拥有相同的宽度
        main_frame.grid_columnconfigure(0, weight=1)  # 报告问题按钮占据列宽
        main_frame.grid_columnconfigure(1, weight=1)  # 提交建议按钮占据列宽
        main_frame.grid_columnconfigure(
            2, weight=1
        )  # 保持第三列扩展能力，使所有列均匀分配空间

        # 如果窗口过大（比如在高DPI屏幕上），设置合适的窗口尺寸和位置
        current_width = self.master.winfo_width()  # 获取当前窗口宽度
        current_height = self.master.winfo_height()  # 获取当前窗口高度
        screen_width = self.master.winfo_screenwidth()  # 获取屏幕宽度
        screen_height = self.master.winfo_screenheight()  # 获取屏幕高度

        if current_width > screen_width or current_height > screen_height:
            # 如果窗口比屏幕尺寸大，重新调整大小
            scaled_width = int(current_width * 0.9)  # 缩小窗口宽度
            scaled_height = int(current_height * 0.9)  # 缩小窗口高度
            self.center_window(
                width=scaled_width, height=scaled_height
            )  # 将窗口置于屏幕中央

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
        # 隐藏主窗口以显示设置窗口
        self.master.withdraw()  # 隐藏主窗口
        settings_window = tk.Toplevel(self.master)  # 创建设置窗口
        settings_window.title("设置")  # 设置设置窗口标题为"设置"
        settings_window.resizable(False, False)  # 设置设置窗口大小不可调整
        self.center_window_on_parent(settings_window, 300, 212)  # 调整设置窗口的大小
        self.minimize_to_tray_var = tk.IntVar(
            value=self.config.get("minimize_to_tray_on_login", True)
        )  # 获取配置中的最小化到托盘变量
        self.auto_start_var = tk.IntVar(
            value=self.config.get("auto_start", False)
        )  # 获取配置中的自动启动变量
        self.auto_login_var = tk.IntVar(
            value=self.config.get("auto_login", False)
        )  # 获取配置中的自动登录变量

        main_frame = ttk.Frame(settings_window)  # 创建主Frame
        main_frame.pack(
            padx=15, pady=15, fill=tk.BOTH, expand=True
        )  # 为主Frame添加内边距

        ttk.Label(main_frame, text="API URL：").grid(
            row=0, column=0, pady=(0, 10), sticky="w"
        )  # 创建API URL标签
        api_url_entry = ttk.Entry(main_frame)  # 创建API URL输入框
        api_url_entry.grid(
            row=0, column=1, pady=(0, 10), sticky="ew"
        )  # 设置API URL输入框位置

        minimize_to_tray_checkbox = ttk.Checkbutton(
            main_frame,
            text="登录成功后最小化到托盘",
            variable=self.minimize_to_tray_var,
        )  # 创建最小化到托盘勾选框
        minimize_to_tray_checkbox.grid(
            row=1, column=0, columnspan=2, pady=(0, 10), sticky="w"
        )  # 设置最小化到托盘勾选框位置

        auto_start_checkbox = ttk.Checkbutton(
            main_frame, text="开机时自动启动", variable=self.auto_start_var
        )  # 创建开机时自动启动勾选框
        auto_start_checkbox.grid(
            row=2, column=0, columnspan=2, pady=(0, 10), sticky="w"
        )  # 设置开机时自动启动勾选框位置

        auto_login_checkbox = ttk.Checkbutton(
            main_frame, text="自动登录", variable=self.auto_login_var
        )  # 创建自动登录勾选框
        auto_login_checkbox.grid(
            row=3, column=0, columnspan=2, pady=(0, 10), sticky="w"
        )  # 设置自动登录勾选框位置

        clear_key_button = ttk.Button(
            main_frame,
            text="清除密钥和用户凭证",
            command=self.clear_key_and_credentials,
        )  # 创建清除密钥和用户凭证按钮
        clear_key_button.grid(
            row=4, column=0, pady=(10, 0), sticky="ew"
        )  # 修改Button的对齐方式

        clear_credentials_button = ttk.Button(
            main_frame, text="清除用户凭证", command=self.clear_credentials
        )  # 创建清除用户凭证按钮
        clear_credentials_button.grid(
            row=4, column=1, pady=(10, 0), sticky="ew"
        )  # 修改Button的对齐方式

        main_frame.grid_columnconfigure(1, weight=1)  # 让Entry能随窗口宽度改变

        # 设置网格内部件之间的距离
        for child in main_frame.winfo_children():
            child.grid_configure(padx=5, pady=2)  # 设置内部件之间的水平和垂直间距

        # 创建取消按钮
        cancel_button = ttk.Button(
            main_frame,
            text="取消",
            command=lambda: self.on_settings_close(settings_window),
        )
        cancel_button.grid(
            row=5, column=1, pady=(10, 0), sticky="e"
        )  # 设置取消按钮位置

        # 创建保存按钮
        save_button = ttk.Button(
            main_frame,
            text="保存",
            command=lambda: self.save_settings_and_close(
                api_url_entry.get(), settings_window
            ),
        )
        save_button.grid(row=5, column=0, pady=(10, 0), sticky="w")  # 设置保存按钮位置

        # 默认由弹窗加载时把先前设置的API URL填入Entry
        api_url_entry.insert(0, self.config.get("api_url", ""))

        # 设置窗口关闭的协议处理函数
        settings_window.protocol(
            "WM_DELETE_WINDOW", lambda: self.on_settings_close(settings_window)
        )

    def save_settings_and_close(self, api_url, settings_window):  # 保存设置并关闭
        # 弹出确认保存设置对话框
        confirm = messagebox.askyesno("确认保存设置", "您确定要保存这些设置吗？")
        if confirm:  # 如果用户选择确认
            # 更新程序的配置实例
            self.config["api_url"] = api_url  # 更新API URL
            self.config["minimize_to_tray_on_login"] = (
                self.minimize_to_tray_var.get()
            )  # 更新最小化到托盘设置
            self.config["auto_start"] = self.auto_start_var.get()  # 更新自动启动设置
            self.config["auto_login"] = self.auto_login_var.get()  # 更新自动登录设置

            # 保存配置到管理器和磁盘
            self.settings_manager.save_config(self.config)  # 保存配置到管理器
            self.settings_manager.save_config_to_disk()  # 保存配置到磁盘

            # 更新启动时自动启动设置
            self.apply_auto_start_setting()

            # 显示已保存配置的消息，并关闭设置窗口
            messagebox.showinfo("设置", "配置已保存。")  # 弹出信息提示框
            settings_window.destroy()  # 关闭设置窗口
            self.restart_app()  # 重启应用程序
        else:
            # 如果用户选择取消，不保存更改，并关闭设置窗口
            settings_window.destroy()
            return  # 返回

    def on_settings_close(self, settings_window):  # 设置窗口关闭
        settings_window.destroy()  # 关闭设置窗口
        self.master.deiconify()  # 重新显示主窗口

    def clear_key_and_credentials(self):
        """清除存储的加密密钥，如果找到，则清除用户凭证"""
        confirm = messagebox.askyesno(
            "确认清除", "这将清除所有保存的用户凭证和加密密钥。您确定要继续吗?"
        )  # 弹出确认对话框，让用户确认清除操作
        if confirm:  # 如果用户选择确认
            key_cleared = False  # 初始化加密密钥清除标志为False
            credentials_cleared = False  # 初始化用户凭证清除标志为False

            # 尝试删除密钥文件
            try:
                os.remove("encryption_key.key")  # 删除密钥文件
                logging.info("加密密钥已被清除。")  # 记录日志，说明加密密钥已被清除
                key_cleared = True  # 设置加密密钥清除标志为True
            except FileNotFoundError:  # 如果找不到密钥文件
                logging.warning(
                    "找不到密钥文件，无法删除。"
                )  # 记录警告日志，说明找不到密钥文件

            # 尝试删除凭证文件
            try:
                os.remove("encrypted_credentials.pkl")  # 删除凭证文件
                logging.info("用户凭证已被清除。")  # 记录日志，说明用户凭证已被清除
                credentials_cleared = True  # 设置用户凭证清除标志为True
            except FileNotFoundError:  # 如果找不到凭证文件
                logging.warning(
                    "找不到凭证文件，无法删除。"
                )  # 记录警告日志，说明找不到凭证文件

            # 根据文件清除的情况给出相应的提示
            if key_cleared and credentials_cleared:  # 如果加密密钥和用户凭证均已被清除
                messagebox.showinfo(
                    "清除完成", "加密密钥和用户凭证均已被清除。"
                )  # 弹出信息提示框
            elif key_cleared:  # 如果仅清除了加密密钥
                messagebox.showinfo(
                    "清除完成", "加密密钥已被清除，未找到用户凭证。"
                )  # 弹出信息提示框
            elif credentials_cleared:  # 如果仅清除了用户凭证
                messagebox.showinfo(
                    "清除完成", "用户凭证已被清除，未找到加密密钥。"
                )  # 弹出信息提示框
            else:  # 如果加密密钥和用户凭证均未被清除
                messagebox.showinfo(
                    "清除失败", "未找到加密密钥和用户凭证，无需进行清除。"
                )  # 弹出信息提示框

            # 如果至少清除了一个文件，则重启应用
            if key_cleared or credentials_cleared:
                self.restart_app()  # 重启应用程序

    def clear_credentials(self):
        """仅清除存储的用户凭证"""
        # 弹出确认对话框，让用户确认清除操作
        confirm = messagebox.askyesno(
            "确认清除", "这将清除所有保存的用户凭证。您确定要继续吗？"
        )
        if confirm:  # 如果用户选择确认
            try:
                # 尝试删除存储用户凭证的文件
                os.remove("encrypted_credentials.pkl")  # 删除用户凭证文件
                logging.info("用户凭证已被清除。")  # 记录日志，说明用户凭证已被清除
                # 弹出信息提示框，告知用户凭证已被清除
                messagebox.showinfo("清除完成", "所有保存的用户凭证已被清除。")
                self.restart_app()  # 重新启动应用程序
            except FileNotFoundError:  # 如果找不到凭证文件
                logging.warning(
                    "找不到凭证文件，无法删除。"
                )  # 记录警告日志，说明找不到凭证文件
                # 弹出信息提示框，告知用户未找到用户凭证文件，无需清除
                messagebox.showinfo("清除失败", "没有找到用户凭证文件，无需进行清除。")

    def apply_auto_start_setting(self):  # 应用自动启动设置
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
                with winshell.shortcut(shortcut_path) as shortcut:  # 创建快捷方式
                    shortcut.path = script_path  # 设置快捷方式的目标路径
                    shortcut.description = "自动登录校园网的应用"  # 设置快捷方式描述
                    shortcut.working_directory = os.getcwd()  # 设置工作目录为当前目录
        else:  # 如果配置中未开启自动启动
            if os.path.exists(shortcut_path):  # 如果快捷方式存在
                # 删除快捷方式
                os.remove(shortcut_path)

    def restart_app(self):  # 重启应用程序
        def restart():  # 重启逻辑
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
        """显示通知的方法"""
        wc = win32gui.WNDCLASS()  # 创建WNDCLASS实例
        wc.hInstance = win32api.GetModuleHandle(None)  # 获取当前实例句柄
        wc.lpszClassName = "CampusNetLoginAppNotification"  # 设置窗口类名
        wc.lpfnWndProc = {
            win32con.WM_DESTROY: self.on_destroy
        }  # 设置窗口消息处理函数，处理销毁消息

        try:
            class_atom = win32gui.RegisterClass(wc)  # 注册窗口类
        except pywintypes.error as e:  # 捕获Windows API错误
            if "类已存在。" in str(e):
                # 类已存在，可以继续使用
                pass  # 什么也不做
            else:
                raise  # 重新抛出其他类型的异常

        style = win32con.WS_OVERLAPPED | win32con.WS_SYSMENU  # 设置窗口样式
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
        )  # 创建窗口
        win32gui.UpdateWindow(self.hwnd)  # 更新窗口

        # 显示通知。
        if icon_path and os.path.isfile(
            icon_path
        ):  # 检查是否有指定图标路径并且文件存在
            icon_flags = win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE
            hicon = win32gui.LoadImage(
                None, icon_path, win32con.IMAGE_ICON, 0, 0, icon_flags
            )  # 加载图标
        else:  # 如果没有指定图标路径或文件不存在
            hicon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)  # 使用默认图标

        flags = (
            win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
        )  # 设置通知图标的标志
        nid = (
            self.hwnd,
            0,
            flags,
            win32con.WM_USER + 20,
            hicon,
            "Tooltip",
        )  # 设置通知图标的属性
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
        timer.start()  # 启动定时器

    def clear_notification_icon(self):
        """清理通知图标的方法"""
        win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (self.hwnd, 0))  # 删除通知图标

    def on_destroy(self, hwnd, msg, wparam, lparam):
        """处理窗口销毁消息"""
        self.settings_manager.save_config_to_disk()  # 保存配置到磁盘


if __name__ == "__main__":  # 如果当前脚本被直接运行
    # 尝试创建一个互斥锁
    mutex = win32event.CreateMutex(
        None, True, "Global\\CampusNetLoginAppMutex"
    )  # 创建一个互斥锁
    last_error = win32api.GetLastError()  # 获取最后一个错误

    if last_error == winerror.ERROR_ALREADY_EXISTS:  # 如果互斥锁已经存在
        messagebox.showinfo("校园网自动登录", "应用程序已在运行。")  # 弹出信息提示框
        sys.exit(0)  # 退出程序
    else:  # 如果互斥锁不存在
        mutex_created = True  # 设置互斥锁创建标志为True

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

    # 程序退出时，确保释放资源
    if mutex_created:  # 如果互斥锁已经创建
        win32event.ReleaseMutex(mutex)  # 释放互斥锁
        win32api.CloseHandle(mutex)  # 关闭互斥锁
        mutex_created = False  # 重置互斥锁创建标志为False
