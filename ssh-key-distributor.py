#!/usr/bin/env python3
"""
SSH Key Distributor - SSH密钥分发与管理工具

功能:
1. 批量分发公钥到多台服务器
2. 支持密码、密钥、跳板机等多种认证方式
3. 自动备份原有authorized_keys
4. 验证分发结果
5. 密钥过期管理和轮换

使用场景:
- 新员工入职，分发密钥到所有服务器
- 员工离职，批量删除密钥
- 定期轮换密钥
- 应急场景快速分发临时密钥

作者: DevOps Team
"""

import argparse
import sys
import os
import paramiko
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import json
import yaml
from typing import List, Dict, Tuple
from colorama import init, Fore, Style

init(autoreset=True)

class SSHKeyDistributor:
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.results = {
            'success': [],
            'failed': [],
            'skipped': []
        }
    
    def _load_config(self, config_file: str) -> dict:
        """加载配置文件"""
        if config_file and os.path.exists(config_file):
            with open(config_file) as f:
                if config_file.endswith('.json'):
                    return json.load(f)
                elif config_file.endswith(('.yml', '.yaml')):
                    return yaml.safe_load(f)
        return {}
    
    def _get_ssh_client(self, host: str, port: int, username: str, 
                       password: str = None, key_file: str = None,
                       jump_host: dict = None) -> paramiko.SSHClient:
        """创建SSH连接"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # 如果有跳板机，先连接跳板机
            if jump_host:
                jump_client = paramiko.SSHClient()
                jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                jump_auth = {}
                if jump_host.get('key_file'):
                    jump_auth['key_filename'] = jump_host['key_file']
                elif jump_host.get('password'):
                    jump_auth['password'] = jump_host['password']
                
                jump_client.connect(
                    jump_host['host'],
                    port=jump_host.get('port', 22),
                    username=jump_host['username'],
                    **jump_auth
                )
                
                # 通过跳板机建立到目标主机的通道
                jump_transport = jump_client.get_transport()
                dest_addr = (host, port)
                local_addr = (jump_host['host'], jump_host.get('port', 22))
                jump_channel = jump_transport.open_channel("direct-tcpip", dest_addr, local_addr)
                
                # 使用通道连接目标主机
                if key_file:
                    client.connect(host, port=port, username=username, 
                                 key_filename=key_file, sock=jump_channel)
                else:
                    client.connect(host, port=port, username=username, 
                                 password=password, sock=jump_channel)
            else:
                # 直接连接
                if key_file:
                    client.connect(host, port=port, username=username, 
                                 key_filename=key_file, timeout=10)
                else:
                    client.connect(host, port=port, username=username, 
                                 password=password, timeout=10)
            
            return client
        except Exception as e:
            raise Exception(f"SSH连接失败: {str(e)}")
    
    def _backup_authorized_keys(self, client: paramiko.SSHClient, user: str) -> bool:
        """备份现有的authorized_keys"""
        try:
            backup_time = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f"~{user}/.ssh/authorized_keys.backup_{backup_time}"
            
            stdin, stdout, stderr = client.exec_command(
                f"[ -f ~{user}/.ssh/authorized_keys ] && "
                f"cp ~{user}/.ssh/authorized_keys {backup_file} || true"
            )
            return stdout.channel.recv_exit_status() == 0
        except Exception as e:
            print(f"{Fore.YELLOW}警告: 备份失败 - {str(e)}")
            return False
    
    def distribute_key(self, host: str, port: int, username: str, 
                      target_user: str, public_key: str,
                      auth_method: str = 'password', auth_value: str = None,
                      jump_host: dict = None, verify: bool = True) -> Tuple[bool, str]:
        """
        分发公钥到单台服务器
        
        Args:
            host: 目标主机
            port: SSH端口
            username: SSH登录用户
            target_user: 要添加密钥的目标用户
            public_key: 公钥内容
            auth_method: 认证方式 (password/key)
            auth_value: 密码或密钥文件路径
            jump_host: 跳板机配置
            verify: 是否验证分发结果
        """
        try:
            # 建立SSH连接
            if auth_method == 'password':
                client = self._get_ssh_client(host, port, username, 
                                             password=auth_value, jump_host=jump_host)
            else:
                client = self._get_ssh_client(host, port, username, 
                                             key_file=auth_value, jump_host=jump_host)
            
            # 备份现有密钥
            self._backup_authorized_keys(client, target_user)
            
            # 确保.ssh目录存在且权限正确
            commands = [
                f"mkdir -p ~{target_user}/.ssh",
                f"chmod 700 ~{target_user}/.ssh",
                f"touch ~{target_user}/.ssh/authorized_keys",
                f"chmod 600 ~{target_user}/.ssh/authorized_keys"
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(f"sudo {cmd}")
                if stdout.channel.recv_exit_status() != 0:
                    error = stderr.read().decode()
                    raise Exception(f"命令执行失败: {cmd}\n{error}")
            
            # 检查密钥是否已存在
            key_comment = public_key.split()[-1] if len(public_key.split()) > 2 else ""
            check_cmd = f"grep -F '{key_comment}' ~{target_user}/.ssh/authorized_keys || echo 'not_found'"
            stdin, stdout, stderr = client.exec_command(f"sudo {check_cmd}")
            output = stdout.read().decode().strip()
            
            if output != 'not_found':
                client.close()
                return True, f"密钥已存在，跳过"
            
            # 添加公钥
            escaped_key = public_key.replace("'", "'\\''")
            add_cmd = f"echo '{escaped_key}' | sudo tee -a ~{target_user}/.ssh/authorized_keys > /dev/null"
            stdin, stdout, stderr = client.exec_command(add_cmd)
            
            if stdout.channel.recv_exit_status() != 0:
                error = stderr.read().decode()
                raise Exception(f"添加密钥失败: {error}")
            
            # 修正所有者
            chown_cmd = f"sudo chown -R {target_user}:{target_user} ~{target_user}/.ssh"
            client.exec_command(chown_cmd)
            
            # 验证
            if verify:
                verify_cmd = f"grep -F '{key_comment}' ~{target_user}/.ssh/authorized_keys"
                stdin, stdout, stderr = client.exec_command(f"sudo {verify_cmd}")
                if stdout.channel.recv_exit_status() != 0:
                    raise Exception("验证失败: 密钥未正确写入")
            
            client.close()
            return True, "分发成功"
            
        except Exception as e:
            return False, str(e)
    
    def remove_key(self, host: str, port: int, username: str,
                  target_user: str, key_identifier: str,
                  auth_method: str = 'password', auth_value: str = None,
                  jump_host: dict = None) -> Tuple[bool, str]:
        """
        从服务器删除指定密钥
        
        Args:
            key_identifier: 密钥标识符（可以是注释、指纹或部分公钥内容）
        """
        try:
            if auth_method == 'password':
                client = self._get_ssh_client(host, port, username, 
                                             password=auth_value, jump_host=jump_host)
            else:
                client = self._get_ssh_client(host, port, username, 
                                             key_file=auth_value, jump_host=jump_host)
            
            # 备份
            self._backup_authorized_keys(client, target_user)
            
            # 删除包含标识符的行
            remove_cmd = f"sudo sed -i.bak '/{key_identifier}/d' ~{target_user}/.ssh/authorized_keys"
            stdin, stdout, stderr = client.exec_command(remove_cmd)
            
            if stdout.channel.recv_exit_status() != 0:
                error = stderr.read().decode()
                raise Exception(f"删除失败: {error}")
            
            client.close()
            return True, "删除成功"
            
        except Exception as e:
            return False, str(e)
    
    def batch_distribute(self, hosts: List[Dict], public_key_file: str,
                        max_workers: int = 10, dry_run: bool = False):
        """
        批量分发密钥
        
        Args:
            hosts: 主机列表，每个元素是包含连接信息的字典
            public_key_file: 公钥文件路径
            max_workers: 最大并发数
            dry_run: 演习模式，不实际执行
        """
        # 读取公钥
        try:
            with open(public_key_file) as f:
                public_key = f.read().strip()
        except Exception as e:
            print(f"{Fore.RED}错误: 无法读取公钥文件 - {str(e)}")
            return
        
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}SSH密钥批量分发")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"公钥文件: {public_key_file}")
        print(f"目标主机数: {len(hosts)}")
        print(f"并发数: {max_workers}")
        print(f"模式: {'演习' if dry_run else '执行'}")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if dry_run:
            print(f"{Fore.YELLOW}演习模式: 仅显示将要执行的操作\n")
            for i, host_info in enumerate(hosts, 1):
                print(f"{i}. {host_info['host']}:{host_info.get('port', 22)} "
                      f"user={host_info.get('target_user', 'root')}")
            return
        
        # 执行分发
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            
            for host_info in hosts:
                future = executor.submit(
                    self.distribute_key,
                    host=host_info['host'],
                    port=host_info.get('port', 22),
                    username=host_info.get('username', 'root'),
                    target_user=host_info.get('target_user', 'root'),
                    public_key=public_key,
                    auth_method=host_info.get('auth_method', 'password'),
                    auth_value=host_info.get('auth_value'),
                    jump_host=host_info.get('jump_host'),
                    verify=host_info.get('verify', True)
                )
                futures[future] = host_info
            
            # 收集结果
            for future in as_completed(futures):
                host_info = futures[future]
                host = host_info['host']
                
                try:
                    success, message = future.result()
                    if success:
                        print(f"{Fore.GREEN}✓ {host}: {message}")
                        self.results['success'].append(host)
                    else:
                        print(f"{Fore.RED}✗ {host}: {message}")
                        self.results['failed'].append({'host': host, 'error': message})
                except Exception as e:
                    print(f"{Fore.RED}✗ {host}: 异常 - {str(e)}")
                    self.results['failed'].append({'host': host, 'error': str(e)})
        
        # 打印汇总
        self._print_summary()
    
    def _print_summary(self):
        """打印执行结果汇总"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}执行结果汇总")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}成功: {len(self.results['success'])} 台")
        print(f"{Fore.RED}失败: {len(self.results['failed'])} 台")
        print(f"{Fore.YELLOW}跳过: {len(self.results['skipped'])} 台")
        
        if self.results['failed']:
            print(f"\n{Fore.RED}失败详情:")
            for item in self.results['failed']:
                print(f"  - {item['host']}: {item['error']}")
        
        print(f"{Fore.CYAN}{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='SSH密钥分发与管理工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:

  # 单台服务器分发
  %(prog)s distribute -H 192.168.1.10 -u root -k ~/.ssh/id_rsa.pub

  # 使用配置文件批量分发
  %(prog)s batch -c hosts.yaml -k ~/.ssh/id_rsa.pub

  # 通过跳板机分发
  %(prog)s distribute -H 10.0.1.5 -u root -k ~/.ssh/id_rsa.pub \\
      --jump-host jump.example.com --jump-user jumper

  # 删除密钥
  %(prog)s remove -H 192.168.1.10 -u root --key-id "user@hostname"

  # 演习模式（查看将要执行的操作）
  %(prog)s batch -c hosts.yaml -k ~/.ssh/id_rsa.pub --dry-run
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='子命令')
    
    # distribute子命令
    distribute_parser = subparsers.add_parser('distribute', help='分发密钥到单台服务器')
    distribute_parser.add_argument('-H', '--host', required=True, help='目标主机IP')
    distribute_parser.add_argument('-p', '--port', type=int, default=22, help='SSH端口')
    distribute_parser.add_argument('-u', '--username', default='root', help='SSH登录用户')
    distribute_parser.add_argument('-t', '--target-user', help='目标用户（默认同登录用户）')
    distribute_parser.add_argument('-k', '--key-file', required=True, help='公钥文件路径')
    distribute_parser.add_argument('--auth-method', choices=['password', 'key'], 
                                  default='password', help='认证方式')
    distribute_parser.add_argument('--auth-value', help='密码或私钥文件路径')
    distribute_parser.add_argument('--jump-host', help='跳板机地址')
    distribute_parser.add_argument('--jump-user', help='跳板机用户')
    distribute_parser.add_argument('--jump-key', help='跳板机私钥')
    
    # batch子命令
    batch_parser = subparsers.add_parser('batch', help='批量分发密钥')
    batch_parser.add_argument('-c', '--config', required=True, help='主机配置文件（YAML/JSON）')
    batch_parser.add_argument('-k', '--key-file', required=True, help='公钥文件路径')
    batch_parser.add_argument('-w', '--workers', type=int, default=10, help='并发数')
    batch_parser.add_argument('--dry-run', action='store_true', help='演习模式')
    
    # remove子命令
    remove_parser = subparsers.add_parser('remove', help='删除密钥')
    remove_parser.add_argument('-H', '--host', required=True, help='目标主机IP')
    remove_parser.add_argument('-p', '--port', type=int, default=22, help='SSH端口')
    remove_parser.add_argument('-u', '--username', default='root', help='SSH登录用户')
    remove_parser.add_argument('-t', '--target-user', help='目标用户')
    remove_parser.add_argument('--key-id', required=True, help='密钥标识符（注释或指纹）')
    remove_parser.add_argument('--auth-method', choices=['password', 'key'], 
                              default='password', help='认证方式')
    remove_parser.add_argument('--auth-value', help='密码或私钥文件路径')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    distributor = SSHKeyDistributor()
    
    if args.command == 'distribute':
        # 处理认证信息
        if not args.auth_value:
            if args.auth_method == 'password':
                args.auth_value = getpass.getpass('SSH密码: ')
            else:
                print("错误: 使用密钥认证时必须提供 --auth-value")
                sys.exit(1)
        
        # 处理跳板机
        jump_host = None
        if args.jump_host:
            jump_host = {
                'host': args.jump_host,
                'username': args.jump_user or 'root',
                'key_file': args.jump_key
            }
            if not jump_host['key_file']:
                jump_host['password'] = getpass.getpass('跳板机密码: ')
        
        # 读取公钥
        with open(args.key_file) as f:
            public_key = f.read().strip()
        
        target_user = args.target_user or args.username
        success, message = distributor.distribute_key(
            args.host, args.port, args.username, target_user,
            public_key, args.auth_method, args.auth_value, jump_host
        )
        
        if success:
            print(f"{Fore.GREEN}✓ {message}")
        else:
            print(f"{Fore.RED}✗ {message}")
            sys.exit(1)
    
    elif args.command == 'batch':
        distributor.batch_distribute(
            distributor.config.get('hosts', []),
            args.key_file,
            args.workers,
            args.dry_run
        )
    
    elif args.command == 'remove':
        if not args.auth_value:
            if args.auth_method == 'password':
                args.auth_value = getpass.getpass('SSH密码: ')
            else:
                print("错误: 使用密钥认证时必须提供 --auth-value")
                sys.exit(1)
        
        target_user = args.target_user or args.username
        success, message = distributor.remove_key(
            args.host, args.port, args.username, target_user,
            args.key_id, args.auth_method, args.auth_value
        )
        
        if success:
            print(f"{Fore.GREEN}✓ {message}")
        else:
            print(f"{Fore.RED}✗ {message}")
            sys.exit(1)


if __name__ == '__main__':
    main()
