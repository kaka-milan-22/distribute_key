# SSH密钥分发工具使用文档

## 📋 目录
- [快速开始](#快速开始)
- [功能特性](#功能特性)
- [安装配置](#安装配置)
- [使用场景](#使用场景)
- [高级用法](#高级用法)
- [最佳实践](#最佳实践)
- [故障排查](#故障排查)

---

## 🚀 快速开始

### 安装依赖
```bash
pip install paramiko pyyaml colorama --break-system-packages
```

### 基础用法

#### 1. 分发密钥到单台服务器
```bash
# 使用密码认证
python ssh-key-distributor.py distribute \
  -H 192.168.1.10 \
  -u root \
  -k ~/.ssh/id_rsa.pub

# 使用密钥认证
python ssh-key-distributor.py distribute \
  -H 192.168.1.10 \
  -u root \
  --auth-method key \
  --auth-value ~/.ssh/id_rsa \
  -k ~/.ssh/id_rsa.pub
```

#### 2. 批量分发（推荐）
```bash
# 从配置文件读取主机列表
python ssh-key-distributor.py batch \
  -c hosts.yaml \
  -k ~/.ssh/id_rsa.pub

# 演习模式（查看将要执行的操作，不实际执行）
python ssh-key-distributor.py batch \
  -c hosts.yaml \
  -k ~/.ssh/id_rsa.pub \
  --dry-run

# 自定义并发数
python ssh-key-distributor.py batch \
  -c hosts.yaml \
  -k ~/.ssh/id_rsa.pub \
  -w 20
```

#### 3. 删除密钥
```bash
python ssh-key-distributor.py remove \
  -H 192.168.1.10 \
  -u root \
  --key-id "user@hostname"
```

---

## ✨ 功能特性

### 核心功能
- ✅ **批量分发**: 一键分发到数百台服务器
- ✅ **并发执行**: 多线程并发，提升效率
- ✅ **自动备份**: 分发前自动备份原有 authorized_keys
- ✅ **结果验证**: 可选的分发结果验证
- ✅ **跳板机支持**: 支持通过跳板机连接内网服务器
- ✅ **演习模式**: 安全预览，避免误操作
- ✅ **进度展示**: 实时显示执行进度和结果
- ✅ **智能去重**: 自动检测密钥是否已存在

### 安全特性
- 🔒 分发前自动备份（带时间戳）
- 🔒 自动设置正确的目录和文件权限（700/600）
- 🔒 支持密码和密钥两种认证方式
- 🔒 密钥去重，避免重复添加
- 🔒 详细的错误日志

---

## 📦 安装配置

### 1. 安装Python依赖
```bash
# 方式1：使用pip
pip install paramiko pyyaml colorama --break-system-packages

# 方式2：使用requirements.txt
cat > requirements.txt << EOF
paramiko>=2.11.0
pyyaml>=6.0
colorama>=0.4.6
EOF

pip install -r requirements.txt --break-system-packages
```

### 2. 创建配置文件

#### 方式1：YAML格式（推荐）
```yaml
# hosts.yaml
hosts:
  - host: 192.168.1.10
    username: root
    target_user: deploy
    auth_method: key
    auth_value: /home/user/.ssh/id_rsa
  
  - host: 192.168.1.11
    username: root
    target_user: deploy
    auth_method: password
    auth_value: "password123"
```

#### 方式2：JSON格式
```json
{
  "hosts": [
    {
      "host": "192.168.1.10",
      "username": "root",
      "target_user": "deploy",
      "auth_method": "key",
      "auth_value": "/home/user/.ssh/id_rsa"
    }
  ]
}
```

### 3. 配置文件参数说明

| 参数 | 必填 | 说明 | 示例 |
|------|------|------|------|
| `host` | ✅ | 目标主机IP或域名 | `192.168.1.10` |
| `port` | ❌ | SSH端口（默认22） | `2222` |
| `username` | ❌ | SSH登录用户（默认root） | `admin` |
| `target_user` | ❌ | 要添加密钥的用户（默认同username） | `deploy` |
| `auth_method` | ❌ | 认证方式（默认password） | `key` / `password` |
| `auth_value` | ✅ | 密码或密钥文件路径 | `/path/to/key` |
| `jump_host` | ❌ | 跳板机配置 | 见下文 |
| `verify` | ❌ | 是否验证结果（默认true） | `true` / `false` |

#### 跳板机配置
```yaml
jump_host:
  host: jump.example.com
  port: 22
  username: jumper
  key_file: /home/user/.ssh/jump_key
  # 或使用密码
  # password: "jump_password"
```

---

## 💼 使用场景

### 场景1：新员工入职
```bash
# 1. 生成新员工密钥对
ssh-keygen -t rsa -b 4096 -C "newuser@company.com" -f ~/.ssh/newuser_key

# 2. 批量分发公钥到所有服务器
python ssh-key-distributor.py batch \
  -c production_hosts.yaml \
  -k ~/.ssh/newuser_key.pub

# 3. 通知员工私钥位置
echo "私钥已生成: ~/.ssh/newuser_key"
```

### 场景2：员工离职（批量删除密钥）
```bash
# 方法1：逐台删除
for host in web-{01..10}.example.com; do
  python ssh-key-distributor.py remove \
    -H $host \
    -u root \
    --key-id "olduser@company.com" \
    --auth-method key \
    --auth-value ~/.ssh/admin_key
done

# 方法2：创建删除脚本
cat > remove_user_keys.sh << 'EOF'
#!/bin/bash
HOSTS_FILE="hosts.yaml"
KEY_ID="olduser@company.com"

# 从YAML提取主机列表并删除
yq eval '.hosts[].host' $HOSTS_FILE | while read host; do
  python ssh-key-distributor.py remove \
    -H $host \
    -u root \
    --key-id "$KEY_ID" \
    --auth-method key \
    --auth-value ~/.ssh/admin_key
done
EOF
chmod +x remove_user_keys.sh
./remove_user_keys.sh
```

### 场景3：通过跳板机分发（内网环境）
```bash
# 配置文件方式
cat > internal_hosts.yaml << EOF
hosts:
  - host: 10.0.1.100
    username: root
    target_user: deploy
    auth_method: key
    auth_value: ~/.ssh/id_rsa
    jump_host:
      host: jump.example.com
      username: jumper
      key_file: ~/.ssh/jump_key
EOF

python ssh-key-distributor.py batch \
  -c internal_hosts.yaml \
  -k ~/.ssh/deploy_key.pub

# 命令行方式（单台）
python ssh-key-distributor.py distribute \
  -H 10.0.1.100 \
  -u root \
  -k ~/.ssh/deploy_key.pub \
  --jump-host jump.example.com \
  --jump-user jumper \
  --jump-key ~/.ssh/jump_key
```

### 场景4：不同环境分发不同密钥
```bash
# 开发环境
python ssh-key-distributor.py batch \
  -c hosts_dev.yaml \
  -k ~/.ssh/dev_key.pub

# 测试环境
python ssh-key-distributor.py batch \
  -c hosts_test.yaml \
  -k ~/.ssh/test_key.pub

# 生产环境（更谨慎，先演习）
python ssh-key-distributor.py batch \
  -c hosts_prod.yaml \
  -k ~/.ssh/prod_key.pub \
  --dry-run

# 确认无误后执行
python ssh-key-distributor.py batch \
  -c hosts_prod.yaml \
  -k ~/.ssh/prod_key.pub
```

### 场景5：应急场景（临时密钥）
```bash
# 1. 生成临时密钥（24小时后过期）
ssh-keygen -t rsa -b 2048 -C "emergency_$(date +%Y%m%d)" -f /tmp/emergency_key

# 2. 快速分发
python ssh-key-distributor.py batch \
  -c critical_hosts.yaml \
  -k /tmp/emergency_key.pub \
  -w 50  # 提高并发数

# 3. 24小时后删除
# 设置定时任务或手动删除
```

---

## 🔧 高级用法

### 1. 从Ansible Inventory生成配置

#### 转换脚本
```python
#!/usr/bin/env python3
"""将Ansible inventory转换为密钥分发工具配置"""
import yaml
import json

def ansible_to_config(inventory_file, output_file):
    """
    假设inventory格式:
    [webservers]
    web-01 ansible_host=192.168.1.10 ansible_user=deploy
    web-02 ansible_host=192.168.1.11 ansible_user=deploy
    """
    hosts = []
    
    with open(inventory_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('[') or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            host_info = {'host': None, 'username': 'root'}
            
            for part in parts[1:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    if key == 'ansible_host':
                        host_info['host'] = value
                    elif key == 'ansible_user':
                        host_info['username'] = value
                        host_info['target_user'] = value
            
            if host_info['host']:
                host_info['auth_method'] = 'key'
                host_info['auth_value'] = '~/.ssh/id_rsa'
                hosts.append(host_info)
    
    config = {'hosts': hosts}
    
    with open(output_file, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print(f"转换完成: {len(hosts)} 台主机")
    print(f"配置文件: {output_file}")

if __name__ == '__main__':
    ansible_to_config('inventory', 'hosts.yaml')
```

### 2. 与密码管理工具集成

#### 从HashiCorp Vault获取密码
```python
import hvac
import yaml

def get_vault_password(vault_addr, token, secret_path):
    client = hvac.Client(url=vault_addr, token=token)
    secret = client.secrets.kv.v2.read_secret_version(path=secret_path)
    return secret['data']['data']['password']

# 使用示例
vault_password = get_vault_password(
    'http://vault:8200',
    'your-token',
    'ssh/root-password'
)

# 动态更新配置
with open('hosts.yaml') as f:
    config = yaml.safe_load(f)

for host in config['hosts']:
    if host['auth_method'] == 'password':
        host['auth_value'] = vault_password
```

### 3. 定期轮换密钥

#### 自动轮换脚本
```bash
#!/bin/bash
# rotate_keys.sh - 定期轮换SSH密钥

DATE=$(date +%Y%m%d)
OLD_KEY_ID="deploy@company"  # 旧密钥标识
NEW_KEY="~/.ssh/deploy_key_${DATE}.pub"

# 1. 生成新密钥
ssh-keygen -t rsa -b 4096 -C "deploy@company_${DATE}" -f ~/.ssh/deploy_key_${DATE} -N ""

# 2. 分发新密钥
python ssh-key-distributor.py batch \
  -c hosts.yaml \
  -k $NEW_KEY

# 3. 验证新密钥可用（重要！）
echo "请手动验证新密钥可用后，再删除旧密钥"
echo "测试命令: ssh -i ~/.ssh/deploy_key_${DATE} user@host"
read -p "新密钥测试通过？(yes/no): " confirm

if [ "$confirm" == "yes" ]; then
  # 4. 删除旧密钥
  python remove_old_keys.py --key-id "$OLD_KEY_ID"
  echo "密钥轮换完成"
else
  echo "请先验证新密钥，然后手动删除旧密钥"
fi
```

### 4. 监控和审计

#### 记录分发日志
```python
# 在主脚本中添加日志记录
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(
    filename=f'/var/log/ssh-key-distributor_{datetime.now().strftime("%Y%m%d")}.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 在关键操作处添加日志
logging.info(f"分发密钥到 {host}: {message}")
logging.error(f"分发失败 {host}: {error}")
```

#### 审计报告生成
```bash
#!/bin/bash
# 生成密钥分发审计报告

LOG_FILE="/var/log/ssh-key-distributor_$(date +%Y%m%d).log"

echo "=== SSH密钥分发审计报告 ==="
echo "日期: $(date)"
echo ""

echo "成功分发:"
grep "分发密钥到.*成功" $LOG_FILE | wc -l

echo "失败记录:"
grep "分发失败" $LOG_FILE

echo "涉及主机:"
grep -oP '(?<=分发密钥到 )[^\:]+' $LOG_FILE | sort -u
```

---

## 📚 最佳实践

### 1. 安全建议

#### ✅ 推荐做法
- 使用密钥认证而非密码
- 生产环境密钥单独管理，不与开发环境共用
- 定期轮换密钥（建议每季度）
- 员工离职立即删除其密钥
- 使用跳板机访问生产环境
- 关键操作先用 `--dry-run` 预览

#### ❌ 避免做法
- 不要在配置文件中明文存储密码
- 不要使用过于宽松的权限（777）
- 不要在多个环境共用同一密钥
- 不要跳过备份步骤
- 不要在生产环境直接测试

### 2. 配置管理

#### 目录结构建议
```
ssh-key-management/
├── ssh-key-distributor.py    # 主脚本
├── config/
│   ├── hosts_dev.yaml        # 开发环境
│   ├── hosts_test.yaml       # 测试环境
│   └── hosts_prod.yaml       # 生产环境
├── keys/
│   ├── deploy_key.pub        # 部署密钥
│   ├── admin_key.pub         # 管理密钥
│   └── readonly_key.pub      # 只读密钥
├── scripts/
│   ├── rotate_keys.sh        # 轮换脚本
│   └── audit_report.sh       # 审计脚本
└── logs/
    └── distributor_*.log     # 日志文件
```

#### Git管理
```bash
# .gitignore
*.log
config/*_prod.yaml  # 生产配置不入库
keys/*_rsa          # 私钥不入库
*.bak
```

### 3. 性能优化

#### 合理设置并发数
```bash
# 小规模（<50台）
python ssh-key-distributor.py batch -c hosts.yaml -k key.pub -w 10

# 中等规模（50-200台）
python ssh-key-distributor.py batch -c hosts.yaml -k key.pub -w 30

# 大规模（>200台）
python ssh-key-distributor.py batch -c hosts.yaml -k key.pub -w 50
```

#### 分批执行
```bash
# 将大量主机分批处理
split -l 100 hosts.yaml hosts_batch_

for batch in hosts_batch_*; do
  python ssh-key-distributor.py batch -c $batch -k key.pub
  sleep 10  # 批次间暂停
done
```

### 4. 自动化集成

#### Jenkins集成
```groovy
pipeline {
    agent any
    parameters {
        choice(name: 'ENV', choices: ['dev', 'test', 'prod'], description: '目标环境')
        string(name: 'USER', description: '用户名')
    }
    stages {
        stage('分发密钥') {
            steps {
                script {
                    sh """
                        python ssh-key-distributor.py batch \
                          -c config/hosts_${params.ENV}.yaml \
                          -k keys/${params.USER}_key.pub
                    """
                }
            }
        }
    }
}
```

#### Cron定时任务
```cron
# 每月1号凌晨2点轮换密钥
0 2 1 * * /opt/scripts/rotate_keys.sh >> /var/log/key_rotation.log 2>&1

# 每天生成审计报告
0 1 * * * /opt/scripts/audit_report.sh > /var/log/audit_$(date +\%Y\%m\%d).txt
```

---

## 🔍 故障排查

### 常见问题

#### 1. 连接超时
**错误**: `SSH连接失败: timed out`

**排查**:
```bash
# 检查网络连通性
ping target-host

# 检查SSH端口
telnet target-host 22
nc -zv target-host 22

# 检查防火墙
sudo iptables -L -n | grep 22
```

**解决**: 
- 检查网络/防火墙配置
- 确认SSH服务运行中
- 增加超时时间（修改代码中的timeout参数）

#### 2. 权限被拒绝
**错误**: `Permission denied`

**排查**:
```bash
# 检查用户权限
sudo -u target_user ls -la ~/.ssh/

# 检查sudoers配置
sudo visudo -c
```

**解决**:
- 确保SSH用户有sudo权限
- 或直接以目标用户登录
- 检查 `/etc/sudoers` 配置

#### 3. 密钥已存在但报错
**错误**: `密钥已存在，跳过`（但实际无法使用）

**排查**:
```bash
# 检查authorized_keys内容
cat ~/.ssh/authorized_keys

# 检查权限
ls -la ~/.ssh/
ls -l ~/.ssh/authorized_keys
```

**解决**:
```bash
# 修正权限
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chown user:user ~/.ssh -R
```

#### 4. 跳板机连接失败
**错误**: 通过跳板机连接失败

**排查**:
```bash
# 手动测试跳板机连接
ssh -i jump_key jumper@jump-host

# 测试端口转发
ssh -i jump_key jumper@jump-host -L 2222:target:22
ssh -p 2222 user@localhost
```

**解决**:
- 确认跳板机配置正确
- 检查跳板机是否允许端口转发
- 验证目标主机从跳板机可达

#### 5. 批量操作部分失败
**现象**: 部分主机成功，部分失败

**分析**:
```bash
# 查看详细错误
python ssh-key-distributor.py batch -c hosts.yaml -k key.pub 2>&1 | tee output.log

# 提取失败主机
grep "✗" output.log > failed_hosts.txt
```

**处理**:
```bash
# 只对失败的主机重试
# 1. 从失败列表生成新配置
# 2. 单独处理
```

### 调试技巧

#### 启用详细日志
```python
# 在脚本中添加
import logging
logging.basicConfig(level=logging.DEBUG)
paramiko.util.log_to_file('/tmp/paramiko.log')
```

#### 单台测试
```bash
# 先在单台主机测试
python ssh-key-distributor.py distribute \
  -H test-host \
  -u root \
  -k key.pub \
  --auth-method password

# 成功后再批量执行
```

#### 验证模式
```bash
# 使用演习模式
python ssh-key-distributor.py batch \
  -c hosts.yaml \
  -k key.pub \
  --dry-run

# 逐步验证
# 1. 检查配置文件语法
# 2. 测试单台主机
# 3. 测试小批次（5-10台）
# 4. 全量执行
```

---

## 📞 支持与反馈

### 获取帮助
```bash
# 查看帮助
python ssh-key-distributor.py -h
python ssh-key-distributor.py distribute -h
python ssh-key-distributor.py batch -h
python ssh-key-distributor.py remove -h
```

### 报告问题
提供以下信息有助于快速解决问题：
1. 操作系统和Python版本
2. 完整的错误信息
3. 配置文件（脱敏后）
4. 网络拓扑（是否有跳板机等）

---

**版本**: v1.0  
**更新日期**: 2024-02-12  
**维护团队**: DevOps  
**许可证**: MIT
