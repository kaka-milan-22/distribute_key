// SSH Key Distributor - Go版本（简化实现）
// 适合需要单文件部署的场景

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type HostConfig struct {
	Host       string
	Port       int
	Username   string
	TargetUser string
	Password   string
	KeyFile    string
}

type Result struct {
	Host    string
	Success bool
	Message string
}

func main() {
	// 命令行参数
	hostList := flag.String("hosts", "", "主机列表，逗号分隔")
	port := flag.Int("port", 22, "SSH端口")
	username := flag.String("user", "root", "SSH用户")
	targetUser := flag.String("target", "", "目标用户（默认同SSH用户）")
	password := flag.String("pass", "", "SSH密码")
	keyFile := flag.String("key", "", "私钥文件")
	pubKeyFile := flag.String("pubkey", "", "要分发的公钥文件")
	workers := flag.Int("workers", 10, "并发数")
	
	flag.Parse()

	if *hostList == "" || *pubKeyFile == "" {
		fmt.Println("用法: ssh-key-dist -hosts='host1,host2' -pubkey=key.pub")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 读取公钥
	pubKey, err := ioutil.ReadFile(*pubKeyFile)
	if err != nil {
		log.Fatalf("读取公钥失败: %v", err)
	}

	// 解析主机列表
	hosts := strings.Split(*hostList, ",")
	
	if *targetUser == "" {
		*targetUser = *username
	}

	// 并发分发
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *workers)
	results := make(chan Result, len(hosts))

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			config := HostConfig{
				Host:       strings.TrimSpace(h),
				Port:       *port,
				Username:   *username,
				TargetUser: *targetUser,
				Password:   *password,
				KeyFile:    *keyFile,
			}

			success, msg := distributeKey(config, string(pubKey))
			results <- Result{Host: h, Success: success, Message: msg}
		}(host)
	}

	// 等待所有任务完成
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集结果
	successCount := 0
	failCount := 0
	for result := range results {
		if result.Success {
			fmt.Printf("✓ %s: %s\n", result.Host, result.Message)
			successCount++
		} else {
			fmt.Printf("✗ %s: %s\n", result.Host, result.Message)
			failCount++
		}
	}

	// 打印汇总
	fmt.Printf("\n=== 执行结果 ===\n")
	fmt.Printf("成功: %d\n", successCount)
	fmt.Printf("失败: %d\n", failCount)
}

func distributeKey(config HostConfig, pubKey string) (bool, string) {
	// 创建SSH配置
	sshConfig := &ssh.ClientConfig{
		User:            config.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 认证方式
	if config.KeyFile != "" {
		key, err := ioutil.ReadFile(config.KeyFile)
		if err != nil {
			return false, fmt.Sprintf("读取私钥失败: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return false, fmt.Sprintf("解析私钥失败: %v", err)
		}
		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		sshConfig.Auth = []ssh.AuthMethod{ssh.Password(config.Password)}
	}

	// 连接SSH
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return false, fmt.Sprintf("连接失败: %v", err)
	}
	defer client.Close()

	// 执行命令
	session, err := client.NewSession()
	if err != nil {
		return false, fmt.Sprintf("创建会话失败: %v", err)
	}
	defer session.Close()

	// 准备命令
	commands := fmt.Sprintf(`
		sudo mkdir -p ~%s/.ssh
		sudo chmod 700 ~%s/.ssh
		sudo touch ~%s/.ssh/authorized_keys
		sudo chmod 600 ~%s/.ssh/authorized_keys
		
		# 检查密钥是否已存在
		if ! sudo grep -qF '%s' ~%s/.ssh/authorized_keys; then
			echo '%s' | sudo tee -a ~%s/.ssh/authorized_keys > /dev/null
			sudo chown -R %s:%s ~%s/.ssh
			echo "added"
		else
			echo "exists"
		fi
	`,
		config.TargetUser, config.TargetUser,
		config.TargetUser, config.TargetUser,
		strings.TrimSpace(pubKey), config.TargetUser,
		strings.TrimSpace(pubKey), config.TargetUser,
		config.TargetUser, config.TargetUser, config.TargetUser,
	)

	output, err := session.CombinedOutput(commands)
	if err != nil {
		return false, fmt.Sprintf("执行失败: %v, 输出: %s", err, output)
	}

	result := strings.TrimSpace(string(output))
	if result == "exists" {
		return true, "密钥已存在"
	} else if result == "added" {
		return true, "分发成功"
	}

	return true, "完成"
}

/*
编译:
  go mod init ssh-key-dist
  go get golang.org/x/crypto/ssh
  go build -o ssh-key-dist

使用示例:
  # 使用密码认证
  ./ssh-key-dist \
    -hosts="192.168.1.10,192.168.1.11" \
    -user=root \
    -pass="password" \
    -pubkey=~/.ssh/id_rsa.pub

  # 使用密钥认证
  ./ssh-key-dist \
    -hosts="web-01,web-02,web-03" \
    -user=deploy \
    -key=~/.ssh/id_rsa \
    -pubkey=~/.ssh/deploy_key.pub \
    -workers=20

优势:
  - 单文件部署，无依赖
  - 性能好，并发高效
  - 跨平台编译

go.mod 内容:
module ssh-key-dist

go 1.21

require golang.org/x/crypto v0.17.0

require golang.org/x/sys v0.15.0 // indirect
*/
