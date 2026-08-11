package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	linuxAppDir       = "/opt/active-ip-sniffer"
	linuxConfigDir    = "/etc/active-ip-sniffer"
	linuxConfigPath   = "/etc/active-ip-sniffer/config.json"
	linuxDataDir      = "/var/lib/active-ip-sniffer/results"
	linuxServiceName  = "active-ip-sniffer"
	defaultListenHost = "0.0.0.0"
	defaultListenPort = 8766
)

type cloudflareSettings struct {
	Token   string   `json:"token,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

type persistedConfig struct {
	Host       string             `json:"host"`
	Port       int                `json:"port"`
	DataDir    string             `json:"data_dir"`
	Mode       string             `json:"mode"`
	Firewall   bool               `json:"firewall"`
	Auth       authSettings       `json:"auth,omitempty"`
	Cloudflare cloudflareSettings `json:"cloudflare"`
}

func defaultPersistedConfig() persistedConfig {
	mode := "daemon"
	if runtime.GOOS == "windows" {
		mode = "single"
	}
	return persistedConfig{
		Host:     defaultListenHost,
		Port:     defaultListenPort,
		DataDir:  defaultDataDir(),
		Mode:     mode,
		Firewall: true,
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = os.TempDir()
		}
		return filepath.Join(base, "ActiveIPSniffer", "results")
	}
	return linuxDataDir
}

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = os.TempDir()
		}
		return filepath.Join(base, "ActiveIPSniffer", "config.json")
	}
	return linuxConfigPath
}

func loadPersistedConfig(path string) (persistedConfig, error) {
	cfg := defaultPersistedConfig()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.Host) == "" {
		cfg.Host = defaultListenHost
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		cfg.Port = defaultListenPort
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = defaultDataDir()
	}
	if cfg.Mode != "daemon" && cfg.Mode != "single" {
		if runtime.GOOS == "windows" {
			cfg.Mode = "single"
		} else {
			cfg.Mode = "daemon"
		}
	}
	if runtime.GOOS == "windows" {
		cfg.Mode = "single"
	}
	cfg.Cloudflare.Domains = normalizeDomainList(cfg.Cloudflare.Domains)
	return cfg, nil
}

func savePersistedConfig(path string, cfg persistedConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil && runtime.GOOS != "windows" {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

type settingsStore struct {
	path string
	mu   sync.RWMutex
	cfg  persistedConfig
}

func newSettingsStore(path string) (*settingsStore, error) {
	cfg, err := loadPersistedConfig(path)
	if err != nil {
		return nil, err
	}
	return &settingsStore{path: path, cfg: cfg}, nil
}

func (s *settingsStore) snapshot() persistedConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.cfg
	cfg.Cloudflare.Domains = append([]string(nil), cfg.Cloudflare.Domains...)
	return cfg
}

func (s *settingsStore) updateCloudflare(value cloudflareSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.Cloudflare = value
	if err := savePersistedConfig(s.path, next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func normalizeDomainList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if value == "" || strings.ContainsAny(value, " /:@") {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func isSetupInvocation(args []string) bool {
	if len(args) > 1 && (args[1] == "setup" || args[1] == "wizard") {
		return true
	}
	base := strings.ToLower(filepath.Base(args[0]))
	return base == "v" || base == "v.exe"
}

func promptLine(reader *bufio.Reader, label, fallback string) (string, error) {
	if fallback != "" {
		fmt.Printf("%s [%s]: ", label, fallback)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return fallback, nil
	}
	return line, nil
}

func promptYesNo(reader *bufio.Reader, label string, fallback bool) (bool, error) {
	hint := "y/N"
	if fallback {
		hint = "Y/n"
	}
	value, err := promptLine(reader, label+" ("+hint+")", "")
	if err != nil {
		return fallback, err
	}
	if value == "" {
		return fallback, nil
	}
	switch strings.ToLower(value) {
	case "y", "yes", "1", "是":
		return true, nil
	case "n", "no", "0", "否":
		return false, nil
	default:
		return fallback, fmt.Errorf("无法识别的选择: %s", value)
	}
}

func runSetupWizard() error {
	reader := bufio.NewReader(os.Stdin)
	configPath := defaultConfigPath()
	cfg, err := loadPersistedConfig(configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Printf(" Active IP Sniffer %s · Go 轻量配置界面\n", appVersion)
	fmt.Println("============================================================")
	fmt.Printf("配置文件: %s\n", configPath)
	fmt.Println("直接按 Enter 保留当前值。")
	fmt.Println()

	host, err := promptLine(reader, "WebUI 监听地址", cfg.Host)
	if err != nil {
		return err
	}
	if net.ParseIP(host) == nil && host != "localhost" {
		return fmt.Errorf("无效监听地址: %s", host)
	}
	cfg.Host = host

	portText, err := promptLine(reader, "WebUI 启动端口", strconv.Itoa(cfg.Port))
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("无效端口: %s", portText)
	}
	cfg.Port = port

	if cfg.Auth.configured() {
		changePassword, err := promptYesNo(reader, "是否修改已经配置的 WebUI 管理密码", false)
		if err != nil {
			return err
		}
		if changePassword {
			password, err := promptLine(reader, "新的 WebUI 管理密码（至少 8 位）", "")
			if err != nil {
				return err
			}
			cfg.Auth, err = makeAuthSettings(password)
			if err != nil {
				return err
			}
		}
	} else {
		password, err := promptLine(reader, "WebUI 管理密码（至少 8 位；留空=暂不启用）", "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(password) != "" {
			cfg.Auth, err = makeAuthSettings(password)
			if err != nil {
				return err
			}
		}
	}

	configureCF, err := promptYesNo(reader, "是否现在配置 Cloudflare Token 与优选域名", cfg.Cloudflare.Token != "" || len(cfg.Cloudflare.Domains) > 0)
	if err != nil {
		return err
	}
	if configureCF {
		tokenLabel := "Cloudflare API Token"
		if cfg.Cloudflare.Token != "" {
			tokenLabel += "（已保存，Enter 保留）"
		}
		token, err := promptLine(reader, tokenLabel, "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(token) == "" {
			token = cfg.Cloudflare.Token
		}
		if strings.TrimSpace(token) == "" {
			return errors.New("Cloudflare Token 不能为空")
		}
		domainDefault := strings.Join(cfg.Cloudflare.Domains, ",")
		domainsText, err := promptLine(reader, "优选域名（多个用逗号分隔）", domainDefault)
		if err != nil {
			return err
		}
		domains := normalizeDomainList(strings.FieldsFunc(domainsText, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}))
		if len(domains) == 0 {
			return errors.New("至少需要一个优选域名")
		}
		fmt.Println("正在验证 Token、Zone 与 DNS 记录...")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		statuses, verifyErr := resolveCloudflareDomains(ctx, token, domains)
		cancel()
		if verifyErr != nil {
			return fmt.Errorf("Cloudflare 验证失败: %w", verifyErr)
		}
		for _, status := range statuses {
			fmt.Printf("  ✓ %s (%s)\n", status.Domain, summarizeDNSRecords(status.Records))
		}
		cfg.Cloudflare = cloudflareSettings{Token: token, Domains: domains}
	} else if cfg.Cloudflare.Token != "" || len(cfg.Cloudflare.Domains) > 0 {
		clearCF, err := promptYesNo(reader, "是否清除已经保存的 Cloudflare 配置", false)
		if err != nil {
			return err
		}
		if clearCF {
			cfg.Cloudflare = cloudflareSettings{}
		}
	}
	if cfg.Cloudflare.Token != "" && !cfg.Auth.configured() {
		return errors.New("配置 Cloudflare DNS 写入能力时必须先设置 WebUI 管理密码")
	}

	if runtime.GOOS == "windows" {
		cfg.Mode = "single"
		cfg.Firewall = false
		fmt.Println("Windows 模式固定为单次前台运行；关闭窗口即停止服务。")
	} else {
		modeDefault := "1"
		if cfg.Mode == "single" {
			modeDefault = "2"
		}
		mode, err := promptLine(reader, "运行模式：1=常驻守护进程  2=单次前台运行", modeDefault)
		if err != nil {
			return err
		}
		switch mode {
		case "1", "daemon", "常驻":
			cfg.Mode = "daemon"
		case "2", "single", "单次":
			cfg.Mode = "single"
		default:
			return fmt.Errorf("无效运行模式: %s", mode)
		}
		if cfg.Mode == "daemon" {
			cfg.Firewall, err = promptYesNo(reader, "是否自动放行 WebUI TCP 端口", cfg.Firewall)
			if err != nil {
				return err
			}
		}
	}

	fmt.Println()
	fmt.Println("---------------------- 配置摘要 ---------------------------")
	fmt.Printf("监听:       %s:%d\n", cfg.Host, cfg.Port)
	fmt.Printf("运行模式:   %s\n", cfg.Mode)
	fmt.Printf("数据目录:   %s\n", cfg.DataDir)
	fmt.Printf("WebUI认证:  %s（用户名 admin）\n", map[bool]string{true: "已配置", false: "未配置"}[cfg.Auth.configured()])
	fmt.Printf("CF Token:   %s\n", map[bool]string{true: "已配置", false: "未配置"}[cfg.Cloudflare.Token != ""])
	fmt.Printf("优选域名:   %s\n", strings.Join(cfg.Cloudflare.Domains, ", "))
	fmt.Println("-----------------------------------------------------------")
	confirm, err := promptYesNo(reader, "保存并应用以上配置", true)
	if err != nil {
		return err
	}
	if !confirm {
		fmt.Println("已取消，未修改配置。")
		return nil
	}
	if err := savePersistedConfig(configPath, cfg); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}

	if runtime.GOOS == "windows" {
		fmt.Printf("启动一次性 WebUI: http://127.0.0.1:%d\n", cfg.Port)
		return runServer(cfg.Host, cfg.Port, cfg.DataDir, configPath)
	}
	if !isPrivileged() {
		return errors.New("Linux 配置应用需要 root；请使用 sudo v")
	}
	if cfg.Mode == "daemon" {
		if err := installSystemdService(cfg, configPath); err != nil {
			return err
		}
		if cfg.Firewall {
			_ = openFirewallPort(cfg.Port)
		}
		fmt.Printf("常驻服务已启动: http://%s:%d\n", displayHost(cfg.Host), cfg.Port)
		fmt.Printf("状态命令: systemctl status %s\n", linuxServiceName)
		return nil
	}
	_ = exec.Command("systemctl", "disable", "--now", linuxServiceName).Run()
	fmt.Printf("单次模式启动: http://%s:%d\n", displayHost(cfg.Host), cfg.Port)
	fmt.Println("按 Ctrl+C 停止。")
	return runServer(cfg.Host, cfg.Port, cfg.DataDir, configPath)
}

func displayHost(host string) string {
	if host == "0.0.0.0" || host == "::" {
		return "<服务器IP>"
	}
	return host
}

func installSystemdService(cfg persistedConfig, configPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	unit := fmt.Sprintf(`[Unit]
Description=Active IP Sniffer Go WebUI（CF 优选 / VLESS / DNS 管理）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s serve -host %s -port %d -data-dir %s -config %s
Restart=on-failure
RestartSec=2
User=root
WorkingDirectory=%s
Environment=GOMEMLIMIT=80MiB
Environment=GOGC=50
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s %s

[Install]
WantedBy=multi-user.target
`, serviceArg(exe), serviceArg(cfg.Host), cfg.Port, serviceArg(cfg.DataDir), serviceArg(configPath), serviceArg(filepath.Dir(exe)), serviceArg(cfg.DataDir), serviceArg(filepath.Dir(configPath)))
	servicePath := filepath.Join("/etc/systemd/system", linuxServiceName+".service")
	if err := os.WriteFile(servicePath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("写入 systemd 服务失败: %w", err)
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", linuxServiceName}, {"restart", linuxServiceName}} {
		cmd := exec.Command("systemctl", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s 失败: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func systemdQuote(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func serviceArg(value string) string {
	return strconv.Quote(value)
}

func openFirewallPort(port int) error {
	portText := strconv.Itoa(port) + "/tcp"
	if _, err := exec.LookPath("ufw"); err == nil {
		status, statusErr := exec.Command("ufw", "status").CombinedOutput()
		if statusErr == nil && strings.Contains(strings.ToLower(string(status)), "status: active") {
			return exec.Command("ufw", "allow", portText, "comment", "Active IP Sniffer WebUI 管理端口").Run()
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if exec.Command("firewall-cmd", "--state").Run() == nil {
			if err := exec.Command("firewall-cmd", "--permanent", "--add-port="+portText).Run(); err != nil {
				return err
			}
			return exec.Command("firewall-cmd", "--reload").Run()
		}
	}
	return nil
}
