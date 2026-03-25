# VPSGuard - Technical Design Document

## 1. Overview

VPSGuard 是一个基于 GeoIP 的 VPS 入站流量防护服务，以 daemon 方式长期运行，通过 nftables 实现按国家的访问控制。

### Core Requirements

1. 通过配置文件，按国家阻止或允许入站新建连接
2. 支持 IP/CIDR 白名单（始终放行）
3. 不影响 VPS 自身发起的出站连接（包括访问被封锁国家的 IP）
4. Daemon 运行，定时更新 GeoIP 数据

---

## 2. Tech Stack

| Component       | Choice                    | Reason                                          |
|----------------|---------------------------|--------------------------------------------------|
| Language        | Go 1.22+                 | 单二进制部署，低内存，原生并发，适合 daemon       |
| Firewall        | nftables (native)        | 独立 table，不干扰现有 iptables-nft / Docker / fail2ban |
| GeoIP Data      | MaxMind GeoLite2 CSV     | 业界标准，准确度高，提供 CIDR→Country 映射       |
| Config Format   | YAML                     | 可读性好，Go 生态成熟                             |
| Service Manager | systemd                  | 标准 Linux daemon 管理                            |
| Logging         | slog (Go stdlib)         | 结构化日志，零外部依赖                            |

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────┐
│                     VPSGuard Daemon                  │
│                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐ │
│  │   Config     │  │   GeoIP     │  │   NFTables   │ │
│  │   Manager    │  │   Engine    │  │   Manager    │ │
│  │             │  │             │  │              │ │
│  │ - YAML 解析  │  │ - CSV 下载   │  │ - 规则生成   │ │
│  │ - 热重载     │  │ - CIDR 提取  │  │ - 原子应用   │ │
│  │ - 校验      │  │ - 定时更新   │  │ - 清理回滚   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘ │
│         │                │                │          │
│         └────────────────┼────────────────┘          │
│                          │                           │
│                   ┌──────┴──────┐                    │
│                   │   Daemon    │                    │
│                   │   Core      │                    │
│                   │             │                    │
│                   │ - 生命周期   │                    │
│                   │ - 信号处理   │                    │
│                   │ - 调度器    │                    │
│                   └─────────────┘                    │
└──────────────────────────────────────────────────────┘
         │                                    │
         ▼                                    ▼
   MaxMind API                          nftables kernel
  (HTTPS download)                    (netfilter subsystem)
```

---

## 4. Project Structure

```
vpsguard/
├── cmd/
│   └── vpsguard/
│       └── main.go              # 入口，CLI 参数解析
├── internal/
│   ├── config/
│   │   ├── config.go            # 配置结构体 & 解析
│   │   └── config_test.go
│   ├── geoip/
│   │   ├── maxmind.go           # MaxMind CSV 下载 & 解压
│   │   ├── parser.go            # CSV 解析，CIDR 按国家提取
│   │   └── parser_test.go
│   ├── firewall/
│   │   ├── nftables.go          # nftables 规则集生成 & 应用
│   │   ├── ruleset.go           # 规则集模板
│   │   └── nftables_test.go
│   ├── daemon/
│   │   ├── daemon.go            # 主循环，调度，信号处理
│   │   └── daemon_test.go
│   └── updater/
│       ├── updater.go           # GeoIP 更新调度逻辑
│       └── updater_test.go
├── configs/
│   └── config.example.yaml      # 示例配置
├── scripts/
│   ├── install.sh               # 安装脚本
│   └── uninstall.sh             # 卸载脚本
├── init/
│   └── vpsguard.service         # systemd unit file
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## 5. Configuration Design

```yaml
# /etc/vpsguard/config.yaml

# 防护模式: "blocklist" 或 "allowlist"
#   blocklist: 封锁列出的国家，其余放行
#   allowlist: 只放行列出的国家，其余封锁
mode: blocklist

# 国家列表 (ISO 3166-1 alpha-2 codes)
countries:
  - CN
  - RU
  - KP
  - IR

# IP/CIDR 白名单 - 无论模式如何，这些地址始终放行
# 支持 IPv4 和 IPv6
whitelist:
  - 1.2.3.4
  - 10.0.0.0/8
  - 192.168.0.0/16
  - 2001:db8::/32

# GeoIP 数据源配置
geoip:
  license_key: "YOUR_MAXMIND_LICENSE_KEY"
  edition: "GeoLite2-Country-CSV"
  # 更新间隔（MaxMind 每周二/五更新，建议 48h~72h）
  update_interval: 48h
  # 本地存储路径
  data_dir: /var/lib/vpsguard/geoip

# nftables 配置
nftables:
  table_name: vpsguard
  # hook priority，-1 表示在默认 input chain 之前执行
  # 确保不和现有 iptables-nft 规则冲突
  priority: -1

# 日志配置
log:
  level: info          # debug | info | warn | error
  file: ""             # 为空则输出到 stdout (由 systemd journal 接管)
  max_size_mb: 100     # 单文件最大大小
  max_backups: 3       # 保留备份数

# Daemon 行为
daemon:
  # 服务停止时是否清除 nftables 规则
  # true:  停止后恢复无防护状态
  # false: 停止后规则保留，直到下次启动时刷新
  cleanup_on_stop: true
  # 启动时是否等待 GeoIP 数据就绪才开始放行流量
  # true:  启动时先加载规则，再接受连接（更安全）
  # false: 先启动，异步加载（更快恢复服务）
  block_until_ready: false
```

---

## 6. nftables Ruleset Design

### 6.1 独立 Table 策略

使用 `table inet vpsguard` 作为完全独立的命名空间，不修改任何现有表（filter、nat、mangle 等），不影响 Docker、fail2ban 或其他 iptables-nft 管理的规则。

### 6.2 Blocklist Mode 规则集

```nft
table inet vpsguard {
    set whitelist_v4 {
        type ipv4_addr
        flags interval
        # auto-merge omitted for kernel compatibility
        elements = { 1.2.3.4, 10.0.0.0/8, 192.168.0.0/16 }
    }

    set whitelist_v6 {
        type ipv6_addr
        flags interval
        # auto-merge omitted for kernel compatibility
    }

    set blocked_v4 {
        type ipv4_addr
        flags interval
        # auto-merge omitted for kernel compatibility
        # 由 daemon 动态填充国家 CIDR
    }

    set blocked_v6 {
        type ipv6_addr
        flags interval
        # auto-merge omitted for kernel compatibility
    }

    chain input {
        type filter hook input priority -1; policy accept;

        # 1. 已建立的连接和相关连接始终放行
        #    这确保 VPS 主动发起的出站连接的回包能正常通过
        ct state established,related accept

        # 2. 本地回环始终放行
        iif lo accept

        # 3. 白名单始终放行（优先级最高）
        ip saddr @whitelist_v4 accept
        ip6 saddr @whitelist_v6 accept

        # 4. 命中国家封锁名单则丢弃
        ip saddr @blocked_v4 drop
        ip6 saddr @blocked_v6 drop

        # 5. 其余流量 policy accept，正常通过
    }
}
```

### 6.3 Allowlist Mode 规则集

```nft
table inet vpsguard {
    # whitelist sets 同上...

    set allowed_v4 {
        type ipv4_addr
        flags interval
        # auto-merge omitted for kernel compatibility
        # 放行国家的 CIDR
    }

    set allowed_v6 {
        type ipv6_addr
        flags interval
        # auto-merge omitted for kernel compatibility
    }

    chain input {
        type filter hook input priority -1; policy accept;

        # 1. 已建立连接放行
        ct state established,related accept

        # 2. 本地回环放行
        iif lo accept

        # 3. 白名单放行
        ip saddr @whitelist_v4 accept
        ip6 saddr @whitelist_v6 accept

        # 4. 新建连接：在允许列表中则放行
        ct state new ip saddr @allowed_v4 accept
        ct state new ip6 saddr @allowed_v6 accept

        # 5. 新建连接：不在列表中则丢弃
        ct state new drop
    }
}
```

### 6.4 为什么 Requirement 3 自动满足

VPS 发起的出站连接（OUTPUT chain）我们完全不 hook，所以 TCP SYN 正常出去。回包匹配 `ct state established,related`，在规则链最顶部直接 accept。即使对端 IP 属于被封锁的国家，也不受影响。

---

## 7. GeoIP Data Pipeline

### 7.1 数据获取

```
MaxMind Download API
  └─ GET https://download.maxmind.com/app/geoip_download
       ?edition_id=GeoLite2-Country-CSV
       &license_key=<KEY>
       &suffix=zip
  └─ Response: GeoLite2-Country-CSV.zip
```

### 7.2 数据解析流程

```
GeoLite2-Country-CSV.zip
  ├── GeoLite2-Country-Blocks-IPv4.csv
  │     network, geoname_id, ...
  │     1.0.0.0/24, 2077456, ...
  │
  ├── GeoLite2-Country-Blocks-IPv6.csv
  │     network, geoname_id, ...
  │
  └── GeoLite2-Country-Locations-en.csv
        geoname_id, ..., country_iso_code, ...
        2077456, ..., AU, ...
```

**解析步骤：**

1. 解析 Locations CSV → 建立 `geoname_id → country_iso_code` 映射表
2. 解析 Blocks-IPv4 CSV → 按 geoname_id 过滤，提取目标国家的所有 IPv4 CIDR
3. 解析 Blocks-IPv6 CSV → 同上，提取 IPv6 CIDR
4. 输出：`map[country_code][]netip.Prefix`

### 7.3 更新策略

- 定时检查（默认 48h），使用 HTTP `If-Modified-Since` 或 ETag 避免重复下载
- 下载失败：指数退避重试（1min → 2min → 4min → ... → 最长 1h），保留旧数据继续运行
- 数据校验：检查 ZIP 完整性 & CSV 记录数量（异常则拒绝更新）
- 原子更新：先写临时文件，解析成功后 rename 替换

---

## 8. nftables Atomic Update

规则更新必须是原子的，避免出现短暂的「无防护」或「全封锁」窗口。

### 更新流程

```
1. 解析新的 GeoIP 数据，在内存中构建完整规则集

2. 将规则集写入临时文件 /tmp/vpsguard-ruleset-XXXXX.nft

3. 执行: nft -f /tmp/vpsguard-ruleset-XXXXX.nft
   - 这会在一个事务中完成：删除旧表 → 创建新表 + sets + rules
   - 如果任何一步失败，整个事务回滚

4. 验证: nft list table inet vpsguard
   - 检查 table 是否存在且规则正确

5. 清理临时文件
```

### 规则文件模板

```nft
# 先删除旧表（如果存在）
delete table inet vpsguard

# 重新创建完整表
table inet vpsguard {
    # ... complete ruleset ...
}
```

`nft -f` 保证这两条语句在同一事务中执行。

---

## 9. Daemon Lifecycle

### 9.1 启动流程

```
main()
  ├── 解析 CLI 参数 (-config, -check, -version, -dry-run)
  ├── 加载 & 校验配置
  ├── 初始化日志
  ├── 检查 nftables 可用性 (nft --version)
  ├── 检查 root 权限
  ├── 加载 GeoIP 数据 (本地缓存或下载)
  ├── 生成 nftables 规则集
  ├── 应用规则
  ├── 启动更新调度器
  └── 进入信号等待循环
```

### 9.2 Signal Handling

| Signal    | Action                              |
|-----------|-------------------------------------|
| SIGHUP    | 重新加载配置文件，重新生成并应用规则 |
| SIGTERM   | 优雅关闭：根据配置决定是否清理规则   |
| SIGINT    | 同 SIGTERM                          |
| SIGUSR1   | 立即触发 GeoIP 数据更新             |

### 9.3 CLI 命令

```bash
vpsguard                          # 前台运行（配合 systemd）
vpsguard -config /path/to/yaml    # 指定配置文件
vpsguard -check                   # 检查配置语法 & nft 可用性
vpsguard -dry-run                 # 生成规则但不应用，输出到 stdout
vpsguard -version                 # 版本信息
vpsguard -status                  # 查看当前运行状态 & 统计
```

---

## 10. systemd Integration

```ini
# /etc/systemd/system/vpsguard.service
[Unit]
Description=VPSGuard - GeoIP-based VPS Protection
Documentation=https://github.com/yourname/vpsguard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vpsguard -config /etc/vpsguard/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=/var/lib/vpsguard /var/log/vpsguard /tmp
ProtectHome=yes

# 需要 CAP_NET_ADMIN 来管理 nftables
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

---

## 11. Go Dependencies

```
go 1.22

require (
    gopkg.in/yaml.v3    # YAML 配置解析
)
```

**核心设计：尽量零外部依赖。**

- CSV 解析：`encoding/csv`（stdlib）
- HTTP 下载：`net/http`（stdlib）
- ZIP 解压：`archive/zip`（stdlib）
- IP/CIDR：`net/netip`（stdlib，Go 1.18+）
- 日志：`log/slog`（stdlib，Go 1.21+）
- 信号处理：`os/signal`（stdlib）
- nftables 交互：通过 `os/exec` 调用 `nft` 命令

唯一的外部依赖是 `gopkg.in/yaml.v3`，用于配置文件解析。

---

## 12. Error Handling & Resilience

| Scenario                       | Behavior                                             |
|-------------------------------|------------------------------------------------------|
| MaxMind 下载失败               | 指数退避重试，保留旧数据继续运行                      |
| GeoIP 数据异常（记录数过少）   | 拒绝更新，报警日志，继续使用旧数据                    |
| nftables 应用失败              | 回滚到上一版规则，记录错误日志                        |
| 配置文件格式错误               | 启动时：报错退出；热重载时：拒绝更新，保留旧配置      |
| 无 root 权限                  | 启动时检查，明确报错                                  |
| nft 命令不存在                 | 启动时检查，提示安装 nftables                         |

---

## 13. Security Considerations

1. **最小权限**: 只需要 `CAP_NET_ADMIN`，不需要完整 root
2. **独立命名空间**: nftables 独立 table，不修改任何现有规则
3. **原子更新**: 规则切换无空窗期
4. **数据校验**: 不信任下载的数据，校验后才应用
5. **License Key 保护**: 配置文件权限设为 600
6. **安全停止**: 可配置停止时是否保留规则

---

## 14. Future Enhancements (v2+)

- **端口级别控制**: 允许对不同端口设置不同的国家策略（如 SSH 严格限制，HTTP 宽松）
- **统计与监控**: 通过 nftables counter 暴露 Prometheus metrics
- **Web Dashboard**: 简单的状态页面（被封锁连接数、国家分布等）
- **ipdeny 备用源**: MaxMind 不可用时自动切换
- **IPv6 优化**: 对 IPv6 做前缀聚合减少规则数量
- **Fail2ban 联动**: 自动将 fail2ban 封禁的 IP 加入黑名单
