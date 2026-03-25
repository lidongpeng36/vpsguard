# VPSGuard

GeoIP-based inbound traffic protection for Linux VPS. Blocks or allows SSH/TCP connections by country using nftables, without affecting your own outbound connections.

## Features

- **Country-level filtering** — block or allow inbound connections by country (ISO 3166-1 alpha-2)
- **Two modes** — `blocklist` (block listed countries) or `allowlist` (allow only listed countries)
- **IP/CIDR whitelist** — always-allow list that overrides country rules
- **Outbound safe** — VPS-initiated connections work normally, even to blocked countries
- **Daemon mode** — runs as a systemd service with automatic GeoIP data updates
- **Non-invasive** — uses an isolated nftables table; does not touch existing iptables/Docker/fail2ban rules
- **Hot reload** — `SIGHUP` reloads config, `SIGUSR1` forces GeoIP update

## How It Works

VPSGuard creates an independent `table inet vpsguard` in nftables with a single `input` chain:

1. `ct state established,related accept` — return traffic for outbound connections always passes
2. `iif lo accept` — loopback always passes
3. Whitelist IPs — always accepted
4. Country CIDRs — dropped (blocklist mode) or accepted (allowlist mode)
5. Default policy — accept (blocklist) or drop new connections (allowlist)

GeoIP data comes from [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free, requires registration).

## Quick Start

```bash
# Build
make build

# Install (as root)
sudo ./scripts/install.sh

# Edit config — set your MaxMind license key
sudo nano /etc/vpsguard/config.yaml

# Validate
sudo vpsguard -check

# Start
sudo systemctl enable --now vpsguard
```

## Configuration

```yaml
mode: blocklist
countries:
  - CN
  - RU
  - KP
whitelist:
  - 1.2.3.4          # your management IP
  - 10.0.0.0/8
geoip:
  license_key: "YOUR_KEY"
  update_interval: 48h
  data_dir: /var/lib/vpsguard/geoip
nftables:
  table_name: vpsguard
  priority: -1
```

See [`configs/config.example.yaml`](configs/config.example.yaml) for the full reference.

## CLI

```bash
vpsguard                    # run as daemon (foreground, for systemd)
vpsguard -config PATH       # custom config path
vpsguard -check             # validate config and exit
vpsguard -dry-run           # print nftables ruleset without applying
vpsguard -status            # show current table status
vpsguard -version           # print version
```

## Management

```bash
systemctl status vpsguard       # service status
systemctl reload vpsguard       # reload config (SIGHUP)
kill -USR1 $(pidof vpsguard)    # force GeoIP update
journalctl -u vpsguard -f       # follow logs
```

## Building

Requires Go 1.22+.

```bash
make              # fmt + vet + test + build
make test         # run all tests
make test-cover   # tests with coverage report
make build        # compile binary to bin/vpsguard
```

## Project Structure

```
cmd/vpsguard/          CLI entry point
internal/
  config/              YAML config parsing & validation
  geoip/               MaxMind CSV download & CIDR extraction
  firewall/            nftables ruleset generation & application
  updater/             GeoIP update orchestration
  daemon/              Lifecycle, signals, hot-reload
configs/               Example configuration
init/                  systemd unit file
scripts/               Install/uninstall scripts
```

## Requirements

- Linux with nftables (`apt install nftables`)
- Go 1.22+ (build only)
- Free [MaxMind GeoLite2 license key](https://www.maxmind.com/en/geolite2/signup)

## License

MIT
