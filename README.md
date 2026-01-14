# CIS Oracle Enterprise Linux 9 Hardening (Python)

A comprehensive Python-based CIS hardening framework for Oracle Enterprise Linux 9, implementing CIS Benchmark v2.0.0 Level 2 Server controls.

## Features

- **127+ CIS Controls** across 14 hardening modules
- **Modular Architecture** - Easy to customize and extend
- **Dry-Run Mode** - Test changes before applying
- **JSON/HTML Reporting** - Detailed compliance reports
- **YAML Configuration** - Centralized, easy-to-edit settings

## Modules

| Module | Description | Key Controls |
|--------|-------------|--------------|
| `aide.py` | File integrity monitoring | AIDE initialization, systemd timer, audit tool monitoring |
| `audit.py` | Audit system configuration | Comprehensive audit rules, auditd.conf, privileged commands |
| `auth.py` | Authentication hardening | Password aging, inactive days, pwquality |
| `banners.py` | Login banners | /etc/issue, /etc/issue.net, /etc/motd |
| `boot.py` | Boot security | GRUB password, boot file permissions, kernel params |
| `coredumps.py` | Core dump restrictions | limits.conf, systemd-coredump |
| `cron.py` | Cron/at hardening | File permissions, cronie/at packages |
| `firewalld.py` | Firewall configuration | Service allowlist, loopback rules, nftables masking |
| `kernel.py` | Kernel hardening | Module blacklisting |
| `logging.py` | Logging configuration | rsyslog, journal-upload, log permissions |
| `mounts.py` | Mount options | noexec, nodev, nosuid for partitions |
| `packages.py` | Package management | Bluetooth removal, service disabling |
| `pam.py` | PAM configuration | pwhistory, session timeout, use_authtok |
| `selinux.py` | SELinux enforcement | Enforcing mode |
| `ssh.py` | SSH hardening | Full CIS SSH configuration (20+ settings) |
| `sudo.py` | Sudo hardening | Logging, pty, su restriction |
| `sysctl.py` | Kernel parameters | Network, IPv6, ptrace_scope settings |

## Usage

```bash
# Dry-run (show what would change)
sudo python3 cis_apply.py --profile l2-server --dry-run --report /root/cis-l2.json

# Apply hardening
sudo python3 cis_apply.py --profile l2-server --apply --report /root/cis-l2.json

# Using enhanced script with verification
sudo python3 cis_apply_enhanced.py --profile l2-server --verify --report /root/verify.json
```

## Configuration

Edit `cis_config.yaml` to customize settings. Key sections:

```yaml
# Firewall - allowlist services
firewalld:
  allow_services: ["ssh", "https"]
  configure_loopback: true
  mask_nftables: true

# SSH hardening
ssh:
  permit_root_login: "no"
  max_auth_tries: 4
  banner: "/etc/issue.net"

# Authentication
auth:
  pass_max_days: 365
  pass_inactive: 30
  apply_to_existing_users: true

# GRUB password (generate with: grub2-mkpasswd-pbkdf2)
boot:
  grub_password: true
  grub_password_hash: "grub.pbkdf2.sha512.10000.HASH..."

# Packages/services
packages:
  remove_bluetooth: true
```

## Prerequisites

- Oracle Enterprise Linux 9.x
- Python 3.9+
- Root/sudo access
- PyYAML (`pip install pyyaml`)

## Files

| File | Description |
|------|-------------|
| `cis_apply.py` | Main hardening script |
| `cis_apply_enhanced.py` | Enhanced version with logging/reporting |
| `cis_config.yaml` | Configuration file |
| `modules/` | Hardening modules |
| `CONTROL.csv` | CIS benchmark scan results |
| `QUICK_START.md` | Quick start guide |
| `IMPLEMENTATION_GUIDE.md` | Detailed implementation guide |

## Firewalld

This bundle is pre-configured to allowlist **ssh** and **https** in `cis_config.yaml`. Loopback traffic rules and nftables masking are also configured for CIS compliance.
