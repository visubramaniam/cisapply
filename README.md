# CIS Oracle Enterprise Linux 9 Hardening (Python)

A comprehensive Python-based CIS hardening framework for Oracle Enterprise Linux 9, implementing CIS Benchmark v2.0.0 Level 2 Server controls.

## Features

- **110+ CIS Controls** across 24 hardening modules
- **Modular Architecture** - Easy to customize and extend
- **Multiple Profiles** - l1-server, l2-server, l2-workstation
- **Dry-Run Mode** - Test changes before applying
- **JSON/HTML/Markdown Reporting** - Detailed compliance reports with CIS section numbers
- **YAML Configuration** - Centralized, easy-to-edit settings
- **Drift Detection** - Compare current state against baseline
- **Qualys-Compatible** - Tested against Qualys CIS scans

## Modules

| Module | Description | CIS Sections |
|--------|-------------|--------------|
| `aide.py` | File integrity monitoring | 6.1.1-6.1.7 |
| `audit.py` | Audit system configuration | 4.1.1-4.1.3 |
| `auth.py` | Authentication hardening | 5.5.1-5.5.9 |
| `banners.py` | Login banners | 5.6.1-5.6.2 |
| `boot.py` | Boot security | 1.3.1-1.4.4 |
| `coredumps.py` | Core dump restrictions | 1.5.3-1.5.4 |
| `cron.py` | Cron/at hardening | 5.1.1-5.1.9 |
| `crypto.py` | System crypto policy | 1.5.2 |
| `dnf.py` | DNF/package manager security | 1.2.1-1.2.3 |
| `fileperms.py` | System file permissions | 5.6.1.1-5.6.1.10 |
| `firewalld.py` | Firewall configuration | 3.4.1.1-3.4.1.6 |
| `ipv6.py` | IPv6 configuration | 3.3.1-3.3.3 |
| `kernel.py` | Kernel module blacklisting | 1.1.1.1-1.1.1.8 |
| `logging.py` | Logging configuration | 4.2.1-4.2.4 |
| `mounts.py` | Mount options hardening | 1.1.2-1.1.6 |
| `packages.py` | Package management | 2.4.1-2.4.3 |
| `pam.py` | PAM configuration | 5.4.1-5.4.4 |
| `postfix.py` | Mail server hardening | 2.2.14-2.2.15 |
| `selinux.py` | SELinux enforcement | 1.5.1 |
| `services.py` | Service management | 2.1.1-2.3.3 |
| `ssh.py` | SSH hardening | 5.2.1-5.2.22 |
| `sudo.py` | Sudo hardening | 5.3.1-5.3.7 |
| `sysctl.py` | Kernel parameters | 3.1.1-3.1.3 |
| `tcpwrappers.py` | TCP Wrappers | 3.4.2.1-3.4.2.3 |

## Quick Start

```bash
# 1. Clone/copy to target system
cd /opt
git clone <repo-url> cis_oel9_l2_server_firewalld
cd cis_oel9_l2_server_firewalld

# 2. Install dependencies
pip3 install pyyaml

# 3. Edit configuration (IMPORTANT - especially ssh.allow_users!)
vi cis_config.yaml

# 4. Dry-run first (always!)
sudo python3 cis_apply_enhanced.py --profile l2-server --dry-run

# 5. Apply hardening
sudo python3 cis_apply_enhanced.py --profile l2-server --apply
```

## Usage

```bash
# Dry-run (show what would change)
sudo python3 cis_apply_enhanced.py --profile l2-server --dry-run

# Apply hardening (generates reports automatically)
sudo python3 cis_apply_enhanced.py --profile l2-server --apply

# Verify compliance without changes
sudo python3 cis_apply_enhanced.py --profile l2-server --verify

# Detect drift from baseline
sudo python3 cis_apply_enhanced.py --profile l2-server --detect-drift --baseline /root/baseline.json

# Custom report paths
sudo python3 cis_apply_enhanced.py --profile l2-server --apply \
  --report /root/cis-report.json \
  --html-report /root/cis-report.html
```

### Output Reports

When running with `--apply`, three reports are automatically generated:
- `hardening.json` - JSON report with full details
- `hardening_report.html` - HTML report for web viewing
- `hardening_report.md` - Markdown report

The console output includes CIS section numbers for each control:

```
Control Results:
       Control ID               CIS Section        Description
  --- - ------------------------ ------------------ ----------------------------------------
  ✅ * KERN-1                   1.1.1.1-1.1.1.8    Disable uncommon filesystem/network kernel modules
  ✅ * SYSCTL-1                 3.1.1-3.1.3        Apply CIS sysctl hardening
  ✅   SSH-1                    5.2.1-5.2.22       Harden SSH daemon configuration
  ...
```

## Configuration

Edit `cis_config.yaml` to customize settings before applying.

### ⚠️ CRITICAL: SSH Allow Users

**Before running**, configure `ssh.allow_users` with your login username(s):

```yaml
ssh:
  # IMPORTANT: Add your username here or you will be locked out!
  allow_users: "root oelcisscan admin"
  # Or use groups:
  # allow_groups: "wheel sshusers"
```

### Key Configuration Sections

```yaml
# Firewall - allowlist services
firewalld:
  allow_services: ["ssh", "https"]
  configure_loopback: true
  mask_nftables: true

# SSH hardening
ssh:
  permit_root_login: "no"
  password_authentication: "no"
  max_auth_tries: 4
  log_level: "VERBOSE"
  ciphers: "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
  allow_users: "root oelcisscan"  # <-- IMPORTANT!

# Authentication
auth:
  pass_max_days: 365
  pass_min_days: 7
  pass_inactive: 30
  apply_to_existing_users: true
  tmout: 900  # Session timeout in seconds

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
- PyYAML (`pip3 install pyyaml`)

## Files

| File | Description |
|------|-------------|
| `cis_apply_enhanced.py` | Main hardening script with full reporting |
| `cis_apply.py` | Simplified hardening script |
| `cis_config.yaml` | Configuration file |
| `modules/` | Hardening modules (24 modules) |
| `modules/utils.py` | Shared utility functions |
| `hardening.json` | Generated JSON report |
| `hardening_report.html` | Generated HTML report |
| `hardening_report.md` | Generated Markdown report |

## Profiles

| Profile | Description | Modules |
|---------|-------------|---------|
| `l1-server` | Level 1 Server | 19 modules (basic hardening) |
| `l2-server` | Level 2 Server | 24 modules (full hardening) |
| `l2-workstation` | Level 2 Workstation | 24 modules (workstation variant) |

## Known Issues & Workarounds

### 1. EPEL Repository GPG Errors

After hardening, you may see GPG errors when using dnf with EPEL repos:
```
Error: Failed to download metadata for repo 'ol9_developer_EPEL': GPG verification is enabled...
```

**Fix:** Disable repo_gpgcheck for that specific repo:
```bash
sudo dnf config-manager --save --setopt=ol9_developer_EPEL.repo_gpgcheck=0
```

### 2. SSH Access After Hardening

If you get locked out after hardening, access via console and:
```bash
sudo vi /etc/ssh/sshd_config.d/99-cis-hardening.conf
# Change: AllowUsers root
# To: AllowUsers root yourusername
sudo systemctl restart sshd
```

### 3. Static Services

Some services like `aidecheck.service` are "static" oneshot services triggered by timers. They cannot be enabled directly - only their timers need to be enabled.

## CIS Control Mapping

The script maps internal control IDs to CIS Benchmark v2.0.0 section numbers. Key mappings:

| Section | Controls | Description |
|---------|----------|-------------|
| 1.x | KERN, BOOT, CORE, CRYPTO, SEL | Initial Setup |
| 2.x | SVC, PKG, MAIL | Services |
| 3.x | SYSCTL, FW, TCP, IPV6 | Network Configuration |
| 4.x | AUD, LOG | Logging and Auditing |
| 5.x | CRON, SSH, SUDO, PAM, AUTH, BANNER, PERM | Access Control |
| 6.x | AIDE | System Maintenance |

## Compliance Testing

Tested with:
- Qualys CIS Oracle Linux 9 v2.0.0 scan
- Manual CIS benchmark verification

Typical compliance after running: **99%+** (some controls require manual intervention like separate partitions)

## Troubleshooting

### View Applied SSH Configuration
```bash
cat /etc/ssh/sshd_config.d/99-cis-hardening.conf
```

### Check AIDE Timer Status
```bash
systemctl status aidecheck.timer
systemctl list-timers | grep aide
```

### View Audit Rules
```bash
auditctl -l
```

### Check SELinux Status
```bash
getenforce
sestatus
```

### Session Timeout (TMOUT)
Session timeout is configured via `/etc/profile.d/cis-tmout.sh` to avoid readonly variable conflicts.

## License

MIT License

## References

- [CIS Oracle Linux 9 Benchmark v2.0.0](https://www.cisecurity.org/benchmark/oracle_linux)
- [Oracle Linux Security Guide](https://docs.oracle.com/en/operating-systems/oracle-linux/9/security/)

