# Quick Start Guide - CIS Apply Script

## Overview

This toolkit provides comprehensive CIS Level 2 hardening for Oracle Enterprise Linux 9, addressing **127+ CIS controls** across **14 modules**.

## What's Included

### Core Scripts
- **cis_apply.py** - Main hardening script
- **cis_apply_enhanced.py** - Enhanced version with logging, reporting, and verification

### 14 Hardening Modules

| Module | Controls | Description |
|--------|----------|-------------|
| `aide.py` | 5 | File integrity monitoring, systemd timer, audit tool monitoring |
| `audit.py` | 15+ | Comprehensive audit rules, auditd.conf, privileged commands |
| `auth.py` | 8 | Password aging, inactive days, pwquality settings |
| `boot.py` | 4 | GRUB password, boot file permissions, kernel params |
| `coredumps.py` | 2 | limits.conf, systemd-coredump restrictions |
| `cron.py` | 6 | File permissions, cronie/at packages, deny files |
| `firewalld.py` | 5 | Service allowlist, loopback rules, nftables masking |
| `logging.py` | 8 | rsyslog, journal-upload, log file permissions |
| `mounts.py` | 6 | Mount options (noexec, nodev, nosuid) |
| `packages.py` | 4 | Bluetooth removal, service disabling |
| `pam.py` | 4 | pwhistory with use_authtok, session timeout |
| `ssh.py` | 20+ | Full CIS SSH configuration |
| `sudo.py` | 8 | Logging, pty, su restriction via pam_wheel |
| `sysctl.py` | 15+ | Network, IPv6, ptrace_scope settings |

## Quick Start

### Step 1: Review Configuration

Edit `cis_config.yaml` to customize settings for your environment:

```yaml
# Key settings to review:
ssh:
  permit_root_login: "no"
  allow_users: ["admin"]  # Customize SSH access

auth:
  pass_max_days: 365
  pass_inactive: 30

firewalld:
  allow_services: ["ssh", "https"]

boot:
  grub_password: true
  grub_password_hash: "grub.pbkdf2.sha512.10000.YOUR_HASH..."
```

### Step 2: Generate GRUB Password Hash (if needed)

```bash
grub2-mkpasswd-pbkdf2
# Enter password when prompted
# Copy the hash to cis_config.yaml under boot.grub_password_hash
```

### Step 3: Dry-Run Test

```bash
sudo python3 cis_apply_enhanced.py --profile l2-server --dry-run \
  --report /tmp/test-report.json --log-level DEBUG
```

### Step 4: Apply Hardening

```bash
sudo python3 cis_apply_enhanced.py --profile l2-server --apply \
  --report /root/hardening.json
```

### Step 5: Verify Compliance

```bash
sudo python3 cis_apply_enhanced.py --profile l2-server --verify \
  --report /root/verify.json
```

## Configuration Highlights

### SSH Access Control
```yaml
ssh:
  # Uncomment and customize:
  # allow_users: ["admin", "operator"]
  # allow_groups: ["sshusers", "wheel"]
  # deny_users: ["nobody"]
  banner: "/etc/issue.net"
  max_startups: "10:30:60"
  max_sessions: 10
```

### Password Policy
```yaml
auth:
  pass_max_days: 365
  pass_min_days: 7
  pass_warn_age: 14
  pass_inactive: 30
  apply_to_existing_users: true
```

### AIDE File Integrity
```yaml
aide:
  initialize_if_missing: false
  use_systemd_timer: true
  monitor_audit_tools: true
```

### Audit Configuration
```yaml
audit:
  enable_comprehensive_rules: true
  audit_privileged_commands: true
  max_log_file_action: "keep_logs"
  space_left_action: "email"
```

### Bluetooth Removal
```yaml
packages:
  remove_bluetooth: true
  disable_unnecessary_services: true
```

### su Restriction
```yaml
sudo:
  restrict_su: true
  su_group: "wheel"
```

## Validation Checklist

After applying hardening, verify:

- [ ] SSH access still works (test before disconnecting!)
- [ ] All required services are running
- [ ] Users can authenticate properly
- [ ] Audit logs are being generated
- [ ] AIDE database initialized (if enabled)
- [ ] No unexpected service disruptions

## Troubleshooting

### SSH Lockout Prevention
Always test SSH access in a separate terminal before disconnecting:
```bash
# Keep existing session open
# In new terminal:
ssh user@server
```

### Module Errors
```bash
# Check module syntax
python3 -m py_compile modules/*.py

# Run with debug logging
sudo python3 cis_apply_enhanced.py --profile l2-server --dry-run --log-level DEBUG
```

### Configuration Issues
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('cis_config.yaml'))"
```

## Files Reference

| File | Purpose |
|------|---------|
| `cis_config.yaml` | Main configuration file |
| `cis_apply.py` | Standard hardening script |
| `cis_apply_enhanced.py` | Enhanced script with logging |
| `modules/` | Hardening modules directory |
| `CONTROL.csv` | CIS benchmark scan results |
| `IMPLEMENTATION_GUIDE.md` | Detailed implementation guide |

## Support

For detailed implementation information, see:
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) - Step-by-step guide
- [ENHANCEMENT_RECOMMENDATIONS.md](ENHANCEMENT_RECOMMENDATIONS.md) - Control analysis
- CIS Oracle Linux 9 Benchmark v2.0.0 documentation

