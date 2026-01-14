# CIS Apply Script - Implementation Guide

## Overview

This guide covers the comprehensive CIS hardening framework for Oracle Enterprise Linux 9, implementing **127+ controls** from CIS Benchmark v2.0.0 Level 2 Server profile.

## Modules Reference

### 1. **modules/pam.py** - PAM Hardening
**CIS Controls:** 5.3.x series

**What it does:**
- PAM-1: Password history restriction with `use_authtok` (prevent password reuse)
- PAM-1b: Configure /etc/security/pwhistory.conf
- PAM-2: PAM session timeout configuration
- PAM-3: Minimum password length enforcement

**Configuration in cis_config.yaml:**
```yaml
pam:
  password_remember: 5           # Prevent reuse of last N passwords
  session_timeout: 600           # 10-minute idle timeout
  pass_min_len: 14               # Minimum password length
  use_authtok: true              # Enable use_authtok in pam_pwhistory
```

### 2. **modules/boot.py** - Boot Hardening
**CIS Controls:** 1.3.x, 1.4.x series

**What it does:**
- BOOT-1: Restrict /boot/grub2/grub.cfg permissions (mode 600)
- BOOT-2: Restrict /boot/grub2/user.cfg permissions (mode 600)
- BOOT-3: GRUB bootloader password protection
- BOOT-3b: Fix all boot file permissions
- BOOT-4: Secure kernel parameters (audit, apparmor, selinux)

**Configuration in cis_config.yaml:**
```yaml
boot:
  grub_password: true
  enforce_kernel_params: true
  grub_password_hash: "grub.pbkdf2.sha512.10000.HASH..."  # Generate with grub2-mkpasswd-pbkdf2
  fix_boot_permissions: true
```

### 3. **modules/auth.py** - Authentication Hardening
**CIS Controls:** 5.6.x series

**What it does:**
- AUTH-1: Password quality settings (pwquality.conf)
- AUTH-2: Login.defs password aging (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE)
- AUTH-2a: Default inactive period (useradd -D -f)
- AUTH-2b: Apply password aging to existing users via chage

**Configuration in cis_config.yaml:**
```yaml
auth:
  pass_max_days: 365
  pass_min_days: 7
  pass_warn_age: 14
  pass_inactive: 30              # Inactive days before account lock
  apply_to_existing_users: true  # Apply aging to existing users
```

### 4. **modules/mounts.py** - Mount Options
**CIS Controls:** 1.1.x series

**What it does:**
- MNT-1: /tmp mount options (noexec, nodev, nosuid)
- MNT-2: /dev/shm mount options
- MNT-3: /home mount options
- MNT-4: /var mount options
- MNT-5: /var/log/audit mount options

**Configuration in cis_config.yaml:**
```yaml
mounts:
  enable_tmp_mount_units: true
  dev_shm_options: ["noexec", "nodev", "nosuid"]
  home_options: ["nodev", "nosuid"]
  var_options: ["nodev", "nosuid"]
  var_log_audit_options: ["nodev", "nosuid", "noexec"]
```

### 5. **modules/coredumps.py** - Core Dump Restrictions
**CIS Controls:** 1.5.x series

**What it does:**
- CORE-1: Restrict core dumps in limits.conf
- CORE-2: systemd-coredump Storage=none, ProcessSizeMax=0

**Configuration in cis_config.yaml:**
```yaml
coredumps:
  disable_systemd_coredump: true
  storage: "none"
  process_size_max: 0
```

### 6. **modules/sysctl.py** - Kernel Parameters
**CIS Controls:** 3.1.x, 3.2.x, 3.3.x series

**What it does:**
- Network hardening (IP forwarding, source routing, ICMP redirects)
- IPv6 hardening (source route, forwarding)
- ptrace_scope, perf_event_paranoid settings

**Configuration in cis_config.yaml:**
```yaml
# Uses L1/L2 profile defaults - no additional config needed
```

### 7. **modules/firewalld.py** - Firewall Configuration
**CIS Controls:** 3.4.x series

**What it does:**
- FW-1: Enable and configure firewalld
- FW-2: Service allowlist
- FW-3: Drop incoming/outgoing by default
- FW-4: Mask nftables service
- FW-5: Configure loopback traffic rules

**Configuration in cis_config.yaml:**
```yaml
firewalld:
  enforce_allowlist: true
  zone: "public"
  allow_services: ["ssh", "https"]
  configure_loopback: true
  mask_nftables: true
```

### 8. **modules/ssh.py** - SSH Hardening
**CIS Controls:** 5.2.x series (20+ controls)

**What it does:**
- Full SSH configuration including Banner, LogLevel, MaxStartups, MaxSessions
- Cryptographic algorithms (ciphers, MACs, KEX)
- Access control (AllowUsers, AllowGroups, DenyUsers, DenyGroups)
- DisableForwarding, GSSAPIAuthentication

**Configuration in cis_config.yaml:**
```yaml
ssh:
  permit_root_login: "no"
  password_authentication: "no"
  banner: "/etc/issue.net"
  log_level: "INFO"
  max_startups: "10:30:60"
  max_sessions: 10
  disable_forwarding: "yes"
  gssapi_authentication: "no"
  ciphers: "aes256-gcm@openssh.com,..."
  macs: "hmac-sha2-512-etm@openssh.com,..."
  # Uncomment to restrict access:
  # allow_users: ["admin", "operator"]
  # allow_groups: ["sshusers", "wheel"]
```

### 9. **modules/audit.py** - Audit Configuration
**CIS Controls:** 4.1.x series

**What it does:**
- AUD-1: Install and enable auditd
- AUD-2: Configure auditd.conf (max_log_file_action, space_left_action, etc.)
- AUD-3: Comprehensive audit rules (time, identity, network, DAC, privileged commands, kernel modules)
- Dynamic privileged command detection

**Configuration in cis_config.yaml:**
```yaml
audit:
  enable_comprehensive_rules: true
  audit_privileged_commands: true
  max_log_file_action: "keep_logs"
  space_left_action: "email"
  admin_space_left_action: "halt"
  disk_full_action: "halt"
  disk_error_action: "halt"
```

### 10. **modules/aide.py** - File Integrity Monitoring
**CIS Controls:** 6.2.x series

**What it does:**
- AIDE-1: Install AIDE
- AIDE-2: Initialize database (optional)
- AIDE-3: Schedule daily checks (cron or systemd timer)
- AIDE-4: Configure aide.conf
- AIDE-5: Monitor audit tools integrity

**Configuration in cis_config.yaml:**
```yaml
aide:
  initialize_if_missing: false
  schedule_daily_check: true
  use_systemd_timer: true        # Use systemd timer instead of cron
  monitor_audit_tools: true      # Add audit tools to aide.conf
```

### 11. **modules/cron.py** - Cron/At Hardening
**CIS Controls:** 5.1.x series

**What it does:**
- CRON-0: Ensure cronie package installed
- CRON-1: Fix cron file permissions
- CRON-2: Configure cron.allow/cron.deny
- CRON-3: Fix at file permissions
- CRON-4: Ensure at package installed

**Configuration in cis_config.yaml:**
```yaml
cron:
  install_cronie: true
  install_at: true
  fix_deny_permissions: true
```

### 12. **modules/packages.py** - Package Management
**CIS Controls:** 2.x series

**What it does:**
- PKG-1: Remove unnecessary packages
- PKG-2: Remove bluetooth (bluez, bluez-libs, bluez-obexd)
- PKG-3: Stop/disable/mask bluetooth service

**Configuration in cis_config.yaml:**
```yaml
packages:
  remove_bluetooth: true
  disable_unnecessary_services: true
```

### 13. **modules/logging.py** - Logging Configuration
**CIS Controls:** 4.2.x series

**What it does:**
- LOG-1: Configure rsyslog
- LOG-9: Fix /var/log/sssd permissions
- LOG-10: Fix all log file permissions
- LOG-11: Configure systemd-journal-upload

**Configuration in cis_config.yaml:**
```yaml
logging:
  fix_logfile_permissions: true
  configure_journal_upload: true
  journal_upload_url: ""         # Set remote URL if needed
```

### 14. **modules/sudo.py** - Sudo Hardening
**CIS Controls:** 5.3.x series

**What it does:**
- SUDO-1: Configure use_pty
- SUDO-2: Configure logfile
- SUDO-3: Various sudo settings (log_host, log_year, etc.)
- SUDO-4: Restrict su command via pam_wheel.so

**Configuration in cis_config.yaml:**
```yaml
sudo:
  use_pty: true
  logfile: "/var/log/sudo.log"
  restrict_su: true
  su_group: "wheel"
```

## Implementation Steps

### Step 1: Review and Customize Configuration

Edit `cis_config.yaml` to match your environment:

```bash
# Review all settings
cat cis_config.yaml

# Key items to customize:
# - SSH allow_users/allow_groups for access control
# - GRUB password hash
# - Firewall allowed services
# - Password aging policies
```

### Step 2: Generate GRUB Password Hash

```bash
# On the target system:
grub2-mkpasswd-pbkdf2

# Enter and confirm password
# Copy the hash starting with "grub.pbkdf2.sha512..."
# Add to cis_config.yaml under boot.grub_password_hash
```

### Step 3: Test with Dry-Run

```bash
# Test without making changes
sudo python3 cis_apply_enhanced.py --profile l2-server --dry-run \
  --report /tmp/test-report.json --log-level DEBUG

# Review the report
cat /tmp/test-report.json | python3 -m json.tool
```

### Step 4: Apply Hardening

```bash
# Apply all controls
sudo python3 cis_apply_enhanced.py --profile l2-server --apply \
  --report /root/cis-hardening.json

# Review results
cat /root/cis-hardening.json | python3 -m json.tool
```

### Step 5: Verify Compliance

```bash
# Verify without making changes
sudo python3 cis_apply_enhanced.py --profile l2-server --verify \
  --report /root/cis-verify.json
```

## Module Development Template

When creating new modules, follow this pattern:

```python
"""
Module Title
CIS Reference: X.X.X series - Description
"""
from typing import List, Dict, Any
from .utils import ActionResult, run
import os, subprocess

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply CIS controls: [List controls]
    
    Args:
        cfg: Configuration dictionary for this module
        dry_run: If True, don't make changes
        profile: Which profile is being applied (l1-server, l2-server, etc.)
    
    Returns:
        List of ActionResult objects
    """
    results = []
    
    # Control 1
    control_id = "MODULE-1"
    title = "Control description"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        # Implementation
        if not dry_run:
            # Apply changes
            pass
        
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=changed,
            ok=ok,
            notes=notes,
            commands=commands,
            files=files
        ))
    except Exception as e:
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=False,
            ok=False,
            notes=f"Error: {str(e)}",
            commands=[],
            files=[]
        ))
    
    return results
```

## Testing

### Test All Modules Load
```bash
python3 -m py_compile modules/*.py && echo "All modules OK"
```

### Test Specific Module
```bash
sudo python3 -c "
from modules.boot import apply
result = apply({}, dry_run=True, profile='l2-server')
for r in result:
    print(f'{r.id}: {r.ok}')
"
```

### Validate Report Structure
```bash
sudo python3 cis_apply_enhanced.py --profile l2-server --dry-run --report /tmp/report.json
python3 << 'EOF'
import json
with open('/tmp/report.json') as f:
    report = json.load(f)
    print(f"Controls: {report['execution']['total_controls']}")
    print(f"Compliance: {report['execution']['compliance_percentage']}%")
EOF
```

## CIS Control Categories Addressed

| Category | CIS Section | Module(s) |
|----------|-------------|-----------|
| Filesystem | 1.1.x | mounts.py |
| Software Updates | 1.2.x | packages.py |
| Bootloader | 1.4.x | boot.py |
| Process Hardening | 1.5.x | coredumps.py, sysctl.py |
| SELinux | 1.6.x | selinux.py |
| Services | 2.x | packages.py, services.py |
| Network | 3.1.x - 3.3.x | sysctl.py, ipv6.py |
| Firewall | 3.4.x | firewalld.py |
| Logging | 4.2.x | logging.py |
| Auditing | 4.1.x | audit.py |
| SSH | 5.2.x | ssh.py |
| PAM | 5.3.x | pam.py, auth.py |
| User Accounts | 5.6.x | auth.py |
| Sudo | 5.3.7 | sudo.py |
| File Integrity | 6.2.x | aide.py |
| File Permissions | 6.1.x | fileperms.py |

## Files Reference

| File | Description |
|------|-------------|
| `cis_apply.py` | Main hardening script |
| `cis_apply_enhanced.py` | Enhanced version with logging/reporting |
| `cis_config.yaml` | Configuration file |
| `modules/` | Hardening modules directory |
| `CONTROL.csv` | CIS benchmark scan results |
| `QUICK_START.md` | Quick start guide |

## Support

For questions about specific CIS controls, refer to:
- CIS Oracle Linux 9 Benchmark v2.0.0
- Control mapping in cis_apply_enhanced.py
- Module documentation comments

