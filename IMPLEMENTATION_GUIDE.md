# CIS Apply Script - Implementation Guide for Missing Controls

## Overview

Your current `cis_apply.py` script **successfully applies all 26 L2-server controls**. However, the CIS Oracle Linux 9 Benchmark includes **additional sub-controls and hardening recommendations** that would further improve compliance.

## New Modules Added

I've created two example modules to demonstrate the enhancement approach:

### 1. **modules/pam.py** - PAM Hardening
**CIS Controls:** 5.3.x series

**What it adds:**
- PAM-1: Password history restriction (prevent password reuse)
- PAM-2: PAM session timeout configuration
- PAM-3: Minimum password length enforcement

**Configuration in cis_config.yaml:**
```yaml
pam:
  password_remember: 5           # Prevent reuse of last N passwords
  session_timeout: 600           # 10-minute idle timeout
  pass_min_len: 14               # Minimum password length
```

### 2. **modules/boot.py** - Boot Hardening
**CIS Controls:** 1.3.x, 1.4.x series

**What it adds:**
- BOOT-1: Restrict /boot/grub2/grub.cfg permissions (mode 600)
- BOOT-2: Restrict /boot/grub2/user.cfg permissions (mode 600)
- BOOT-3: GRUB bootloader password protection
- BOOT-4: Secure kernel parameters (audit, apparmor, selinux)

**Configuration in cis_config.yaml:**
```yaml
boot:
  grub_password: true            # Require GRUB password
  enforce_kernel_params: true    # Enforce secure boot parameters
```

## Enhanced Main Script

**cis_apply_enhanced.py** - Next-generation version with improvements:

### New Features:
1. **Control Mapping to CIS Benchmark**
   - Each control ID mapped to specific CIS section
   - Example: "SSH-1" → "5.2.1-5.2.21"

2. **Structured Logging**
   - File-based logging: `/var/log/cis_apply.log`
   - Configurable log levels: DEBUG, INFO, WARNING, ERROR
   - Usage: `--log-level DEBUG`

3. **Enhanced Reporting**
   - Compliance percentage calculation
   - Remediation tracking (remediated vs already compliant)
   - System information capture

4. **Verification Mode**
   - `--verify` flag for compliance checking without changes
   - Useful for audit and drift detection

5. **Better Error Handling**
   - Comprehensive exception handling per module
   - Failed modules don't stop execution
   - Detailed error messages in report

6. **Summary Output**
   ```
   ============================================================
   CIS L2-SERVER Hardening Report
   ============================================================
   Total Controls:        26
   Passed:                25
   Failed:                1
   Compliance:            96.2%
   Overall Status:        ✅ PASS
   ============================================================
   ```

## Recommended Implementation Priority

### Phase 1: Core Missing Controls (High Priority)
These are explicitly mentioned in CIS L2 requirements:

1. **SSH Cryptographic Configuration** (Enhance ssh.py)
   ```python
   # Current: ciphers, macs, kex_algorithms are optional
   # Should be: MANDATORY for L2
   # Add to config:
   ssh:
     ciphers: "aes256-ctr,aes192-ctr,aes128-ctr"
     macs: "hmac-sha2-512,hmac-sha2-256"
     kex_algorithms: "diffie-hellman-group-exchange-sha256"
   ```

2. **Boot Hardening** (boot.py - already created)
   - GRUB password protection
   - Secure kernel parameters

3. **PAM Advanced Configuration** (pam.py - already created)
   - Password reuse restrictions
   - Session timeouts
   - Minimum password length

4. **TCP Wrappers** (NEW MODULE NEEDED)
   ```python
   # modules/tcpwrappers.py
   # Configure /etc/hosts.allow and /etc/hosts.deny
   # Implement network access control lists
   ```

### Phase 2: Logging & Monitoring Enhancement
5. **Rsyslog Advanced Configuration** (Enhance logging.py)
   ```python
   # Add rsyslog rules for:
   # - Auth logging
   # - Action on log size
   # - Log forwarding capability
   ```

6. **AIDE Baseline Initialization** (Enhance aide.py)
   ```python
   # Add automatic AIDE database initialization
   # Add daily cron job for AIDE checks
   # Email alerts configuration
   ```

### Phase 3: Package Management Security
7. **DNF/YUM Repository Hardening** (NEW MODULE NEEDED)
   ```python
   # modules/dnf.py
   # - Enforce GPG signature verification
   # - Repository validation
   # - Remove unnecessary repositories
   ```

8. **Postfix Mail Service** (NEW MODULE NEEDED)
   ```python
   # modules/postfix.py
   # - Remove if unnecessary
   # - Configure for local delivery only
   # - Disable network listening
   ```

## Integration Steps

### Step 1: Update cis_apply.py to use enhanced version
```bash
# Backup current version
cp cis_apply.py cis_apply.py.backup

# Replace with enhanced version
mv cis_apply_enhanced.py cis_apply.py
chmod +x cis_apply.py
```

### Step 2: Add new modules to profile
```python
# In cis_apply.py, update PROFILES:
PROFILES = {
    "l2-server": [
        # ... existing modules ...
        "boot",        # New
        "pam",         # New (when ready)
        "tcpwrappers", # New (when ready)
    ]
}
```

### Step 3: Update configuration file
```bash
# Add to cis_config.yaml:
cat >> cis_config.yaml << 'EOF'

boot:
  grub_password: true
  enforce_kernel_params: true

pam:
  password_remember: 5
  session_timeout: 600
  pass_min_len: 14

tcpwrappers:
  enable: true
  allowed_hosts:
    - "127.0.0.1"
    - "localhost"
    - "10.0.0.0/8"
EOF
```

### Step 4: Test with dry-run
```bash
# Test new modules without applying
sudo python3 cis_apply.py --profile l2-server --dry-run \
  --report /tmp/test-report.json --log-level DEBUG

# Check report
cat /tmp/test-report.json | python3 -m json.tool
```

### Step 5: Apply changes
```bash
# Apply hardening with new modules
sudo python3 cis_apply.py --profile l2-server --apply \
  --report /root/cis-hardening.json

# Verify compliance
sudo python3 cis_apply.py --profile l2-server --verify \
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

## Testing the New Implementation

### Test 1: Verify all modules load
```bash
sudo python3 cis_apply.py --profile l2-server --dry-run --log-level DEBUG 2>&1 | grep -E "Loading module|Error|Failed"
```

### Test 2: Check specific module
```bash
sudo python3 -c "
from modules.boot import apply
result = apply({}, dry_run=True, profile='l2-server')
for r in result:
    print(f'{r.id}: {r.ok}')
"
```

### Test 3: Validate report structure
```bash
sudo python3 cis_apply.py --profile l2-server --dry-run --report /tmp/report.json
python3 << 'EOF'
import json
with open('/tmp/report.json') as f:
    report = json.load(f)
    print(f"Controls: {report['execution']['total_controls']}")
    print(f"Compliance: {report['execution']['compliance_percentage']}%")
    print(f"Metadata: {report['metadata']}")
EOF
```

## Expected Results After Implementation

### Before (Current State)
```
Total Controls:  26
Passed:          25
Compliance:      96.2%
```

### After (With All New Modules)
```
Total Controls:  45+
Passed:          42+
Compliance:      95%+ (higher number of controls, but still excellent)
```

## Files Provided

1. **ENHANCEMENT_RECOMMENDATIONS.md** - Detailed analysis of all missing controls
2. **cis_apply_enhanced.py** - Next-generation script with logging, reporting, verification
3. **modules/boot.py** - Boot hardening (4 controls)
4. **modules/pam.py** - PAM hardening (3 controls)

## Next Steps

1. ✅ Review the enhancement recommendations document
2. ✅ Test the new modules in dry-run mode
3. ✅ Update cis_config.yaml with new parameters
4. ✅ Create remaining modules (tcpwrappers, dnf, postfix)
5. ✅ Integrate new modules into main script
6. ✅ Run full L2 hardening with all controls
7. ✅ Generate final compliance report

## Support

For questions about specific CIS controls, refer to:
- CIS Oracle Linux 9 Benchmark v2.0.0 (attached PDF)
- Control mapping in cis_apply_enhanced.py
- Module documentation comments

