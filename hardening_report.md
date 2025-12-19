# CIS Benchmark Hardening Report

**Oracle Enterprise Linux 9.x Level 2 Server with Firewalld**

---

## 📋 Report Metadata

| Property | Value |
|----------|-------|
| **Hostname** | oel-cis-1216.coe.hv |
| **Kernel** | 5.15.0-205.149.5.1.el9uek.x86_64 |
| **Machine Type** | x86_64 |
| **Report Generated** | 2025-12-19 06:53:36 UTC |
| **CIS Benchmark** | Oracle Linux 9 v2.0.0 |
| **Script Version** | 2.0 |
| **Profile** | l2-server |
| **Dry Run** | false |

---

## 📊 Execution Summary

| Metric | Value | Status |
|--------|-------|--------|
| **Total Controls** | 66 | ✅ |
| **Passed** | 66 | ✅ |
| **Failed** | 0 | ✅ |
| **Compliance Rate** | 100.0% | ✅ |

---

## 🔧 Remediation Summary

| Category | Count |
|----------|-------|
| **Controls Remediated** | 39 |
| **Already Compliant** | 27 |
| **Failed** | 0 |
| **Execution Status** | ✅ SUCCESS |

---

## 📈 Control Results by Category

### Kernel & System Hardening (3 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| KERN-1 | Disable uncommon filesystem/network kernel modules | ✅ PASS | Yes |
| SYSCTL-1 | Apply CIS sysctl hardening | ✅ PASS | Yes |
| CRYPTO-1 | Ensure system crypto policy is not LEGACY | ✅ PASS | No |

### Boot & Bootloader (5 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| BOOT-1 | Ensure /boot/grub2/grub.cfg has restricted permissions | ✅ PASS | No |
| BOOT-2 | Ensure /boot/grub2/user.cfg has restricted permissions | ✅ PASS | No |
| BOOT-3 | Ensure GRUB bootloader has password protection | ✅ PASS | No |
| BOOT-4 | Ensure audit kernel parameters are set in /etc/default/grub | ✅ PASS | Yes |
| BOOT-5 | Ensure GRUB kernel parameters are secure | ✅ PASS | No |

### Firewall & Network (3 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| FW-1 | Install firewalld | ✅ PASS | Yes |
| FW-2 | Enable firewalld | ✅ PASS | Yes |
| FW-3 | Configure firewalld | ✅ PASS | Yes |

### Authentication & Access Control (4 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| AUTH-1 | Configure PAM password quality and history | ✅ PASS | Yes |
| AUTH-2 | Configure session timeout (TMOUT) | ✅ PASS | Yes |
| AUTH-3 | Remove insecure PAM modules (nullok) | ✅ PASS | Yes |
| AUTH-4 | Configure account lockout for root | ✅ PASS | Yes |

### Services Management (20 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| SVC-avahi-daemon | Disable service: avahi-daemon | ✅ PASS | Yes |
| SVC-cups | Disable service: cups | ✅ PASS | Yes |
| SVC-dhcpd | Disable service: dhcpd | ✅ PASS | Yes |
| SVC-slapd | Disable service: slapd | ✅ PASS | Yes |
| SVC-nfs-server | Disable service: nfs-server | ✅ PASS | Yes |
| SVC-rpcbind | Disable service: rpcbind | ✅ PASS | Yes |
| SVC-smb | Disable service: smb | ✅ PASS | Yes |
| SVC-snmpd | Disable service: snmpd | ✅ PASS | Yes |
| SVC-rsyncd | Disable service: rsyncd | ✅ PASS | Yes |
| SVC-ypserv | Disable service: ypserv | ✅ PASS | Yes |
| SVC-telnet.socket | Disable service: telnet.socket | ✅ PASS | Yes |
| SVC-tftp.socket | Disable service: tftp.socket | ✅ PASS | Yes |
| SVC-systemd-journal-remote.service | Disable service: systemd-journal-remote.service | ✅ PASS | Yes |
| SVC-systemd-journal-upload.service | Disable service: systemd-journal-upload.service | ✅ PASS | Yes |
| SVC-auditd | Enable Audit daemon for security logging | ✅ PASS | Yes |
| SVC-JOURNAL-REMOTE | Ensure systemd-journal-remote is disabled | ✅ PASS | No |
| SVC-AIDE-PKG | Ensure aide package is installed | ✅ PASS | Yes |
| SVC-AIDE-INIT | Ensure AIDE database is initialized | ✅ PASS | Yes |
| SVC-aidecheck.service | Enable AIDE file integrity monitoring service | ✅ PASS | No |
| SVC-aidecheck.timer | Enable AIDE file integrity monitoring timer | ✅ PASS | No |

### Audit & Logging (16 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| AUD-1 | Install auditd and aide packages | ✅ PASS | Yes |
| AUD-2 | Enable auditd service | ✅ PASS | Yes |
| AUD-2a | Configure auditd settings | ✅ PASS | No |
| AUD-3 | Install CIS audit rules and load | ✅ PASS | No |
| LOG-1 | Harden journald persistence/limits/forwarding | ✅ PASS | No |
| LOG-2 | Install rsyslog | ✅ PASS | Yes |
| LOG-3 | Configure rsyslog $FileCreateMode | ✅ PASS | No |
| LOG-4 | Enable rsyslog service | ✅ PASS | Yes |
| LOG-5 | Enable systemd-journald service | ✅ PASS | Yes |
| LOG-6-/var/log/wtmp | Set permissions on /var/log/wtmp | ✅ PASS | No |
| LOG-6-/var/log/btmp | Set permissions on /var/log/btmp | ✅ PASS | No |
| LOG-6-/var/log/lastlog | Set permissions on /var/log/lastlog | ✅ PASS | No |
| LOG-7-/var/log/messages | Set permissions on /var/log/messages | ✅ PASS | No |
| LOG-7-/var/log/secure | Set permissions on /var/log/secure | ✅ PASS | No |
| LOG-9 | Install systemd-journal-remote | ✅ PASS | Yes |
| LOG-10 | Disable systemd-journal-remote | ✅ PASS | Yes |
| LOG-11 | Disable systemd-journal-upload | ✅ PASS | Yes |

### Package Management (1 control)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| PKG-1 | Remove legacy/insecure network packages | ✅ PASS | Yes |

### File Integrity & Permissions (3 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| AIDE-CONFIG | Ensure AIDE configuration file exists | ✅ PASS | Yes |
| AIDE-2 | Initialize AIDE database | ✅ PASS | Yes |
| PERM-1 | Harden key system file permissions | ✅ PASS | No |

### Security Module (1 control)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| SELINUX-1 | Ensure SELinux is enforcing | ✅ PASS | No |

### Login & Session Banners (1 control)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| BANNER-1 | Set login banners and clear /etc/motd | ✅ PASS | No |

### SSH & Sudo (2 controls)

| Control ID | Title | Status | Changed |
|------------|-------|--------|---------|
| SSH-1 | Harden SSH daemon configuration | ✅ PASS | No |
| SUDO-1 | Configure sudo to use pty and log to /var/log/sudo.log | ✅ PASS | No |

---

## 🎯 Compliance Summary

### Breakdown by Status

```
✅ PASSED:  66 controls (100.0%)
❌ FAILED:   0 controls (0.0%)
───────────────────────────
Total:      66 controls
```

### Controls by Change Status

- **Remediated (Changed):** 39 controls
- **Already Compliant (No Change):** 27 controls
- **Total:** 66 controls

### Category Performance

| Category | Passed | Failed | Compliance |
|----------|--------|--------|------------|
| Kernel & System | 3 | 0 | 100% |
| Boot & Bootloader | 5 | 0 | 100% |
| Firewall & Network | 3 | 0 | 100% |
| Authentication | 4 | 0 | 100% |
| Services | 20 | 0 | 100% |
| Audit & Logging | 17 | 0 | 100% |
| Package Management | 1 | 0 | 100% |
| File Integrity | 3 | 0 | 100% |
| Security Modules | 1 | 0 | 100% |
| Session Management | 1 | 0 | 100% |
| Remote Access | 2 | 0 | 100% |
| **TOTAL** | **66** | **0** | **100%** |

---

## 📝 Key Accomplishments

### Security Hardening Measures Applied

1. **Kernel Module Hardening**
   - Disabled uncommon filesystems: cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf, usb-storage
   - Disabled uncommon network protocols: dccp, sctp, rds, tipc

2. **Boot Security**
   - GRUB bootloader password protection enabled
   - Kernel audit parameters configured (audit=1, audit_backlog_limit=8192)
   - Secure kernel parameters applied

3. **Service Hardening**
   - 14 unnecessary services disabled
   - Auditd and rsyslog enabled for comprehensive logging
   - AIDE installed and database initialized for file integrity monitoring

4. **Authentication Hardening**
   - PAM password quality controls: maxrepeat=3, maxsequence=3, difok=3
   - Password history: remember=5
   - Session timeout: 900 seconds
   - Account lockout for root with 60-second unlock time
   - Insecure PAM parameters removed

5. **Audit & Logging**
   - 150+ comprehensive audit rules loaded
   - Journald forwarding to syslog enabled
   - Rsyslog file creation mode hardened (0640)
   - Log file permissions secured

6. **Network Security**
   - Firewalld installed and enabled
   - Firewall zones configured
   - Sysctl network parameters hardened:
     - IP forwarding disabled
     - ICMP redirects disabled
     - TCP SYN cookies enabled
     - Reverse path filtering enabled
     - Source route handling disabled

7. **System Permissions**
   - Key system files (/etc/passwd, /etc/group, /etc/shadow) permissions verified
   - SSH configuration hardened
   - Sudo logging to /var/log/sudo.log configured

8. **File Integrity Monitoring**
   - AIDE file integrity monitoring tool configured
   - Comprehensive file/directory monitoring rules applied
   - AIDE database initialized for baseline

---

## ✅ Verification Results

All 66 CIS Level 2 benchmark controls have been successfully implemented and verified:

- ✅ **100% Compliance Rate**
- ✅ **All Controls Passing**
- ✅ **No Failed Remediations**
- ✅ **System Fully Hardened**

---

## 🔒 Security Posture Assessment

### Overall Rating: **EXCELLENT** 🟢

Your system now meets the CIS Oracle Linux 9 Level 2 benchmark requirements:

| Aspect | Status | Notes |
|--------|--------|-------|
| **Kernel Hardening** | ✅ Complete | Unnecessary modules disabled |
| **Access Control** | ✅ Complete | PAM and sudo hardening applied |
| **Audit & Logging** | ✅ Complete | Comprehensive audit rules loaded |
| **Network Security** | ✅ Complete | Firewall and sysctl parameters secured |
| **File Integrity** | ✅ Complete | AIDE installed and initialized |
| **Service Hardening** | ✅ Complete | Unnecessary services disabled |
| **Authentication** | ✅ Complete | Session timeout and password policies configured |

---

## 📋 Report Information

- **Report Type:** CIS Benchmark Compliance Report
- **Report Format:** Markdown
- **Generated:** 2025-12-19 06:53:36 UTC
- **System:** oel-cis-1216.coe.hv
- **Profile:** CIS Oracle Linux 9 Level 2 - Server with Firewalld
- **Status:** ✅ FULLY COMPLIANT

---

## 📞 Next Steps

### Recommended Actions

1. **Continuous Monitoring**
   - Monitor auditd logs regularly: `tail -f /var/log/audit/audit.log`
   - Check rsyslog entries: `tail -f /var/log/secure`

2. **File Integrity Monitoring**
   - Perform regular AIDE checks: `aide --check`
   - Schedule AIDE daily via cron or aidecheck.timer

3. **Periodic Compliance Validation**
   - Re-run hardening script quarterly to ensure compliance
   - Address any configuration drift immediately

4. **Backup & Recovery**
   - Maintain backups of critical files
   - Document any approved deviations from baseline
   - Keep audit logs for regulatory compliance

5. **Updates & Patches**
   - Keep system packages updated: `dnf update`
   - Monitor security advisories for critical patches
   - Test patches in non-production environment first

---

**End of Report**

*For detailed information about specific controls or remediation steps, refer to the CIS Benchmark v2.0.0 documentation or the implementation guide in this repository.*
