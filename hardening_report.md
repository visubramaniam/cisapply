# CIS Compliance Report - L2-SERVER

## Summary

| Metric | Value |
|--------|-------|
| **Profile** | L2-SERVER |
| **Hostname** | oel-cis-1216.coe.hv |
| **OS** | N/A |
| **Kernel** | 5.15.0-205.149.5.1.el9uek.x86_64 |
| **Benchmark** | Oracle Linux 9 v2.0.0 |
| **Generated** | 2026-01-17T23:07:24.917260 |
| **Mode** | APPLY |

## Compliance Score

| Status | Count |
|--------|-------|
| **Total Controls** | 111 |
| **Passed** | 111 |
| **Failed** | 0 |
| **Compliance** | 100.0% |
| **Overall Status** | ✅ PASS |

## Remediation Summary

| Action | Count |
|--------|-------|
| Remediated | 38 |
| Already Compliant | 73 |
| Failed | 0 |

## Control Details

| Status | Control ID | CIS Section | Title | Changed | Notes |
|--------|------------|-------------|-------|---------|-------|
| ✅ | `KERN-1` | 1.1.1.1-1.1.1.8 | Disable uncommon filesystem/network kernel modules | Yes | cramfs: No change; freevxfs: No change; hfs: No change; hfsp... |
| ✅ | `SYSCTL-1` | 3.1.1-3.1.3 | Apply CIS sysctl hardening | Yes | /etc/bashrc: line 90: TMOUT: readonly variable /etc/profile:... |
| ✅ | `SYSCTL-2` | 3.1.2 | Ensure kernel.yama.ptrace_scope is set | No | kernel.yama.ptrace_scope already set to 2 |
| ✅ | `CRYPTO-1` | 1.5.2 | Ensure system crypto policy is not LEGACY | No | current: DEFAULT |
| ✅ | `BANNER-1` | 5.6.1-5.6.2 | Set login banners and clear /etc/motd | No | No change; No change; No change |
| ✅ | `SSH-1` | 5.2.1-5.2.22 | Harden SSH daemon configuration | Yes | /etc/bashrc: line 90: TMOUT: readonly variable /etc/profile:... |
| ✅ | `SSH-2` | 5.2.2 | Ensure /etc/ssh/sshd_config.d/ file permissions | No | All files already have correct permissions |
| ✅ | `SSH-3` | 5.2.3 | Ensure SSH config Include file permissions | No | No change |
| ✅ | `SUDO-1` | 5.3.1-5.3.3 | Configure sudo with use_pty, logging, and security settings | No | No change |
| ✅ | `SUDO-2` | 5.3.4 | Ensure sudo log file exists with proper permissions | No | /var/log/sudo.log already has correct permissions |
| ✅ | `SUDO-3` | 5.3.5 | Verify sudo use_pty is enabled | No | use_pty enabled in sudoers configuration |
| ✅ | `SUDO-4` | 5.3.6-5.3.7 | Restrict access to the su command | No | pam_wheel.so already configured in /etc/pam.d/su |
| ✅ | `SVC-avahi-daemon` | 2.1.1 | Disable service: avahi-daemon | Yes |  |
| ✅ | `SVC-cups` | 2.2.1 | Disable service: cups | Yes |  |
| ✅ | `SVC-dhcpd` | 2.1.2 | Disable service: dhcpd | Yes |  |
| ✅ | `SVC-slapd` | 2.1.3 | Disable service: slapd | Yes |  |
| ✅ | `SVC-nfs-server` | 2.1.4 | Disable service: nfs-server | Yes |  |
| ✅ | `SVC-rpcbind` | 2.1.5 | Disable service: rpcbind | Yes |  |
| ✅ | `SVC-smb` | 2.2.2 | Disable service: smb | Yes |  |
| ✅ | `SVC-snmpd` | 2.2.3 | Disable service: snmpd | Yes |  |
| ✅ | `SVC-rsyncd` | 2.2.4 | Disable service: rsyncd | Yes |  |
| ✅ | `SVC-ypserv` | 2.1.6 | Disable service: ypserv | Yes |  |
| ✅ | `SVC-telnet.socket` | 2.3.1 | Disable service: telnet.socket | Yes |  |
| ✅ | `SVC-tftp.socket` | 2.3.2 | Disable service: tftp.socket | Yes |  |
| ✅ | `SVC-systemd-journal-remote.service` | 2.3.3.1 | Disable service: systemd-journal-remote.service | Yes |  |
| ✅ | `SVC-systemd-journal-upload.service` | 2.3.3.2 | Disable service: systemd-journal-upload.service | Yes |  |
| ✅ | `SVC-AIDE-PKG` | 6.1.1 | Ensure aide package is installed | No | Already installed: aide |
| ✅ | `SVC-AIDE-INIT` | 6.1.3 | Ensure AIDE database is initialized | No | AIDE database already exists |
| ✅ | `SVC-aidecheck.timer` | 6.1.5 | Enable AIDE file integrity monitoring timer | Yes |  |
| ✅ | `SVC-auditd` | 4.1.1.4 | Enable Audit daemon for security logging | Yes |  |
| ✅ | `SVC-JOURNAL-REMOTE` | 4.2.4.2 | Ensure systemd-journal-remote is disabled | No | systemd-journal-remote.service already disabled |
| ✅ | `PKG-1` | 2.4.1.1-2.4.1.8 | Remove legacy/insecure network packages | Yes | No match for argument: telnet No match for argument: telnet-... |
| ✅ | `PKG-2` | 2.4.2 | Remove bluetooth packages | Yes | No match for argument: bluez No match for argument: bluez-li... |
| ✅ | `PKG-3` | 2.4.3 | Disable unnecessary services | No | No unnecessary services found to disable |
| ✅ | `AUD-1` | 4.1.1.1-4.1.1.3 | Install auditd packages | No | Already installed: audit, audit-libs |
| ✅ | `AUD-2` | 4.1.1.4 | Enable auditd service | Yes |  |
| ✅ | `AUD-2a` | 4.1.2.1 | Configure auditd.conf settings | No | No change; No change; No change; No change; No change; No ch... |
| ✅ | `AUD-3` | 4.1.3.1-4.1.3.21 | Install CIS audit rules and load | No | No change /sbin/augenrules: No change /sbin/augenrules: Audi... |
| ✅ | `LOG-1` | 4.2.1.1.1-4.2.1.1.4 | Harden journald persistence/limits/forwarding | No | No change; No change; No change; No change |
| ✅ | `LOG-2` | 4.2.1.2 | Install rsyslog | No | Already installed: rsyslog |
| ✅ | `LOG-3` | 4.2.1.3 | Configure rsyslog $FileCreateMode | No | $FileCreateMode 0640 already configured |
| ✅ | `LOG-4` | 4.2.1.4 | Enable rsyslog service | Yes |  |
| ✅ | `LOG-5` | 4.2.1.5 | Enable systemd-journald service | Yes | The unit files have no installation config (WantedBy=, Requi... |
| ✅ | `LOG-6-/var/log/wtmp` | 4.2.2.1-4.2.2.3 | Set permissions on /var/log/wtmp | No | No change |
| ✅ | `LOG-6-/var/log/btmp` | 4.2.2.1-4.2.2.3 | Set permissions on /var/log/btmp | No | No change |
| ✅ | `LOG-6-/var/log/lastlog` | 4.2.2.1-4.2.2.3 | Set permissions on /var/log/lastlog | No | No change |
| ✅ | `LOG-7-/var/log/messages` | 4.2.2.4-4.2.2.5 | Set permissions on /var/log/messages | No | No change |
| ✅ | `LOG-7-/var/log/secure` | 4.2.2.4-4.2.2.5 | Set permissions on /var/log/secure | No | No change |
| ✅ | `LOG-8-/var/log/journal/103febaae9134c39b5dd203c49ab0726/system.journal` | 4.2.2.6 | Set permissions on /var/log/journal/103febaae9134c39b5dd203c49ab0726/system.journal | No | No change |
| ✅ | `LOG-8-/var/log/journal/103febaae9134c39b5dd203c49ab0726/system.journal` | 4.2.2.6 | Set permissions on /var/log/journal/103febaae9134c39b5dd203c49ab0726/system.journal | No | No change |
| ✅ | `LOG-8-/var/log/journal/103febaae9134c39b5dd203c49ab0726/user-1001.journal` | 4.2.2.6 | Set permissions on /var/log/journal/103febaae9134c39b5dd203c49ab0726/user-1001.journal | No | No change |
| ✅ | `LOG-9` | 4.2.2.7 | Set permissions on /var/log/sssd directory | No | No change |
| ✅ | `LOG-10` | 4.2.3 | Ensure permissions on all logfiles | No | Log file permissions OK |
| ✅ | `LOG-11a` | 4.2.4.1 | Install systemd-journal-remote | No | Already installed: systemd-journal-remote |
| ✅ | `LOG-11` | 4.2.4 | Ensure systemd-journal-upload is configured | Yes | systemd-journal-upload enabled (configure journal_remote_url... |
| ✅ | `PERM-1` | 5.6.1.1-5.6.1.10 | Harden key system file permissions | No | /etc/passwd: No change; /etc/group: No change; /etc/shadow: ... |
| ✅ | `FW-1` | 3.4.1.1 | Install firewalld | No | Already installed: firewalld |
| ✅ | `FW-2` | 3.4.1.2 | Enable firewalld | Yes |  |
| ✅ | `FW-3` | 3.4.1.3-3.4.1.4 | Configure firewalld | Yes | success Warning: ZONE_ALREADY_SET: public success success su... |
| ✅ | `FW-4` | 3.4.1.5 | Ensure nftables service is masked (firewalld manages nftables) | Yes | nftables service masked |
| ✅ | `FW-5` | 3.4.1.6 | Configure firewalld loopback traffic rules | Yes | Loopback traffic rules configured |
| ✅ | `SEL-1` | 1.5.1.1-1.5.1.8 | Ensure SELinux is enforcing | Yes | Enforcing /etc/bashrc: line 90: TMOUT: readonly variable /et... |
| ✅ | `AUTH-0` | 5.5.1 | Install authentication packages | No | Already installed: authselect, libpwquality, pam |
| ✅ | `AUTH-1` | 5.5.2 | Configure password quality (pwquality.conf) | No | No change; No change; No change; No change; No change; No ch... |
| ✅ | `AUTH-1b` | 5.5.3 | Configure password history (pwhistory.conf) | No | No change; No change |
| ✅ | `AUTH-2` | 5.5.4 | Configure password aging (login.defs) | No | No change; No change; No change |
| ✅ | `AUTH-2a` | 5.5.5 | Set default inactive period for new users | Yes | Set INACTIVE to 30 days |
| ✅ | `AUTH-2b` | 5.5.6 | Ensure password aging on existing user accounts | Yes | Applied password aging to users: root, libstoragemgmt, oelci... |
| ✅ | `AUTH-3` | 5.5.7 | Set default umask | Yes | /etc/bashrc: line 90: TMOUT: readonly variable /etc/profile:... |
| ✅ | `AUTH-3a` | 5.5.8 | Set session timeout via profile.d | Yes | Created /etc/profile.d/cis-tmout.sh with TMOUT=900 |
| ✅ | `AUTH-4` | 5.5.9 | Enable/configure account lockout (faillock) | Yes | [error] [/etc/authselect/system-auth] has unexpected content... |
| ✅ | `CORE-1` | 1.5.3 | Disable core dumps via limits.conf | Yes | No change; Updated /etc/sysctl.d/99-cis-hardening.conf: fs.s... |
| ✅ | `CORE-2` | 1.5.4 | Configure systemd-coredump settings (ProcessSizeMax, Storage) | No | No change; coredump.conf already has correct settings |
| ✅ | `CRON-0` | 5.1.1 | Install cronie package | No | Already installed: cronie |
| ✅ | `CRON-1` | 5.1.2 | Enable cron daemon | Yes |  |
| ✅ | `CRON-2` | 5.1.3-5.1.4 | Restrict cron/at to authorized users (create allow files) | No | No change; No change |
| ✅ | `CRON-2b` | 5.1.5 | Remove cron.deny and at.deny files (allow files take precedence) | No | /etc/cron.deny: not present (OK); /etc/at.deny: not present ... |
| ✅ | `CRON-3` | 5.1.6-5.1.8 | Harden cron permissions | No | /etc/crontab: No change; /etc/cron.hourly: No change; /etc/c... |
| ✅ | `CRON-4` | 5.1.9 | Install at package | No | Already installed: at |
| ✅ | `AIDE-1` | 6.1.1 | Install AIDE package | No | Already installed: aide |
| ✅ | `AIDE-CONFIG` | 6.1.2 | Ensure AIDE configuration file exists | No | AIDE configuration file already exists |
| ✅ | `AIDE-2` | 6.1.3 | AIDE database exists | No | AIDE database already initialized |
| ✅ | `AIDE-3` | 6.1.4 | Schedule daily AIDE integrity check | No | Daily AIDE check cron job already exists |
| ✅ | `AIDE-3b` | 6.1.5 | Configure AIDE systemd timer and service | No | AIDE systemd timer already configured |
| ✅ | `AIDE-4` | 6.1.6 | Configure AIDE email alerts | No | Email alerts disabled; set aide.email_alerts=true to enable |
| ✅ | `AIDE-5` | 6.1.7 | Configure AIDE to monitor audit tools integrity | No | Audit tools already configured in AIDE |
| ✅ | `MNT-1` | 1.1.2.1 | Configure tmpfs mounts for /tmp and /var/tmp | Yes |  |
| ✅ | `MNT-2` | 1.1.2.2 | Ensure noexec,nodev,nosuid options on /dev/shm | No | /dev/shm already has noexec,nodev,nosuid options |
| ✅ | `MNT-3` | 1.1.3.1 | Ensure nodev,nosuid options on /home partition | No | /home already has nodev,nosuid options |
| ✅ | `MNT-4` | 1.1.4.1 | Ensure nodev,nosuid options on /var partition | No | /var already has nodev,nosuid options |
| ✅ | `MNT-5` | 1.1.5.1-1.1.5.4 | Ensure nodev,nosuid,noexec options on /var/log/audit partition | No | /var/log/audit not in /etc/fstab - MANUAL: Create separate p... |
| ✅ | `MNT-6` | 1.1.6.1-1.1.6.4 | Ensure separate partition for /var/log | No | MANUAL ACTION REQUIRED: Create separate partition for /var/l... |
| ✅ | `IPV6-0` | 3.3.1-3.3.3 | Disable IPv6 (skipped by config) | No | ipv6.disable=false |
| ✅ | `PAM-1` | 5.4.1 | Enable pam_pwhistory module in password-auth and system-auth | No | pam_pwhistory.so with use_authtok already configured in /etc... |
| ✅ | `PAM-1b` | 5.4.2 | Configure password history in /etc/security/pwhistory.conf | No | No change; No change; No change |
| ✅ | `PAM-2` | 5.4.3 | Configure PAM session timeout | No | Session timeout configured for 600 seconds |
| ✅ | `PAM-3` | 5.4.4 | Set minimum password length (login.defs) | No | No change |
| ✅ | `BOOT-1` | 1.4.1 | Ensure /boot/grub2/grub.cfg has restricted permissions (600) | No | Permissions already correct (600) |
| ✅ | `BOOT-2` | 1.4.2 | Ensure /boot/grub2/user.cfg has restricted permissions (600) | No | Permissions already correct (600) |
| ✅ | `BOOT-3` | 1.4.3 | Ensure GRUB bootloader has password protection | No | GRUB password protection already configured |
| ✅ | `BOOT-3b` | 1.4.4 | Ensure ownership and permissions of /boot/* files | No | Boot file permissions OK |
| ✅ | `BOOT-4` | 1.3.1 | Ensure audit kernel parameters are set in /etc/default/grub | No | Audit kernel parameters already configured: crashkernel=1G-6... |
| ✅ | `BOOT-5` | 1.3.2 | Ensure GRUB kernel parameters are secure | No | Missing kernel parameters: audit=1 (Auditd enabled) To apply... |
| ✅ | `TCP-1` | 3.4.2.1 | Configure /etc/hosts.allow with explicit allow rules | No | /etc/hosts.allow already properly configured |
| ✅ | `TCP-2` | 3.4.2.2 | Configure /etc/hosts.deny with deny all rule | No | /etc/hosts.deny already properly configured |
| ✅ | `TCP-3` | 3.4.2.3 | Verify TCP Wrappers support in system services | No | TCP Wrappers (libwrap) not linked - normal for OL9/RHEL9; ho... |
| ✅ | `DNF-1` | 1.2.1 | Ensure gpgcheck is globally activated | No | /etc/dnf/dnf.conf already has GPG checks enabled |
| ✅ | `DNF-2` | 1.2.2 | Ensure gpgcheck is enabled for all repositories | No | All 4 repositories have gpgcheck enabled |
| ✅ | `DNF-3` | 1.2.3 | Ensure DNF automatic security updates are configured | No | Automatic updates disabled in configuration (set dnf.enable_... |
| ✅ | `MAIL-1` | 2.2.14 | Configure MTA for local-only mode | No | No MTA (Postfix/Sendmail) installed - acceptable for minimal... |
| ✅ | `MAIL-2` | 2.2.15 | Remove or disable unnecessary mail services | No | No unnecessary mail services found |

---

*Generated by CIS Oracle Linux 9 Hardening Tool v2.0*
