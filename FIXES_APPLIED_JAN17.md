# CIS Hardening Fixes Applied - January 17, 2026

Based on analysis of the Qualys scan report (Scheduled Report - OEL8-2026-01-17), the following modules were updated to address failing SERIOUS and CRITICAL controls.

## Summary of Changes

### 1. modules/coredumps.py
**Controls Addressed:** 29027, 29028 (SERIOUS)
- Fixed `Storage=none` and `ProcessSizeMax=0` to be written directly in `/etc/systemd/coredump.conf` under the `[Coredump]` section
- Qualys checks the main config file, not just drop-in directories
- Added regex-based parsing to ensure settings are properly placed within the section

### 2. modules/aide.py  
**Controls Addressed:** 10859, 17971, 17972, 17973 (CRITICAL)
- Updated AIDE cron script to use direct path `/usr/sbin/aide --check` format
- Qualys expects regex: `/usr/s?bin/aide(\.wrapper)?\s--(check|update)`
- Added crontab entry to `/etc/crontab` for direct detection
- Updated systemd timer/service to match expected format
- Timer now properly enabled with `systemctl enable` and `systemctl start`

### 3. modules/ssh.py
**Controls Addressed:** 26772, 26814, 26879-26882, 26995, 26996 (CRITICAL/SERIOUS)
- Changed default `LogLevel` from "INFO" to "VERBOSE" (CIS requirement)
- Removed `chacha20-poly1305@openssh.com` from ciphers (flagged by some scanners)
- Added default `AllowUsers` configuration for CIS access control compliance

### 4. cis_config.yaml
- Updated `ssh.log_level` to "VERBOSE"
- Added `ssh.allow_users: "root"` for basic access control
- Removed chacha20 cipher from default cipher list

### 5. modules/pam.py
**Controls Addressed:** 29160, 29161, 28818, 28819, 29449 (SERIOUS/CRITICAL)
- Added `retry = 3` to pwhistory.conf configuration
- Ensured proper remember, enforce_for_root settings

### 6. modules/auth.py
**Controls Addressed:** 29162, 29165, 5436 (CRITICAL/SERIOUS)
- Removed invalid `INACTIVE` from login.defs (it's set via `useradd -D`)
- Added `pass_min_days` (-m flag) to chage command for existing users
- Fixed password aging to include both max and min days

### 7. modules/boot.py
**Controls Addressed:** 28220, 28926, 25465, 25466 (CRITICAL/SERIOUS)
- Added comments clarifying GRUB2_PASSWORD format expected by Qualys
- Ensured password hash is written in correct format: `GRUB2_PASSWORD=grub.pbkdf2.sha512...`

### 8. modules/logging.py
**Controls Addressed:** 31026, 23777, 29444, 29445 (CRITICAL/SERIOUS)
- Fixed `$FileCreateMode 0640` to use space separator (not `=`)
- Qualys expects: `$FileCreateMode 0640` format
- Added proper regex replacement to ensure correct format
- Restarts rsyslog after changes

### 9. modules/cron.py
**Controls Addressed:** 5796, 7356, 7357 (CRITICAL)
- Changed logic to REMOVE cron.deny and at.deny when allow files exist
- CIS requires: when .allow files exist, .deny files should not exist
- Previous behavior was fixing permissions on deny files, now removes them

### 10. modules/mounts.py
**Controls Addressed:** 29042-29067 (SERIOUS)
- Updated /var/log/audit mount options to include all three: `nodev,nosuid,noexec`
- Previously only checked for `nodev`

## Controls Still Requiring Manual Attention

Some controls cannot be automatically remediated and require manual action:

1. **Separate Partitions (29062, 29066, 29067):**
   - `/var/log` and `/var/log/audit` must be on separate partitions
   - Requires disk repartitioning during installation or migration

2. **SSH Access Controls (26879-26882):**
   - `AllowUsers`, `AllowGroups`, `DenyUsers`, `DenyGroups` must be customized per environment
   - Default set to `AllowUsers: root` - customize as needed

3. **User Account Inactivity (5436):**
   - Requires running `chage -I 30 <username>` on existing accounts
   - Script handles this automatically when run

## Verification Steps

After running the hardening script, verify fixes with:

```bash
# Coredumps
grep -E "^(Storage|ProcessSizeMax)" /etc/systemd/coredump.conf

# AIDE
grep aide /etc/crontab
systemctl status aidecheck.timer

# SSH
grep -E "^LogLevel|^AllowUsers|^Ciphers" /etc/ssh/sshd_config.d/99-cis-hardening.conf

# rsyslog
grep FileCreateMode /etc/rsyslog.conf

# cron/at deny files
ls -la /etc/cron.deny /etc/at.deny 2>/dev/null || echo "deny files removed (good)"

# GRUB password
cat /boot/grub2/user.cfg | head -1
```

## Running the Hardening Script

```bash
# Dry run first
python3 cis_apply_enhanced.py --dry-run

# Apply changes
python3 cis_apply_enhanced.py --apply
```
