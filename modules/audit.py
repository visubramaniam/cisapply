from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, ensure_service_enabled, write_file, run, ensure_kv_in_file
import shlex, subprocess

RULES = """## CIS baseline audit rules - comprehensive
# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Identity and authentication
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudoers
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Sudo log file
-w /var/log/sudo.log -p wa -k actions

# Authentication files
-w /etc/pam.d/ -p wa -k access
-w /etc/pam.conf -p wa -k access
-w /etc/nsswitch.conf -p wa -k access

# Login/session events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Session initiation
-w /var/run/faillock/ -p wa -k logins

# System administration / network configuration
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/NetworkManager/ -p wa -k system-locale

# Time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S clock_adjtime -F auid>=1000 -F auid!=4294967295 -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Hostname changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale

# SELinux changes
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k usermod

# Mount operations
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount,umount,umount2 -F auid>=1000 -F auid!=4294967295 -k mounts

# File access attempts (unsuccessful)
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# File deletion/modification
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete

# File permission and attribute changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=4294967295 -k modules

# Privileged commands (will be dynamically generated)
# -a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=4294967295 -k privileged

# Execution logging
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k actions
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k actions
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k actions
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k actions

# Make configuration immutable
-e 2
"""

def _get_privileged_commands():
    """Find all setuid/setgid binaries for privileged command auditing"""
    try:
        result = subprocess.run(
            ["find", "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f"],
            capture_output=True, text=True, timeout=60
        )
        binaries = [b.strip() for b in result.stdout.strip().split('\n') if b.strip()]
        rules = []
        for binary in binaries:
            rules.append(f"-a always,exit -F path={binary} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged")
        return "\n".join(rules)
    except Exception:
        return ""

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    ensure_pkg(["audit","audit-libs"], dry_run, results, "AUD-1", "Install auditd packages")
    ensure_service_enabled("auditd", dry_run, results, "AUD-2", "Enable auditd service")
    
    # Configure auditd settings
    aconf="/etc/audit/auditd.conf"
    c1,n1=ensure_kv_in_file(aconf,"log_file", "/var/log/audit/audit.log", sep=" = ", dry_run=dry_run)
    c2,n2=ensure_kv_in_file(aconf,"log_group", "adm", sep=" = ", dry_run=dry_run)
    c3,n3=ensure_kv_in_file(aconf,"log_format", "ENRICHED", sep=" = ", dry_run=dry_run)
    c4,n4=ensure_kv_in_file(aconf,"max_log_file_action", "keep_logs", sep=" = ", dry_run=dry_run)
    c5,n5=ensure_kv_in_file(aconf,"space_left_action", "email", sep=" = ", dry_run=dry_run)
    c6,n6=ensure_kv_in_file(aconf,"admin_space_left_action", "halt", sep=" = ", dry_run=dry_run)
    c7,n7=ensure_kv_in_file(aconf,"disk_full_action", "halt", sep=" = ", dry_run=dry_run)
    c8,n8=ensure_kv_in_file(aconf,"disk_error_action", "halt", sep=" = ", dry_run=dry_run)
    
    results.append(ActionResult("AUD-2a","Configure auditd.conf settings", 
                                c1 or c2 or c3 or c4 or c5 or c6 or c7 or c8, True, 
                                notes="; ".join([n1,n2,n3,n4,n5,n6,n7,n8]), files=[aconf]))
    
    # Build full rules with privileged commands
    full_rules = RULES
    if not dry_run:
        priv_rules = _get_privileged_commands()
        if priv_rules:
            # Insert before the immutable line
            full_rules = RULES.replace("# Make configuration immutable", 
                                       f"# Privileged commands\n{priv_rules}\n\n# Make configuration immutable")
    
    # Write comprehensive audit rules
    changed, note = write_file("/etc/audit/rules.d/99-cis-hardening.rules", full_rules, mode=0o640, dry_run=dry_run)
    
    # Load audit rules
    cmd=["augenrules","--load"]
    if dry_run:
        results.append(ActionResult("AUD-3","Install CIS audit rules and load", changed, True,
                                    notes=note+"\nDRY-RUN: would run "+shlex.join(cmd),
                                    commands=[shlex.join(cmd)], files=["/etc/audit/rules.d/99-cis-hardening.rules"]))
    else:
        cp=run(cmd)
        ok=(cp.returncode==0)
        results.append(ActionResult("AUD-3","Install CIS audit rules and load", changed, ok,
                                    notes=note+"\n"+(cp.stdout+cp.stderr).strip(),
                                    commands=[shlex.join(cmd)], files=["/etc/audit/rules.d/99-cis-hardening.rules"]))
    
    return results
