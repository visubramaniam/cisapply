from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, ensure_service_enabled, write_file, run, ensure_kv_in_file
import shlex

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

# Authentication files
-w /etc/pam.d/ -p wa -k access
-w /etc/pam.conf -p wa -k access
-w /etc/nsswitch.conf -p wa -k access

# Login/session events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Session initiation
-w /var/run/faillock/ -p wa -k logins

# System administration
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
-a always,exit -F arch=b32 -S clock_adjtime,setfsgid32,setfsgid,setfsuid32,setfsuid,setgid32,setgid,setgroups32,setgroups,sethostname,setitimer,setpgid,setpriority,setregid32,setregid,setresgid32,setresgid,setresuid32,setresuid,setreuid32,setreuid,setrlimit,setsid,setsockopt,settimeofday,setuid32,setuid -F auid>=1000 -F auid!=4294967295 -k time-change

# Hostname changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale

# SELinux changes
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=4294967295 -F perm=x -F auid!=-1 -k MAC-policy
-a always,exit -F path=/usr/bin/setfacl -F auid>=1000 -F auid!=4294967295 -F perm=x -F auid!=-1 -k MAC-policy
-a always,exit -F path=/usr/bin/chacl -F auid>=1000 -F auid!=4294967295 -F perm=x -F auid!=-1 -k MAC-policy
-a always,exit -F path=/usr/sbin/usermod -F auid>=1000 -F auid!=4294967295 -F perm=x -F auid!=-1 -k MAC-policy

# Mount operations
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount,umount,umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

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

# File creation and access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# File truncation
-a always,exit -F arch=b64 -S truncate,ftruncate -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S truncate,ftruncate -F auid>=1000 -F auid!=4294967295 -k delete

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F path=/usr/bin/kmod -F auid>=1000 -F auid!=4294967295 -F perm=x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Privileged commands
-a always,exit -F path=/usr/sbin/usermod -F auid>=1000 -F auid!=4294967295 -k privileged-usermod
-a always,exit -F path=/usr/sbin/userdel -F auid>=1000 -F auid!=4294967295 -k privileged-userdel
-a always,exit -F path=/usr/sbin/useradd -F auid>=1000 -F auid!=4294967295 -k privileged-useradd
-a always,exit -F path=/usr/sbin/passwd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# Execution logging
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Make configuration immutable
-e 2
"""

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    ensure_pkg(["audit","audit-libs","aide"], dry_run, results, "AUD-1", "Install auditd and aide packages")
    ensure_service_enabled("auditd", dry_run, results, "AUD-2", "Enable auditd service")
    
    # Configure auditd settings
    aconf="/etc/audit/auditd.conf"
    c1,n1=ensure_kv_in_file(aconf,"log_file", "/var/log/audit/audit.log", sep=" = ", dry_run=dry_run)
    c2,n2=ensure_kv_in_file(aconf,"log_group", "adm", sep=" = ", dry_run=dry_run)
    c3,n3=ensure_kv_in_file(aconf,"log_format", "RAW", sep=" = ", dry_run=dry_run)
    results.append(ActionResult("AUD-2a","Configure auditd settings", c1 or c2 or c3, True, 
                                notes="; ".join([n1,n2,n3]), files=[aconf]))
    
    # Write comprehensive audit rules
    changed, note = write_file("/etc/audit/rules.d/99-cis-hardening.rules", RULES, mode=0o640, dry_run=dry_run)
    
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
