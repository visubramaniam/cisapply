from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, ensure_service_enabled, ensure_kv_in_file, run, ensure_perm
import shlex, os, glob

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    
    # Journald hardening
    c1,n1=ensure_kv_in_file("/etc/systemd/journald.conf","Storage","persistent",sep="=",dry_run=dry_run)
    c2,n2=ensure_kv_in_file("/etc/systemd/journald.conf","Compress","yes",sep="=",dry_run=dry_run)
    c3,n3=ensure_kv_in_file("/etc/systemd/journald.conf","SystemMaxUse","1G",sep="=",dry_run=dry_run)
    c4,n4=ensure_kv_in_file("/etc/systemd/journald.conf","ForwardToSyslog","yes",sep="=",dry_run=dry_run)
    results.append(ActionResult("LOG-1","Harden journald persistence/limits/forwarding", c1 or c2 or c3 or c4, True, 
                                notes="; ".join([n1,n2,n3,n4]), files=["/etc/systemd/journald.conf"]))
    
    # Install and enable rsyslog
    ensure_pkg(["rsyslog"], dry_run, results, "LOG-2", "Install rsyslog")
    
    # Configure rsyslog - set $FileCreateMode
    c5,n5=ensure_kv_in_file("/etc/rsyslog.conf","$FileCreateMode","0640",sep=" ",dry_run=dry_run)
    results.append(ActionResult("LOG-3","Configure rsyslog $FileCreateMode", c5, True, notes=n5, files=["/etc/rsyslog.conf"]))
    
    # Enable rsyslog and systemd-journald services
    ensure_service_enabled("rsyslog", dry_run, results, "LOG-4", "Enable rsyslog service")
    ensure_service_enabled("systemd-journald", dry_run, results, "LOG-5", "Enable systemd-journald service")
    
    # Fix log file permissions and ownership
    log_perms = [
        ("/var/log/wtmp", 0o664, 0, 0),
        ("/var/log/btmp", 0o660, 0, 0),
        ("/var/log/lastlog", 0o644, 0, 0),
    ]
    for log_file, mode, uid, gid in log_perms:
        if os.path.exists(log_file):
            c,n = ensure_perm(log_file, mode, uid, gid, dry_run)
            results.append(ActionResult(f"LOG-6-{log_file}",f"Set permissions on {log_file}", c, True, notes=n, files=[log_file]))
    
    # Fix /var/log/secure, messages, and other system log permissions
    system_logs = ["/var/log/messages", "/var/log/secure"]
    for log_file in system_logs:
        if os.path.exists(log_file):
            c,n = ensure_perm(log_file, 0o640, 0, 0, dry_run)
            results.append(ActionResult(f"LOG-7-{log_file}",f"Set permissions on {log_file}", c, True, notes=n, files=[log_file]))
    
    # Fix journal permissions
    journal_files = glob.glob("/var/log/journal/*/system.journal*") + glob.glob("/var/log/journal/*/*")
    for jf in journal_files:
        if os.path.exists(jf) and os.path.isfile(jf):
            c,n = ensure_perm(jf, 0o640, 0, 0, dry_run)
            results.append(ActionResult(f"LOG-8-{jf}",f"Set permissions on {jf}", c, True, notes=n, files=[jf]))
    
    # Disable systemd-journal-upload and journal-remote if present
    ensure_pkg(["systemd-journal-remote"], dry_run, results, "LOG-9", "Install systemd-journal-remote")
    ensure_service_enabled("systemd-journal-remote", dry_run, results, "LOG-10", "Disable systemd-journal-remote", state="disable")
    ensure_service_enabled("systemd-journal-upload", dry_run, results, "LOG-11", "Disable systemd-journal-upload", state="disable")
    
    return results
