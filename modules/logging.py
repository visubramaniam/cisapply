from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, ensure_service_enabled, ensure_kv_in_file, run, ensure_perm
import shlex, os, glob, re

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
    
    # Configure rsyslog - set $FileCreateMode 0640 (space after mode)
    # Qualys expects: $FileCreateMode 0640 (with space, not =)
    rsyslog_conf = "/etc/rsyslog.conf"
    control_id = "LOG-3"
    title = "Configure rsyslog $FileCreateMode"
    changed = False
    notes = ""
    
    try:
        if os.path.exists(rsyslog_conf):
            with open(rsyslog_conf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            new_content = content
            modified = False
            
            # Check if $FileCreateMode is already set correctly
            if not re.search(r'^\$FileCreateMode\s+0640', content, re.MULTILINE):
                # Remove any existing $FileCreateMode line
                new_content = re.sub(r'^\$FileCreateMode.*$\n?', '', new_content, flags=re.MULTILINE)
                # Add the correct setting near the top (after any module loads)
                if '$ModLoad' in new_content:
                    new_content = re.sub(
                        r'(\$ModLoad[^\n]*\n)',
                        r'\1$FileCreateMode 0640\n',
                        new_content,
                        count=1
                    )
                else:
                    new_content = "$FileCreateMode 0640\n" + new_content
                modified = True
            
            if modified and not dry_run:
                with open(rsyslog_conf, "w", encoding="utf-8") as f:
                    f.write(new_content)
                changed = True
                notes = "Set $FileCreateMode 0640 in rsyslog.conf"
                run(["systemctl", "restart", "rsyslog"])
            elif modified:
                notes = "DRY-RUN: Would set $FileCreateMode 0640"
            else:
                notes = "$FileCreateMode 0640 already configured"
        else:
            notes = "rsyslog.conf not found"
    except Exception as e:
        notes = f"Error: {str(e)}"
    
    results.append(ActionResult(control_id, title, changed, True, notes=notes, files=[rsyslog_conf]))
    
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
    
    # Control: Fix /var/log/sssd permissions if exists
    control_id = "LOG-9"
    title = "Set permissions on /var/log/sssd directory"
    
    sssd_log_dir = "/var/log/sssd"
    if os.path.exists(sssd_log_dir):
        c, n = ensure_perm(sssd_log_dir, 0o750, 0, 0, dry_run)
        results.append(ActionResult(control_id, title, c, True, notes=n, files=[sssd_log_dir]))
    else:
        results.append(ActionResult(control_id, title, False, True, notes="/var/log/sssd does not exist"))
    
    # Control: Fix permissions on all log files
    control_id = "LOG-10"
    title = "Ensure permissions on all logfiles"
    changed = False
    notes = []
    
    # Get all log files excluding special ones
    excluded_patterns = ['lastlog', 'wtmp', 'btmp', 'journal', 'gdm', 'sssd']
    
    for log_file in glob.glob("/var/log/*"):
        if os.path.isfile(log_file):
            # Skip excluded files
            if any(excl in log_file for excl in excluded_patterns):
                continue
            
            st = os.stat(log_file)
            mode = st.st_mode & 0o777
            
            # Log files should not be world-readable
            if mode & 0o004:  # World readable
                if not dry_run:
                    os.chmod(log_file, mode & ~0o007)  # Remove world permissions
                    changed = True
                    notes.append(f"Fixed {log_file}")
    
    results.append(ActionResult(control_id, title, changed, True, 
                                notes="; ".join(notes) if notes else "Log file permissions OK"))
    
    # Control: Configure systemd-journal-upload
    control_id = "LOG-11"
    title = "Ensure systemd-journal-upload is configured"
    
    # Check if journal-upload service should be enabled
    journal_upload_enabled = cfg.get("journal_upload_enabled", True)
    
    if journal_upload_enabled:
        ensure_pkg(["systemd-journal-remote"], dry_run, results, "LOG-11a", "Install systemd-journal-remote")
        
        # Enable journal-upload service
        if not dry_run:
            run(["systemctl", "enable", "systemd-journal-upload"])
            # Don't start it if no remote server is configured
            journal_remote_url = cfg.get("journal_remote_url", "")
            if journal_remote_url:
                run(["systemctl", "start", "systemd-journal-upload"])
                results.append(ActionResult(control_id, title, True, True, 
                                            notes=f"systemd-journal-upload enabled and started (remote: {journal_remote_url})"))
            else:
                results.append(ActionResult(control_id, title, True, True, 
                                            notes="systemd-journal-upload enabled (configure journal_remote_url to start)"))
        else:
            results.append(ActionResult(control_id, title, True, True,
                                        notes="DRY-RUN: Would enable systemd-journal-upload"))
    else:
        # Disable journal-upload if not needed
        if not dry_run:
            run(["systemctl", "stop", "systemd-journal-upload"])
            run(["systemctl", "disable", "systemd-journal-upload"])
        results.append(ActionResult(control_id, title, True, True, 
                                    notes="systemd-journal-upload disabled (set journal_upload_enabled=true to enable)"))
    
    return results
