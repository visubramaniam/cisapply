from typing import List, Dict, Any
from .utils import ActionResult, ensure_kv_in_file, run, ensure_pkg
import shlex, os, re

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    
    # Ensure authselect and pam packages
    ensure_pkg(["authselect","libpwquality","pam"], dry_run, results, "AUTH-0", "Install authentication packages")
    
    # Configure password quality (pwquality.conf)
    pwq="/etc/security/pwquality.conf"
    pwq_dir="/etc/security/pwquality.conf.d"
    changes=[]
    changes.append(ensure_kv_in_file(pwq,"minlen", str(cfg.get("pwquality_minlen",14)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"minclass", str(cfg.get("pwquality_minclass",4)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"maxrepeat", str(cfg.get("pwquality_maxrepeat",3)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"maxsequence", str(cfg.get("pwquality_maxsequence",3)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"difok", str(cfg.get("pwquality_difok",3)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"enforce_for_root", "", sep="", dry_run=dry_run))
    for k in ["dcredit","ucredit","lcredit","ocredit"]:
        changes.append(ensure_kv_in_file(pwq,k, str(cfg.get(f"pwquality_{k}",-1)), sep=" = ", dry_run=dry_run))
    results.append(ActionResult("AUTH-1","Configure password quality (pwquality.conf)", any(c for c,_ in changes), True,
                                notes="; ".join(n for _,n in changes), files=[pwq]))

    # Configure password history
    pwh="/etc/security/pwhistory.conf"
    ph_changes=[]
    ph_changes.append(ensure_kv_in_file(pwh,"remember", str(cfg.get("pwhistory_remember",24)), sep=" = ", dry_run=dry_run))
    ph_changes.append(ensure_kv_in_file(pwh,"enforce_for_root", "", sep="", dry_run=dry_run))
    results.append(ActionResult("AUTH-1b","Configure password history (pwhistory.conf)", any(c for c,_ in ph_changes), True,
                                notes="; ".join(n for _,n in ph_changes), files=[pwh]))

    # Configure login.defs for password aging
    ld="/etc/login.defs"
    ch=[]
    ch.append(ensure_kv_in_file(ld,"PASS_MAX_DAYS", str(cfg.get("pass_max_days",365)), sep="\t", dry_run=dry_run))
    ch.append(ensure_kv_in_file(ld,"PASS_MIN_DAYS", str(cfg.get("pass_min_days",1)), sep="\t", dry_run=dry_run))
    ch.append(ensure_kv_in_file(ld,"PASS_WARN_AGE", str(cfg.get("pass_warn_age",14)), sep="\t", dry_run=dry_run))
    # Note: INACTIVE is set via useradd -D, not login.defs (it's not a valid login.defs parameter)
    results.append(ActionResult("AUTH-2","Configure password aging (login.defs)", any(c for c,_ in ch), True,
                                notes="; ".join(n for _,n in ch), files=[ld]))

    # Set default inactive days for new users using useradd
    inactive_days = int(cfg.get("inactive_days", 30))
    cmd_inactive = ["useradd", "-D", "-f", str(inactive_days)]
    if dry_run:
        results.append(ActionResult("AUTH-2a", "Set default inactive period for new users", True, True,
                                    notes=f"DRY-RUN: would run {shlex.join(cmd_inactive)}",
                                    commands=[shlex.join(cmd_inactive)]))
    else:
        cp = run(cmd_inactive)
        results.append(ActionResult("AUTH-2a", "Set default inactive period for new users", True, cp.returncode == 0,
                                    notes=(cp.stdout + cp.stderr).strip() or f"Set INACTIVE to {inactive_days} days",
                                    commands=[shlex.join(cmd_inactive)]))

    # Fix existing users' password aging if needed
    control_id = "AUTH-2b"
    title = "Ensure password aging on existing user accounts"
    pass_max_days = int(cfg.get("pass_max_days", 365))
    pass_min_days = int(cfg.get("pass_min_days", 1))
    
    try:
        # Get list of users with UID >= 1000 that have passwords
        cmd_getusers = ["bash", "-c", "awk -F: '($3 >= 1000 && $2 != \"*\" && $2 != \"!\" && $2 != \"!!\") {print $1}' /etc/shadow"]
        cp_users = run(cmd_getusers)
        users = cp_users.stdout.strip().split("\n") if cp_users.stdout.strip() else []
        
        modified_users = []
        for user in users:
            if user:
                # Set max days, min days, and inactive days
                cmd_chage = ["chage", "-M", str(pass_max_days), "-m", str(pass_min_days), "-I", str(inactive_days), user]
                if not dry_run:
                    run(cmd_chage)
                    modified_users.append(user)
        
        if modified_users:
            results.append(ActionResult(control_id, title, True, True,
                                        notes=f"Applied password aging to users: {', '.join(modified_users)}"))
        elif users:
            results.append(ActionResult(control_id, title, True, True,
                                        notes=f"DRY-RUN: Would apply password aging to: {', '.join(users)}"))
        else:
            results.append(ActionResult(control_id, title, False, True,
                                        notes="No applicable user accounts found"))
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False, notes=f"Error: {str(e)}"))

    # Control: Ensure password change date is in the past (not future)
    # Qualys control 12807
    control_id = "AUTH-2c"
    title = "Ensure last password change date is in the past"
    
    try:
        # Check for accounts with future password change dates
        # This can happen if system clock was wrong when password was set
        import time
        current_days = int(time.time() / 86400)  # Days since epoch
        
        cmd_shadow = ["bash", "-c", "awk -F: '{print $1\":\"$3}' /etc/shadow"]
        cp_shadow = run(cmd_shadow)
        
        fixed_users = []
        if cp_shadow.stdout:
            for line in cp_shadow.stdout.strip().split("\n"):
                if ":" in line:
                    parts = line.split(":")
                    user = parts[0]
                    last_change = parts[1] if len(parts) > 1 else ""
                    
                    if last_change and last_change.isdigit():
                        last_change_days = int(last_change)
                        if last_change_days > current_days:
                            # Last change is in the future - fix it
                            if not dry_run:
                                # Force password change today
                                run(["chage", "-d", "0", user])  # Expire password
                                fixed_users.append(user)
        
        if fixed_users:
            results.append(ActionResult(control_id, title, True, True,
                                        notes=f"Fixed future password change dates for: {', '.join(fixed_users)}"))
        else:
            results.append(ActionResult(control_id, title, False, True,
                                        notes="No accounts with future password change dates found"))
    except Exception as e:
        results.append(ActionResult(control_id, title, False, True, notes=f"Error: {str(e)}"))

    # Set default umask - CIS 5.4.4
    # Qualys control 29216 expects umask in /etc/bashrc or /etc/profile directly
    umask_val=str(cfg.get("umask","027"))
    
    # Configure umask in /etc/bashrc, /etc/profile, and login.defs
    umask_files_updated = []
    umask_changed = False
    
    for umask_file in ["/etc/bashrc", "/etc/profile"]:
        try:
            if os.path.exists(umask_file):
                with open(umask_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # Remove any existing umask settings (except commented ones)
                new_content = re.sub(r'^(\s*)umask\s+\d+\s*$', '', content, flags=re.MULTILINE)
                
                # Add umask at the end
                if not new_content.rstrip().endswith(f"umask {umask_val}"):
                    new_content = new_content.rstrip() + f"\n\n# CIS Default umask\numask {umask_val}\n"
                    
                    if not dry_run:
                        with open(umask_file, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        umask_files_updated.append(umask_file)
                        umask_changed = True
        except Exception:
            pass
    
    # Also set UMASK in /etc/login.defs
    ld = "/etc/login.defs"
    try:
        c, n = ensure_kv_in_file(ld, "UMASK", umask_val, sep="\t\t", dry_run=dry_run)
        if c:
            umask_changed = True
            umask_files_updated.append(ld)
    except Exception:
        pass
    
    # Also create profile.d script for compatibility
    um="/etc/profile.d/99-cis-umask.sh"
    if not dry_run:
        try:
            with open(um, "w", encoding="utf-8") as f:
                f.write(f"# CIS umask setting\numask {umask_val}\n")
            os.chmod(um, 0o644)
            umask_files_updated.append(um)
        except Exception:
            pass
    
    results.append(ActionResult("AUTH-3", "Set default umask", umask_changed, True, 
                               notes=f"Set umask {umask_val} in {', '.join(umask_files_updated)}" if umask_files_updated else f"Would set umask {umask_val}",
                               files=umask_files_updated))

    # Set session timeout (TMOUT) - CIS 5.5.4
    # Qualys expects TMOUT to be set in /etc/bashrc or /etc/profile directly
    # profile.d scripts may not be detected by all scanners
    tmout_value = str(cfg.get("tmout", 900))
    
    # Configure TMOUT in both /etc/bashrc and /etc/profile for maximum compatibility
    tmout_content = f"""
# CIS Oracle Linux 9 - Session Timeout (5.5.4)
TMOUT={tmout_value}
readonly TMOUT
export TMOUT
"""
    
    changed_tmout = False
    tmout_files_updated = []
    
    for tf in ["/etc/bashrc", "/etc/profile"]:
        try:
            if os.path.exists(tf):
                with open(tf, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # Remove any existing TMOUT configuration
                new_content = re.sub(r'^[^#]*\bTMOUT\b.*$\n?', '', content, flags=re.MULTILINE)
                
                # Also remove any block comments with CIS Session Timeout
                new_content = re.sub(r'\n*# CIS.*Session Timeout.*\n(TMOUT=.*\n)?(readonly TMOUT.*\n)?(export TMOUT.*\n)?', '\n', new_content, flags=re.IGNORECASE)
                
                # Append TMOUT configuration at the end
                new_content = new_content.rstrip() + "\n" + tmout_content
                
                if not dry_run:
                    with open(tf, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    tmout_files_updated.append(tf)
                    changed_tmout = True
                else:
                    changed_tmout = True
        except Exception as e:
            pass
    
    # Also create profile.d script for shell compatibility
    tmout_script = "/etc/profile.d/cis-tmout.sh"
    tmout_script_content = f"""#!/bin/bash
# CIS Oracle Linux 9 - Session Timeout (5.5.4)
# Redundant setting for shell compatibility
if [[ -z "$TMOUT" ]]; then
    TMOUT={tmout_value}
    readonly TMOUT
    export TMOUT
fi
"""
    
    # Write the profile.d script
    if dry_run:
        results.append(ActionResult("AUTH-3a", "Set session timeout (TMOUT in bashrc/profile)", changed_tmout, True, 
                                   notes=f"DRY-RUN: would set TMOUT={tmout_value} in /etc/bashrc, /etc/profile, and {tmout_script}", 
                                   files=["/etc/bashrc", "/etc/profile", tmout_script]))
    else:
        try:
            with open(tmout_script, "w", encoding="utf-8") as f:
                f.write(tmout_script_content)
            os.chmod(tmout_script, 0o644)
            tmout_files_updated.append(tmout_script)
            results.append(ActionResult("AUTH-3a", "Set session timeout (TMOUT in bashrc/profile)", True, True, 
                                       notes=f"Set TMOUT={tmout_value} in {', '.join(tmout_files_updated)}", 
                                       files=tmout_files_updated))
        except Exception as e:
            results.append(ActionResult("AUTH-3a", "Set session timeout (TMOUT in bashrc/profile)", changed_tmout, True, 
                                       notes=f"Set TMOUT in bashrc/profile; profile.d error: {str(e)}", 
                                       files=["/etc/bashrc", "/etc/profile"]))

    # Configure faillock
    deny=int(cfg.get("lockout_deny",5))
    fail_interval=int(cfg.get("lockout_fail_interval",900))
    unlock_time=int(cfg.get("lockout_unlock_time",900))
    root_unlock_time=int(cfg.get("root_unlock_time",60))
    
    fl="/etc/security/faillock.conf"
    c1,n1=ensure_kv_in_file(fl,"deny", str(deny), sep=" = ", dry_run=dry_run)
    c2,n2=ensure_kv_in_file(fl,"fail_interval", str(fail_interval), sep=" = ", dry_run=dry_run)
    c3,n3=ensure_kv_in_file(fl,"unlock_time", str(unlock_time), sep=" = ", dry_run=dry_run)
    c4,n4=ensure_kv_in_file(fl,"root_unlock_time", str(root_unlock_time), sep=" = ", dry_run=dry_run)
    
    # Remove nullok from pam files
    pam_files = ["/etc/pam.d/password-auth", "/etc/pam.d/system-auth"]
    for pf in pam_files:
        if os.path.exists(pf):
            with open(pf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            new_content = re.sub(r'\bnullok\b', '', content)
            if new_content != content and not dry_run:
                with open(pf, "w", encoding="utf-8") as f:
                    f.write(new_content)
                results.append(ActionResult(f"AUTH-3b-{pf}", f"Remove nullok from {pf}", True, True, files=[pf]))
            elif new_content != content:
                results.append(ActionResult(f"AUTH-3b-{pf}", f"Remove nullok from {pf}", True, True, notes="DRY-RUN: would update", files=[pf]))
    
    cmd2=["bash","-lc","authselect current >/dev/null 2>&1 && authselect enable-feature with-faillock && authselect apply-changes || true"]
    if dry_run:
        results.append(ActionResult("AUTH-4","Enable/configure account lockout (faillock)", c1 or c2 or c3 or c4, True,
                                    notes="DRY-RUN: would run "+shlex.join(cmd2)+"; "+ "; ".join([n1,n2,n3,n4]),
                                    commands=[shlex.join(cmd2)], files=[fl]))
    else:
        cp=run(cmd2)
        results.append(ActionResult("AUTH-4","Enable/configure account lockout (faillock)", True, cp.returncode==0,
                                    notes=(cp.stdout+cp.stderr).strip()+"; "+ "; ".join([n1,n2,n3,n4]),
                                    commands=[shlex.join(cmd2)], files=[fl]))
    
    return results
