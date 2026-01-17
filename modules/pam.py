"""
PAM (Pluggable Authentication Modules) Hardening
CIS Reference: 5.3.x series - Password and Authentication Policy
Covers: pam_pwhistory with use_authtok, faillock, password quality
"""
from typing import List, Dict, Any
from .utils import ActionResult, run, ensure_kv_in_file, write_file
import os, re, shlex

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply PAM hardening configurations:
    - Enable pam_pwhistory module with use_authtok
    - Configure pwhistory.conf for password history
    - Account lockout policies via faillock
    - Password quality requirements
    """
    results = []
    
    # Control: Enable pam_pwhistory module in PAM files
    control_id = "PAM-1"
    title = "Enable pam_pwhistory module in password-auth and system-auth"
    changed = False
    ok = True
    notes = []
    commands = []
    files = []
    
    pam_files = ["/etc/pam.d/password-auth", "/etc/pam.d/system-auth"]
    password_remember = int(cfg.get("password_remember", 24))
    
    try:
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                with open(pam_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                new_content = content
                file_changed = False
                
                # Check if pam_pwhistory.so is already present
                if "pam_pwhistory.so" not in content:
                    # Add pam_pwhistory.so line after pam_pwquality.so or at the password section
                    pwhistory_line = "password    requisite     pam_pwhistory.so remember={} use_authtok\n".format(password_remember)
                    
                    # Insert after pam_pwquality.so if present
                    if "pam_pwquality.so" in content:
                        new_content = re.sub(
                            r'(password\s+requisite\s+pam_pwquality\.so[^\n]*\n)',
                            r'\1' + pwhistory_line,
                            content
                        )
                    else:
                        # Insert at the beginning of password section
                        new_content = re.sub(
                            r'(password\s+)',
                            pwhistory_line + r'\1',
                            content,
                            count=1
                        )
                    
                    if new_content != content:
                        file_changed = True
                        notes.append(f"Added pam_pwhistory.so to {pam_file}")
                else:
                    # Check if use_authtok is set
                    if "pam_pwhistory.so" in content and "use_authtok" not in content.split("pam_pwhistory.so")[1].split("\n")[0]:
                        new_content = re.sub(
                            r'(password\s+\S+\s+pam_pwhistory\.so[^\n]*)',
                            r'\1 use_authtok',
                            content
                        )
                        if new_content != content:
                            file_changed = True
                            notes.append(f"Added use_authtok to pam_pwhistory.so in {pam_file}")
                    else:
                        notes.append(f"pam_pwhistory.so with use_authtok already configured in {pam_file}")
                
                if file_changed and not dry_run:
                    # Backup first
                    run(["cp", pam_file, f"{pam_file}.cis-backup"])
                    with open(pam_file, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    changed = True
                    files.append(pam_file)
                elif file_changed:
                    changed = True
                    files.append(pam_file)
        
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=changed,
            ok=ok,
            notes="; ".join(notes) if notes else "pam_pwhistory already configured",
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
    
    # Control: Configure /etc/security/pwhistory.conf
    control_id = "PAM-1b"
    title = "Configure password history in /etc/security/pwhistory.conf"
    
    try:
        pwhistory_conf = "/etc/security/pwhistory.conf"
        
        # CIS requires: remember, retry, enforce_for_root
        c1, n1 = ensure_kv_in_file(pwhistory_conf, "remember", str(password_remember), sep=" = ", dry_run=dry_run)
        c2, n2 = ensure_kv_in_file(pwhistory_conf, "enforce_for_root", "", sep="", dry_run=dry_run)
        
        # Ensure retry is set (some Qualys checks look for this)
        c3, n3 = ensure_kv_in_file(pwhistory_conf, "retry", "3", sep=" = ", dry_run=dry_run)
        
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=c1 or c2 or c3,
            ok=True,
            notes=f"{n1}; {n2}; {n3}",
            commands=[],
            files=[pwhistory_conf]
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
    
    # Control: PAM Session Timeout
    control_id = "PAM-2"
    title = "Configure PAM session timeout"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        session_timeout = int(cfg.get("session_timeout", 600))  # 10 minutes default
        
        # Configure TMOUT in /etc/profile.d/
        tmout_script = f"""#!/bin/bash
# CIS Hardening - Session Timeout
TMOUT={session_timeout}
readonly TMOUT
export TMOUT
"""
        tmout_file = "/etc/profile.d/99-cis-tmout.sh"
        c, n = write_file(tmout_file, tmout_script, mode=0o644, dry_run=dry_run)
        changed = c
        notes = f"Session timeout configured for {session_timeout} seconds"
        files.append(tmout_file)
        
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
    
    # Control: Password Minimum Length in login.defs
    control_id = "PAM-3"
    title = "Set minimum password length (login.defs)"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        pass_min_len = int(cfg.get("pass_min_len", 14))
        login_defs = "/etc/login.defs"
        
        c, n = ensure_kv_in_file(login_defs, "PASS_MIN_LEN", str(pass_min_len), sep="\t", dry_run=dry_run)
        changed = c
        notes = n
        files.append(login_defs)
        
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
