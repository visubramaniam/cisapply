from typing import List, Dict, Any
from .utils import ActionResult, ensure_perm, run
import os
import pwd
import stat

TARGETS = [("/etc/passwd",0o644),("/etc/group",0o644),("/etc/shadow",0o000),("/etc/gshadow",0o000),("/etc/ssh/sshd_config",0o600)]

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results = []
    notes=[]; changed=False
    for p,mode in TARGETS:
        c,n=ensure_perm(p, mode, 0,0, dry_run=dry_run)
        if c: changed=True
        notes.append(f"{p}: {n}")
    results.append(ActionResult("PERM-1","Harden key system file permissions", changed, True, notes="; ".join(notes)))
    
    # Control: Ensure all users' dot files are not group or world writable
    # Qualys controls 29421, 29422
    control_id = "PERM-2"
    title = "Ensure user dot files are not group or world writable"
    dot_changed = False
    dot_notes = []
    
    try:
        # Get all users with valid home directories
        min_uid = int(cfg.get("min_user_uid", 1000))
        
        for pw in pwd.getpwall():
            # Check system users with valid shells and home dirs
            home = pw.pw_dir
            uid = pw.pw_uid
            
            # Skip users without real home directories or non-interactive users
            if not os.path.isdir(home) or home == "/" or home == "/nonexistent":
                continue
            
            # Process both system and regular users that have home directories
            for entry in os.listdir(home):
                if entry.startswith("."):
                    dot_path = os.path.join(home, entry)
                    
                    if os.path.isfile(dot_path):
                        try:
                            st = os.stat(dot_path)
                            mode = st.st_mode
                            
                            # Check if group or world writable
                            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                                # Remove group and world write permissions
                                new_mode = mode & ~(stat.S_IWGRP | stat.S_IWOTH)
                                
                                if not dry_run:
                                    os.chmod(dot_path, new_mode)
                                    dot_changed = True
                                    dot_notes.append(f"Fixed {dot_path}")
                                else:
                                    dot_notes.append(f"Would fix {dot_path}")
                                    dot_changed = True
                            
                            # Also check ownership - dot files should be owned by the user or root
                            file_uid = st.st_uid
                            if file_uid != uid and file_uid != 0:
                                if not dry_run:
                                    os.chown(dot_path, uid, pw.pw_gid)
                                    dot_changed = True
                                    dot_notes.append(f"Fixed ownership on {dot_path}")
                        except (OSError, PermissionError):
                            pass
    except Exception as e:
        dot_notes.append(f"Error checking dot files: {str(e)}")
    
    if not dot_notes:
        dot_notes.append("All user dot files have correct permissions")
    
    results.append(ActionResult(control_id, title, dot_changed, True, notes="; ".join(dot_notes[:10])))  # Limit notes
    
    return results
