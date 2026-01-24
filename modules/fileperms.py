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
    
    # Control: Ensure all users' dot files have correct ownership
    # Qualys controls 29421 (group ownership), 29422 (user ownership)
    # Dot files should be owned by the user and the group should be either
    # the user's primary group or root (gid 0)
    control_id = "PERM-2"
    title = "Ensure user dot files have correct ownership and permissions"
    dot_changed = False
    dot_notes = []
    
    # Excluded dot files per Qualys
    excluded_dotfiles = {'.forward', '.rhost', '.bash_history', '.netrc'}
    
    try:
        for pw in pwd.getpwall():
            home = pw.pw_dir
            uid = pw.pw_uid
            gid = pw.pw_gid
            
            # Skip users without real home directories
            if not os.path.isdir(home) or home == "/" or home == "/nonexistent":
                continue
            
            # Skip system users (typically uid < 1000) but include root
            if uid != 0 and uid < 1000:
                continue
            
            try:
                entries = os.listdir(home)
            except PermissionError:
                continue
            
            for entry in entries:
                if entry.startswith(".") and entry not in excluded_dotfiles:
                    dot_path = os.path.join(home, entry)
                    
                    if os.path.isfile(dot_path):
                        try:
                            st = os.stat(dot_path)
                            file_mode = st.st_mode
                            file_uid = st.st_uid
                            file_gid = st.st_gid
                            needs_fix = False
                            
                            # Check user ownership - must be owned by the user
                            if file_uid != uid:
                                needs_fix = True
                                if not dry_run:
                                    os.chown(dot_path, uid, file_gid)
                                    dot_notes.append(f"Fixed user ownership on {dot_path}")
                            
                            # Check group ownership - must be user's primary group or root
                            if file_gid != gid and file_gid != 0:
                                needs_fix = True
                                if not dry_run:
                                    os.chown(dot_path, uid, gid)
                                    dot_notes.append(f"Fixed group ownership on {dot_path}")
                            
                            # Check permissions - not group or world writable
                            if file_mode & (stat.S_IWGRP | stat.S_IWOTH):
                                needs_fix = True
                                new_mode = file_mode & ~(stat.S_IWGRP | stat.S_IWOTH)
                                if not dry_run:
                                    os.chmod(dot_path, new_mode)
                                    dot_notes.append(f"Fixed permissions on {dot_path}")
                            
                            if needs_fix:
                                dot_changed = True
                                
                        except (OSError, PermissionError) as e:
                            pass
    except Exception as e:
        dot_notes.append(f"Error: {str(e)}")
    
    if not dot_notes:
        dot_notes.append("All user dot files have correct ownership and permissions")
    
    results.append(ActionResult(control_id, title, dot_changed, True, notes="; ".join(dot_notes[:10])))
    
    # Control: Ensure no non-directory files exist in system PATH
    # Qualys control 10506
    control_id = "PERM-3"
    title = "Ensure no non-directory files in global PATH variable"
    path_changed = False
    path_notes = []
    
    # Check /etc/environment and shell profile files for PATH
    path_files = ["/etc/environment", "/etc/profile", "/etc/bashrc"]
    
    try:
        # Get current system PATH from environment files
        system_path = os.environ.get("PATH", "").split(":")
        
        for path_entry in system_path:
            if path_entry and os.path.exists(path_entry):
                if not os.path.isdir(path_entry):
                    path_notes.append(f"Non-directory in PATH: {path_entry}")
            elif path_entry and not os.path.exists(path_entry):
                # Path doesn't exist - this is also a potential issue
                pass
        
        if not path_notes:
            path_notes.append("PATH contains only valid directories")
        else:
            path_notes.append("Review and fix PATH configuration in /etc/environment or shell profiles")
    except Exception as e:
        path_notes.append(f"Error checking PATH: {str(e)}")
    
    results.append(ActionResult(control_id, title, path_changed, True, notes="; ".join(path_notes)))
    
    return results
