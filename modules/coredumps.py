from typing import List, Dict, Any
from .utils import ActionResult, ensure_kv_in_file, run, write_file
import shlex
import os

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results = []
    
    # Control: Disable core dumps via limits.conf
    control_id = "CORE-1"
    title = "Disable core dumps via limits.conf"
    
    lim="/etc/security/limits.d/99-cis-coredumps.conf"
    limits_content = "* hard core 0\n"
    
    c1, n1 = write_file(lim, limits_content, mode=0o644, dry_run=dry_run)
    
    # Also configure fs.suid_dumpable in sysctl
    c2, n2 = ensure_kv_in_file("/etc/sysctl.d/99-cis-hardening.conf", "fs.suid_dumpable", "0", sep=" = ", dry_run=dry_run)
    
    results.append(ActionResult(control_id, title, c1 or c2, True,
                                notes=f"{n1}; {n2}",
                                files=[lim, "/etc/sysctl.d/99-cis-hardening.conf"]))
    
    # Control: Configure systemd-coredump with ProcessSizeMax and Storage
    control_id = "CORE-2"
    title = "Configure systemd-coredump settings (ProcessSizeMax, Storage)"
    
    coredump_conf = "/etc/systemd/coredump.conf"
    coredump_d = "/etc/systemd/coredump.conf.d"
    
    try:
        # Create drop-in directory if needed
        if not os.path.exists(coredump_d):
            if not dry_run:
                os.makedirs(coredump_d, mode=0o755, exist_ok=True)
        
        # Write drop-in configuration
        dropin_file = os.path.join(coredump_d, "99-cis-hardening.conf")
        dropin_content = """# CIS Hardening - Disable coredumps
[Coredump]
Storage=none
ProcessSizeMax=0
"""
        
        c3, n3 = write_file(dropin_file, dropin_content, mode=0o644, dry_run=dry_run)
        
        # Update main coredump.conf - ensure settings are in [Coredump] section
        # Qualys checks the main coredump.conf file directly
        c4 = c5 = False
        n4 = n5 = ""
        
        if os.path.exists(coredump_conf):
            with open(coredump_conf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            new_content = content
            modified = False
            
            # Ensure [Coredump] section exists and has our settings
            if "[Coredump]" not in content:
                # Add section with settings
                new_content = content.rstrip() + "\n\n[Coredump]\nStorage=none\nProcessSizeMax=0\n"
                modified = True
            else:
                # Check and update Storage setting
                import re
                if not re.search(r'^\s*Storage\s*=', content, re.MULTILINE):
                    # Add Storage after [Coredump]
                    new_content = re.sub(r'(\[Coredump\])', r'\1\nStorage=none', new_content)
                    modified = True
                elif not re.search(r'^\s*Storage\s*=\s*none', content, re.MULTILINE):
                    new_content = re.sub(r'^\s*#?\s*Storage\s*=.*$', 'Storage=none', new_content, flags=re.MULTILINE)
                    modified = True
                
                # Check and update ProcessSizeMax setting
                if not re.search(r'^\s*ProcessSizeMax\s*=', new_content, re.MULTILINE):
                    new_content = re.sub(r'(\[Coredump\])', r'\1\nProcessSizeMax=0', new_content)
                    modified = True
                elif not re.search(r'^\s*ProcessSizeMax\s*=\s*0', new_content, re.MULTILINE):
                    new_content = re.sub(r'^\s*#?\s*ProcessSizeMax\s*=.*$', 'ProcessSizeMax=0', new_content, flags=re.MULTILINE)
                    modified = True
            
            if modified and not dry_run:
                with open(coredump_conf, "w", encoding="utf-8") as f:
                    f.write(new_content)
                c4 = True
                n4 = "Updated coredump.conf with Storage=none and ProcessSizeMax=0"
            elif modified:
                n4 = "DRY-RUN: Would update coredump.conf"
            else:
                n4 = "coredump.conf already has correct settings"
        
        # Reload systemd
        if not dry_run and (c3 or c4):
            run(["systemctl", "daemon-reload"])
        
        results.append(ActionResult(control_id, title, c3 or c4, True,
                                    notes=f"{n3}; {n4}",
                                    files=[dropin_file, coredump_conf]))
        
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False,
                                    notes=f"Error: {str(e)}"))
    
    return results
