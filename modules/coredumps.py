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
        
        # Also update main coredump.conf for redundancy
        c4, n4 = ensure_kv_in_file(coredump_conf, "Storage", "none", sep="=", dry_run=dry_run)
        c5, n5 = ensure_kv_in_file(coredump_conf, "ProcessSizeMax", "0", sep="=", dry_run=dry_run)
        
        # Reload systemd
        if not dry_run and (c3 or c4 or c5):
            run(["systemctl", "daemon-reload"])
        
        results.append(ActionResult(control_id, title, c3 or c4 or c5, True,
                                    notes=f"{n3}; {n4}; {n5}",
                                    files=[dropin_file, coredump_conf]))
        
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False,
                                    notes=f"Error: {str(e)}"))
    
    return results
