from typing import List, Dict, Any
from .utils import ActionResult, ensure_perm, ensure_service_enabled, write_file, ensure_pkg, run
import os

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    
    # Ensure cronie package is installed
    ensure_pkg(["cronie"], dry_run, results, "CRON-0", "Install cronie package")
    
    # Enable crond service
    ensure_service_enabled("crond", dry_run, results, "CRON-1", "Enable cron daemon")
    
    # Control: Create /etc/cron.allow and /etc/at.allow
    c1,n1=write_file("/etc/cron.allow","root\n", mode=0o600, dry_run=dry_run)
    c2,n2=write_file("/etc/at.allow","root\n", mode=0o600, dry_run=dry_run)
    results.append(ActionResult("CRON-2","Restrict cron/at to authorized users (create allow files)", c1 or c2, True, notes="; ".join([n1,n2]),
                                files=["/etc/cron.allow","/etc/at.allow"]))
    
    # Control: Ensure cron.deny and at.deny do not exist when allow files exist
    # CIS requires: when allow files exist, deny files should be removed
    control_id = "CRON-2b"
    title = "Remove cron.deny and at.deny files (allow files take precedence)"
    changed = False
    notes = []
    
    # If allow files exist, deny files should be removed per CIS
    allow_files = [("/etc/cron.allow", "/etc/cron.deny"), ("/etc/at.allow", "/etc/at.deny")]
    for allow_file, deny_file in allow_files:
        if os.path.exists(allow_file) and os.path.exists(deny_file):
            if not dry_run:
                os.remove(deny_file)
                changed = True
                notes.append(f"Removed {deny_file} (allow file exists)")
            else:
                notes.append(f"DRY-RUN: Would remove {deny_file}")
                changed = True
        elif os.path.exists(deny_file) and not os.path.exists(allow_file):
            # If no allow file, ensure deny file has proper permissions
            c, n = ensure_perm(deny_file, 0o600, 0, 0, dry_run)
            if c:
                changed = True
                notes.append(f"{deny_file}: permissions fixed to 0600")
            else:
                notes.append(f"{deny_file}: permissions OK (0600)")
        else:
            notes.append(f"{deny_file}: not present (OK)")
    
    results.append(ActionResult(control_id, title, changed, True, notes="; ".join(notes)))
    
    # Control: Harden cron directory permissions
    dirs=["/etc/crontab","/etc/cron.hourly","/etc/cron.daily","/etc/cron.weekly","/etc/cron.monthly","/etc/cron.d"]
    notes_perms=[]; changed_perms=False
    for d in dirs:
        mode = 0o600 if d=="/etc/crontab" else 0o700
        c,n=ensure_perm(d, mode, 0,0, dry_run=dry_run)
        if c: changed_perms=True
        notes_perms.append(f"{d}: {n}")
    results.append(ActionResult("CRON-3","Harden cron permissions", changed_perms, True, notes="; ".join(notes_perms)))
    
    # Control: Ensure at package is installed and at.allow exists
    ensure_pkg(["at"], dry_run, results, "CRON-4", "Install at package")
    
    return results
