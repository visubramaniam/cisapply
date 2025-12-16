from typing import List, Dict, Any
from .utils import ActionResult, ensure_perm, ensure_service_enabled, write_file

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    ensure_service_enabled("crond", dry_run, results, "CRON-1", "Enable cron daemon")
    c1,n1=write_file("/etc/cron.allow","root\n", mode=0o600, dry_run=dry_run)
    c2,n2=write_file("/etc/at.allow","root\n", mode=0o600, dry_run=dry_run)
    results.append(ActionResult("CRON-2","Restrict cron/at to authorized users", c1 or c2, True, notes="; ".join([n1,n2]),
                                files=["/etc/cron.allow","/etc/at.allow"]))
    dirs=["/etc/crontab","/etc/cron.hourly","/etc/cron.daily","/etc/cron.weekly","/etc/cron.monthly","/etc/cron.d"]
    notes=[]; changed=False
    for d in dirs:
        mode = 0o600 if d=="/etc/crontab" else 0o700
        c,n=ensure_perm(d, mode, 0,0, dry_run=dry_run)
        if c: changed=True
        notes.append(f"{d}: {n}")
    results.append(ActionResult("CRON-3","Harden cron permissions", changed, True, notes="; ".join(notes)))
    return results
