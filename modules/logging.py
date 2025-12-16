from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, ensure_service_enabled, ensure_kv_in_file

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    c1,n1=ensure_kv_in_file("/etc/systemd/journald.conf","Storage","persistent",sep="=",dry_run=dry_run)
    c2,n2=ensure_kv_in_file("/etc/systemd/journald.conf","Compress","yes",sep="=",dry_run=dry_run)
    c3,n3=ensure_kv_in_file("/etc/systemd/journald.conf","SystemMaxUse","1G",sep="=",dry_run=dry_run)
    results.append(ActionResult("LOG-1","Harden journald persistence/limits", c1 or c2 or c3, True, notes="; ".join([n1,n2,n3]),
                                files=["/etc/systemd/journald.conf"]))
    ensure_pkg(["rsyslog"], dry_run, results, "LOG-2", "Install rsyslog")
    ensure_service_enabled("rsyslog", dry_run, results, "LOG-3", "Enable rsyslog")
    return results
