from typing import List, Dict, Any
from .utils import ActionResult, ensure_kv_in_file

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    disable=bool(cfg.get("disable", False))
    if not disable:
        return [ActionResult("IPV6-0","Disable IPv6 (skipped by config)", False, True, notes="ipv6.disable=false")]
    c1,n1=ensure_kv_in_file("/etc/sysctl.d/99-cis-hardening.conf","net.ipv6.conf.all.disable_ipv6","1",sep=" = ",dry_run=dry_run)
    c2,n2=ensure_kv_in_file("/etc/sysctl.d/99-cis-hardening.conf","net.ipv6.conf.default.disable_ipv6","1",sep=" = ",dry_run=dry_run)
    return [ActionResult("IPV6-1","Disable IPv6 via sysctl", c1 or c2, True, notes="; ".join([n1,n2]),
                         files=["/etc/sysctl.d/99-cis-hardening.conf"])]
