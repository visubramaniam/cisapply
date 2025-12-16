from typing import List, Dict, Any
from .utils import ActionResult, ensure_perm

TARGETS = [("/etc/passwd",0o644),("/etc/group",0o644),("/etc/shadow",0o000),("/etc/gshadow",0o000),("/etc/ssh/sshd_config",0o600)]

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    notes=[]; changed=False
    for p,mode in TARGETS:
        c,n=ensure_perm(p, mode, 0,0, dry_run=dry_run)
        if c: changed=True
        notes.append(f"{p}: {n}")
    return [ActionResult("PERM-1","Harden key system file permissions", changed, True, notes="; ".join(notes))]
