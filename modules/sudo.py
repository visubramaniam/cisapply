from typing import List, Dict, Any
from .utils import ActionResult, write_file

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    content = "# CIS hardening\nDefaults use_pty\nDefaults logfile=\"/var/log/sudo.log\"\n"
    changed,n=write_file("/etc/sudoers.d/99-cis-hardening", content, mode=0o440, dry_run=dry_run)
    return [ActionResult("SUDO-1","Configure sudo to use pty and log to /var/log/sudo.log", changed, True, notes=n,
                         files=["/etc/sudoers.d/99-cis-hardening"])]
