from typing import List, Dict, Any
from .utils import ActionResult, write_file

BANNER = "Authorized uses only. All activity may be monitored and reported.\n"

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    c1,n1=write_file("/etc/issue", BANNER, mode=0o644, dry_run=dry_run)
    c2,n2=write_file("/etc/issue.net", BANNER, mode=0o644, dry_run=dry_run)
    c3,n3=write_file("/etc/motd", "", mode=0o644, dry_run=dry_run)
    return [ActionResult("BANNER-1","Set login banners and clear /etc/motd", c1 or c2 or c3, True,
                         notes="; ".join([n1,n2,n3]), files=["/etc/issue","/etc/issue.net","/etc/motd"])]
