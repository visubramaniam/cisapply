from typing import List, Dict, Any
from .utils import ensure_service_enabled

UNWANTED = ["avahi-daemon","cups","dhcpd","slapd","nfs-server","rpcbind","smb","snmpd","rsyncd","ypserv","telnet.socket","tftp.socket"]

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    for svc in UNWANTED:
        ensure_service_enabled(svc, dry_run, results, f"SVC-{svc}", f"Disable service: {svc}", state="mask")
    return results
