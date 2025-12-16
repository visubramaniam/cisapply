from typing import List, Dict, Any
from .utils import ActionResult, ensure_kv_in_file, run
import shlex

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    lim="/etc/security/limits.d/99-cis-coredumps.conf"
    cmd=["bash","-lc", f"cat > {shlex.quote(lim)} <<'EOF'\n* hard core 0\nEOF\nchmod 644 {shlex.quote(lim)}"]
    c1,n1=ensure_kv_in_file("/etc/sysctl.d/99-cis-hardening.conf","fs.suid_dumpable","0",sep=" = ",dry_run=dry_run)
    if dry_run:
        return [ActionResult("CORE-1","Disable core dumps", True, True, notes="DRY-RUN: would write "+lim+"; "+n1,
                             commands=[shlex.join(cmd)], files=[lim,"/etc/sysctl.d/99-cis-hardening.conf"])]
    cp=run(cmd); ok=cp.returncode==0
    return [ActionResult("CORE-1","Disable core dumps", True, ok, notes=(cp.stdout+cp.stderr).strip()+"; "+n1,
                         commands=[shlex.join(cmd)], files=[lim])]
