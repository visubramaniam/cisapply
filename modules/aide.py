from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, run
import shlex

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    ensure_pkg(["aide"], dry_run, results, "AIDE-1", "Install AIDE")
    init=bool(cfg.get("initialize_if_missing", False))
    if not init:
        results.append(ActionResult("AIDE-2","AIDE initialization (skipped by config)", False, True, notes="Set aide.initialize_if_missing=true to initialize"))
        return results
    cmd=["bash","-lc","aide --init && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"]
    if dry_run:
        results.append(ActionResult("AIDE-2","Initialize AIDE database", False, True, notes="DRY-RUN: would run "+shlex.join(cmd), commands=[shlex.join(cmd)]))
        return results
    cp=run(cmd); results.append(ActionResult("AIDE-2","Initialize AIDE database", True, cp.returncode==0, notes=(cp.stdout+cp.stderr).strip(), commands=[shlex.join(cmd)]))
    return results
