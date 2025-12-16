from typing import List, Dict, Any
from .utils import ActionResult, run
import shlex

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    enforce=bool(cfg.get("enforce", True))
    if not enforce:
        return [ActionResult("SEL-0","SELinux enforcement (skipped by config)", False, True, notes="selinux.enforce=false")]
    cmds=[["getenforce"],["bash","-lc","sed -ri 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"],["setenforce","1"]]
    if dry_run:
        return [ActionResult("SEL-1","Ensure SELinux is enforcing", False, True,
                             notes="DRY-RUN: would set /etc/selinux/config and run setenforce 1",
                             commands=[shlex.join(c) for c in cmds], files=["/etc/selinux/config"])]
    out=[]; ok=True
    for c in cmds:
        cp=run(c); out.append((cp.stdout+cp.stderr).strip()); ok = ok and (cp.returncode==0)
    return [ActionResult("SEL-1","Ensure SELinux is enforcing", True, ok, notes="\n".join(o for o in out if o),
                         commands=[shlex.join(c) for c in cmds], files=["/etc/selinux/config"])]
