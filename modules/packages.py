from typing import List, Dict, Any
from .utils import ActionResult, run
import shlex

REMOVE = ["telnet","telnet-server","ftp","tftp","tftp-server","rsh","rsh-server","ypbind","ypserv","talk","talk-server","xinetd"]

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    cmd=["dnf","-y","remove"]+REMOVE
    if dry_run:
        return [ActionResult("PKG-1","Remove legacy/insecure network packages", False, True, notes="DRY-RUN: would run "+shlex.join(cmd), commands=[shlex.join(cmd)])]
    cp=run(cmd); ok=(cp.returncode==0)
    return [ActionResult("PKG-1","Remove legacy/insecure network packages", True, ok, notes=(cp.stdout+cp.stderr).strip(), commands=[shlex.join(cmd)])]
