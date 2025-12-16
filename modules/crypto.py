from typing import List, Dict, Any
from .utils import ActionResult, run

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    if dry_run:
        return [ActionResult("CRYPTO-1","Ensure system crypto policy is not LEGACY", False, True,
                             notes="DRY-RUN: would check and set crypto policy to DEFAULT if LEGACY",
                             commands=["update-crypto-policies --show","update-crypto-policies --set DEFAULT"])]
    cp=run(["update-crypto-policies","--show"])
    cur=(cp.stdout+cp.stderr).strip()
    changed=False
    ok=True
    notes=[f"current: {cur}"]
    if "LEGACY" in cur:
        changed=True
        cp2=run(["update-crypto-policies","--set","DEFAULT"])
        ok = (cp2.returncode==0)
        notes.append((cp2.stdout+cp2.stderr).strip())
    return [ActionResult("CRYPTO-1","Ensure system crypto policy is not LEGACY", changed, ok, notes="\n".join(notes),
                         commands=["update-crypto-policies --show","update-crypto-policies --set DEFAULT"])]
