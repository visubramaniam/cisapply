from typing import List, Dict, Any
from .utils import ActionResult, write_file, run
import shlex

DISABLE_MODULES_L1 = ["cramfs","freevxfs","hfs","hfsplus","jffs2","squashfs","udf","usb-storage"]
DISABLE_NETPROTO_L2 = ["dccp","sctp","rds","tipc"]

def _conf(mod: str) -> str:
    return f"install {mod} /bin/true\nblacklist {mod}\n"

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str) -> List[ActionResult]:
    mods=list(DISABLE_MODULES_L1)
    if profile.startswith("l2"):
        mods += DISABLE_NETPROTO_L2
    notes=[]
    changed_any=False
    for m in mods:
        path=f"/etc/modprobe.d/cis-disable-{m}.conf"
        changed, note = write_file(path, _conf(m), mode=0o644, dry_run=dry_run)
        changed_any = changed_any or changed
        notes.append(f"{m}: {note}")
    cmds=[["modprobe","-r",m] for m in mods]
    if dry_run:
        return [ActionResult("KERN-1","Disable uncommon filesystem/network kernel modules", changed_any, True,
                             notes="; ".join(notes)+"\nDRY-RUN: would attempt unload modules",
                             commands=[shlex.join(c) for c in cmds], files=[f"/etc/modprobe.d/cis-disable-{m}.conf" for m in mods])]
    out=[]
    for c in cmds:
        cp=run(c); out.append((cp.stdout+cp.stderr).strip())
    return [ActionResult("KERN-1","Disable uncommon filesystem/network kernel modules", True, True,
                         notes="; ".join(notes)+"\n"+"\n".join(o for o in out if o),
                         commands=[shlex.join(c) for c in cmds], files=[f"/etc/modprobe.d/cis-disable-{m}.conf" for m in mods])]
