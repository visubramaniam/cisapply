from typing import List, Dict, Any
from .utils import ActionResult, run
import shlex

TMP_UNIT="/etc/systemd/system/tmp.mount"
VARTMP_UNIT="/etc/systemd/system/var-tmp.mount"

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    enable=bool(cfg.get("enable_tmp_mount_units", True))
    if not enable:
        return [ActionResult("MNT-0","tmpfs mount units (skipped by config)", False, True, notes="mounts.enable_tmp_mount_units=false")]
    tmp_size=str(cfg.get("tmp_size","1G"))
    vartmp_size=str(cfg.get("var_tmp_size","1G"))
    tmp_unit=f"""[Unit]
Description=Temporary Directory (/tmp)
Before=local-fs.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nodev,nosuid,noexec,size={tmp_size}

[Install]
WantedBy=local-fs.target
"""
    vartmp_unit=f"""[Unit]
Description=Temporary Directory (/var/tmp)
Before=local-fs.target

[Mount]
What=tmpfs
Where=/var/tmp
Type=tmpfs
Options=mode=1777,strictatime,nodev,nosuid,noexec,size={vartmp_size}

[Install]
WantedBy=local-fs.target
"""
    cmd=["bash","-lc", f"cat > {shlex.quote(TMP_UNIT)} <<'EOF'\n{tmp_unit}EOF\ncat > {shlex.quote(VARTMP_UNIT)} <<'EOF'\n{vartmp_unit}EOF\nsystemctl daemon-reload\nsystemctl enable --now tmp.mount var-tmp.mount"]
    if dry_run:
        return [ActionResult("MNT-1","Configure tmpfs mounts for /tmp and /var/tmp", True, True,
                             notes="DRY-RUN: would create systemd mount units and enable them",
                             commands=[shlex.join(cmd)], files=[TMP_UNIT,VARTMP_UNIT])]
    cp=run(cmd); return [ActionResult("MNT-1","Configure tmpfs mounts for /tmp and /var/tmp", True, cp.returncode==0,
                                     notes=(cp.stdout+cp.stderr).strip(), commands=[shlex.join(cmd)], files=[TMP_UNIT,VARTMP_UNIT])]
