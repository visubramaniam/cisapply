from typing import List, Dict, Any
from .utils import ActionResult, ensure_kv_in_file, run
import shlex

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    pwq="/etc/security/pwquality.conf"
    changes=[]
    changes.append(ensure_kv_in_file(pwq,"minlen", str(cfg.get("pwquality_minlen",14)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"minclass", str(cfg.get("pwquality_minclass",4)), sep=" = ", dry_run=dry_run))
    for k in ["dcredit","ucredit","lcredit","ocredit"]:
        changes.append(ensure_kv_in_file(pwq,k, str(cfg.get(f"pwquality_{k}",-1)), sep=" = ", dry_run=dry_run))
    results.append(ActionResult("AUTH-1","Configure password quality (pwquality.conf)", any(c for c,_ in changes), True,
                                notes="; ".join(n for _,n in changes), files=[pwq]))

    ld="/etc/login.defs"
    ch=[]
    ch.append(ensure_kv_in_file(ld,"PASS_MAX_DAYS", str(cfg.get("pass_max_days",365)), sep="\t", dry_run=dry_run))
    ch.append(ensure_kv_in_file(ld,"PASS_MIN_DAYS", str(cfg.get("pass_min_days",7)), sep="\t", dry_run=dry_run))
    ch.append(ensure_kv_in_file(ld,"PASS_WARN_AGE", str(cfg.get("pass_warn_age",14)), sep="\t", dry_run=dry_run))
    results.append(ActionResult("AUTH-2","Configure password aging (login.defs)", any(c for c,_ in ch), True,
                                notes="; ".join(n for _,n in ch), files=[ld]))

    um="/etc/profile.d/99-cis-umask.sh"
    umask_val=str(cfg.get("umask","027"))
    cmd=["bash","-lc", f"cat > {shlex.quote(um)} <<'EOF'\numask {umask_val}\nEOF\nchmod 644 {shlex.quote(um)}"]
    if dry_run:
        results.append(ActionResult("AUTH-3","Set default umask", True, True, notes="DRY-RUN: would write "+um, commands=[shlex.join(cmd)], files=[um]))
    else:
        cp=run(cmd); results.append(ActionResult("AUTH-3","Set default umask", True, cp.returncode==0, notes=(cp.stdout+cp.stderr).strip(), commands=[shlex.join(cmd)], files=[um]))

    deny=int(cfg.get("lockout_deny",5))
    fail_interval=int(cfg.get("lockout_fail_interval",900))
    unlock_time=int(cfg.get("lockout_unlock_time",900))
    fl="/etc/security/faillock.conf"
    c1,n1=ensure_kv_in_file(fl,"deny", str(deny), sep=" = ", dry_run=dry_run)
    c2,n2=ensure_kv_in_file(fl,"fail_interval", str(fail_interval), sep=" = ", dry_run=dry_run)
    c3,n3=ensure_kv_in_file(fl,"unlock_time", str(unlock_time), sep=" = ", dry_run=dry_run)
    cmd2=["bash","-lc","authselect current >/dev/null 2>&1 && authselect enable-feature with-faillock && authselect apply-changes || true"]
    if dry_run:
        results.append(ActionResult("AUTH-4","Enable/configure account lockout (faillock)", c1 or c2 or c3, True,
                                    notes="DRY-RUN: would run "+shlex.join(cmd2)+"; "+ "; ".join([n1,n2,n3]),
                                    commands=[shlex.join(cmd2)], files=[fl]))
    else:
        cp=run(cmd2)
        results.append(ActionResult("AUTH-4","Enable/configure account lockout (faillock)", True, cp.returncode==0,
                                    notes=(cp.stdout+cp.stderr).strip()+"; "+ "; ".join([n1,n2,n3]),
                                    commands=[shlex.join(cmd2)], files=[fl]))
    return results
