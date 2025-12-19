from typing import List, Dict, Any
from .utils import ActionResult, ensure_kv_in_file, run, ensure_pkg
import shlex, os, re

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    
    # Ensure authselect and pam packages
    ensure_pkg(["authselect","libpwquality","pam"], dry_run, results, "AUTH-0", "Install authentication packages")
    
    # Configure password quality (pwquality.conf)
    pwq="/etc/security/pwquality.conf"
    pwq_dir="/etc/security/pwquality.conf.d"
    changes=[]
    changes.append(ensure_kv_in_file(pwq,"minlen", str(cfg.get("pwquality_minlen",14)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"minclass", str(cfg.get("pwquality_minclass",4)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"maxrepeat", str(cfg.get("pwquality_maxrepeat",3)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"maxsequence", str(cfg.get("pwquality_maxsequence",3)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"difok", str(cfg.get("pwquality_difok",3)), sep=" = ", dry_run=dry_run))
    changes.append(ensure_kv_in_file(pwq,"enforce_for_root", "", sep="", dry_run=dry_run))
    for k in ["dcredit","ucredit","lcredit","ocredit"]:
        changes.append(ensure_kv_in_file(pwq,k, str(cfg.get(f"pwquality_{k}",-1)), sep=" = ", dry_run=dry_run))
    results.append(ActionResult("AUTH-1","Configure password quality (pwquality.conf)", any(c for c,_ in changes), True,
                                notes="; ".join(n for _,n in changes), files=[pwq]))

    # Configure password history
    pwh="/etc/security/pwhistory.conf"
    ph_changes=[]
    ph_changes.append(ensure_kv_in_file(pwh,"remember", str(cfg.get("pwhistory_remember",5)), sep=" = ", dry_run=dry_run))
    ph_changes.append(ensure_kv_in_file(pwh,"enforce_for_root", "", sep="", dry_run=dry_run))
    results.append(ActionResult("AUTH-1b","Configure password history (pwhistory.conf)", any(c for c,_ in ph_changes), True,
                                notes="; ".join(n for _,n in ph_changes), files=[pwh]))

    # Configure login.defs for password aging
    ld="/etc/login.defs"
    ch=[]
    ch.append(ensure_kv_in_file(ld,"PASS_MAX_DAYS", str(cfg.get("pass_max_days",365)), sep="\t", dry_run=dry_run))
    ch.append(ensure_kv_in_file(ld,"PASS_MIN_DAYS", str(cfg.get("pass_min_days",1)), sep="\t", dry_run=dry_run))
    ch.append(ensure_kv_in_file(ld,"PASS_WARN_AGE", str(cfg.get("pass_warn_age",14)), sep="\t", dry_run=dry_run))
    results.append(ActionResult("AUTH-2","Configure password aging (login.defs)", any(c for c,_ in ch), True,
                                notes="; ".join(n for _,n in ch), files=[ld]))

    # Set default umask
    um="/etc/profile.d/99-cis-umask.sh"
    umask_val=str(cfg.get("umask","027"))
    cmd=["bash","-lc", f"cat > {shlex.quote(um)} <<'EOF'\numask {umask_val}\nEOF\nchmod 644 {shlex.quote(um)}"]
    if dry_run:
        results.append(ActionResult("AUTH-3","Set default umask", True, True, notes="DRY-RUN: would write "+um, commands=[shlex.join(cmd)], files=[um]))
    else:
        cp=run(cmd); results.append(ActionResult("AUTH-3","Set default umask", True, cp.returncode==0, notes=(cp.stdout+cp.stderr).strip(), commands=[shlex.join(cmd)], files=[um]))

    # Set session timeout (tmout)
    tmout_files = ["/etc/bashrc", "/etc/profile"]
    for tf in tmout_files:
        if os.path.exists(tf):
            c,n = ensure_kv_in_file(tf,"TMOUT", str(cfg.get("tmout",900)), sep="=", dry_run=dry_run)
            results.append(ActionResult(f"AUTH-3a-{tf}",f"Set session timeout in {tf}", c, True, notes=n, files=[tf]))

    # Configure faillock
    deny=int(cfg.get("lockout_deny",5))
    fail_interval=int(cfg.get("lockout_fail_interval",900))
    unlock_time=int(cfg.get("lockout_unlock_time",900))
    root_unlock_time=int(cfg.get("root_unlock_time",60))
    
    fl="/etc/security/faillock.conf"
    c1,n1=ensure_kv_in_file(fl,"deny", str(deny), sep=" = ", dry_run=dry_run)
    c2,n2=ensure_kv_in_file(fl,"fail_interval", str(fail_interval), sep=" = ", dry_run=dry_run)
    c3,n3=ensure_kv_in_file(fl,"unlock_time", str(unlock_time), sep=" = ", dry_run=dry_run)
    c4,n4=ensure_kv_in_file(fl,"root_unlock_time", str(root_unlock_time), sep=" = ", dry_run=dry_run)
    
    # Remove nullok from pam files
    pam_files = ["/etc/pam.d/password-auth", "/etc/pam.d/system-auth"]
    for pf in pam_files:
        if os.path.exists(pf):
            with open(pf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            new_content = re.sub(r'\bnullok\b', '', content)
            if new_content != content and not dry_run:
                with open(pf, "w", encoding="utf-8") as f:
                    f.write(new_content)
                results.append(ActionResult(f"AUTH-3b-{pf}", f"Remove nullok from {pf}", True, True, files=[pf]))
            elif new_content != content:
                results.append(ActionResult(f"AUTH-3b-{pf}", f"Remove nullok from {pf}", True, True, notes="DRY-RUN: would update", files=[pf]))
    
    cmd2=["bash","-lc","authselect current >/dev/null 2>&1 && authselect enable-feature with-faillock && authselect apply-changes || true"]
    if dry_run:
        results.append(ActionResult("AUTH-4","Enable/configure account lockout (faillock)", c1 or c2 or c3 or c4, True,
                                    notes="DRY-RUN: would run "+shlex.join(cmd2)+"; "+ "; ".join([n1,n2,n3,n4]),
                                    commands=[shlex.join(cmd2)], files=[fl]))
    else:
        cp=run(cmd2)
        results.append(ActionResult("AUTH-4","Enable/configure account lockout (faillock)", True, cp.returncode==0,
                                    notes=(cp.stdout+cp.stderr).strip()+"; "+ "; ".join([n1,n2,n3,n4]),
                                    commands=[shlex.join(cmd2)], files=[fl]))
    
    return results
