
import os, subprocess, shlex, re, stat
from dataclasses import dataclass
from typing import List, Dict, Tuple, Any

@dataclass
class ActionResult:
    id: str
    title: str
    changed: bool
    ok: bool
    notes: str = ""
    commands: List[str] = None
    files: List[str] = None

def run(cmd: List[str], check: bool=False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)

def is_root() -> bool:
    return os.geteuid() == 0

def ensure_pkg(pkgs: List[str], dry_run: bool, results: List[ActionResult], rid: str, title: str):
    cmd = ["dnf","-y","install"] + pkgs
    if dry_run:
        results.append(ActionResult(rid, title, False, True, notes="DRY-RUN: would run " + shlex.join(cmd), commands=[shlex.join(cmd)]))
        return
    cp = run(cmd)
    ok = (cp.returncode==0)
    results.append(ActionResult(rid, title, True if ok else False, ok, notes=(cp.stdout+cp.stderr).strip(), commands=[shlex.join(cmd)]))

def ensure_service_enabled(service: str, dry_run: bool, results: List[ActionResult], rid: str, title: str, state: str="enable"):
    if state=="enable":
        cmds=[["systemctl","enable","--now",service]]
    elif state=="disable":
        cmds=[["systemctl","disable","--now",service]]
    elif state=="mask":
        cmds=[["systemctl","mask","--now",service]]
    else:
        raise ValueError("state")
    if dry_run:
        results.append(ActionResult(rid, title, False, True, notes="DRY-RUN: would run "+ " && ".join(shlex.join(c) for c in cmds), commands=[shlex.join(c) for c in cmds]))
        return
    out=[]
    ok=True
    for c in cmds:
        cp=run(c)
        out.append((cp.stdout+cp.stderr).strip())
        ok = ok and (cp.returncode==0)
    results.append(ActionResult(rid, title, True if ok else False, ok, notes="\n".join(out), commands=[shlex.join(c) for c in cmds]))

def write_file(path: str, content: str, mode: int=0o644, dry_run: bool=False) -> Tuple[bool,str]:
    existing=None
    if os.path.exists(path):
        with open(path,"r",encoding="utf-8",errors="ignore") as f:
            existing=f.read()
    if existing == content:
        return False, "No change"
    if dry_run:
        return True, "DRY-RUN: would write " + path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path,"w",encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, mode)
    return True, "Wrote " + path

def ensure_kv_in_file(path: str, key: str, value: str, sep: str=" ", comment_prefix: str="#", dry_run: bool=False) -> Tuple[bool,str]:
    lines=[]
    changed=False
    if os.path.exists(path):
        with open(path,"r",encoding="utf-8",errors="ignore") as f:
            lines=f.read().splitlines()
    pat=re.compile(r'^\s*' + re.escape(key) + r'\b')
    new_lines=[]
    found=False
    for ln in lines:
        if pat.match(ln) and not ln.strip().startswith(comment_prefix):
            new_lines.append(f"{key}{sep}{value}")
            found=True
            if ln.strip() != f"{key}{sep}{value}":
                changed=True
        else:
            new_lines.append(ln)
    if not found:
        new_lines.append(f"{key}{sep}{value}")
        changed=True
    new_content="\n".join(new_lines).rstrip()+"\n"
    if not changed:
        return False, "No change"
    if dry_run:
        return True, f"DRY-RUN: would update {path}: {key}"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path,"w",encoding="utf-8") as f:
        f.write(new_content)
    return True, f"Updated {path}: {key}"

def ensure_perm(path: str, mode: int, owner_uid: int=0, owner_gid: int=0, dry_run: bool=False) -> Tuple[bool,str]:
    if not os.path.exists(path):
        return False, f"Not found: {path}"
    st=os.stat(path)
    changed=False
    notes=[]
    if stat.S_IMODE(st.st_mode) != mode:
        changed=True
        notes.append(f"mode {oct(stat.S_IMODE(st.st_mode))}->{oct(mode)}")
    if st.st_uid != owner_uid or st.st_gid != owner_gid:
        changed=True
        notes.append(f"owner {st.st_uid}:{st.st_gid}->{owner_uid}:{owner_gid}")
    if not changed:
        return False, "No change"
    if dry_run:
        return True, "DRY-RUN: would set " + path + " " + ", ".join(notes)
    os.chmod(path, mode)
    try:
        os.chown(path, owner_uid, owner_gid)
    except PermissionError:
        pass
    return True, "Set " + path + " " + ", ".join(notes)
