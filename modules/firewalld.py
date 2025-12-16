from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, ensure_service_enabled, run
import shlex

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str) -> List[ActionResult]:
    results=[]
    ensure_pkg(["firewalld"], dry_run, results, "FW-1", "Install firewalld")
    ensure_service_enabled("firewalld", dry_run, results, "FW-2", "Enable firewalld")

    zone = str(cfg.get("zone","public"))
    enforce = bool(cfg.get("enforce_allowlist", False))
    allow_services = cfg.get("allow_services", [])
    allow_ports = cfg.get("allow_ports", [])

    cmds=[["firewall-cmd","--set-default-zone",zone]]

    if enforce:
        bash_lines = [
          "set -e",
          f'ZONE={shlex.quote(zone)}',
          'SVCS="$(firewall-cmd --zone=\"$ZONE\" --list-services || true)"',
          'PORTS="$(firewall-cmd --zone=\"$ZONE\" --list-ports || true)"',
          'for s in $SVCS; do firewall-cmd --permanent --zone=\"$ZONE\" --remove-service=\"$s\" || true; done',
          'for p in $PORTS; do firewall-cmd --permanent --zone=\"$ZONE\" --remove-port=\"$p\" || true; done',
        ]
        for s in allow_services:
            bash_lines.append(f'firewall-cmd --permanent --zone=\"$ZONE\" --add-service={shlex.quote(str(s))}')
        for p in allow_ports:
            bash_lines.append(f'firewall-cmd --permanent --zone=\"$ZONE\" --add-port={shlex.quote(str(p))}')
        bash_lines.append("firewall-cmd --reload")
        cmds.append(["bash","-lc","\n".join(bash_lines)])
    else:
        cmds.append(["firewall-cmd","--reload"])

    if dry_run:
        results.append(ActionResult("FW-3","Configure firewalld", False, True,
                                    notes="DRY-RUN: would run\n" + "\n".join(shlex.join(c) for c in cmds),
                                    commands=[shlex.join(c) for c in cmds]))
        return results

    out=[]
    ok=True
    for c in cmds:
        cp=run(c)
        out.append((cp.stdout+cp.stderr).strip())
        ok = ok and (cp.returncode==0)
    results.append(ActionResult("FW-3","Configure firewalld", True, ok, notes="\n".join(o for o in out if o),
                                commands=[shlex.join(c) for c in cmds]))
    return results
