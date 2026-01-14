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
    else:
        out=[]
        ok=True
        for c in cmds:
            cp=run(c)
            out.append((cp.stdout+cp.stderr).strip())
            ok = ok and (cp.returncode==0)
        results.append(ActionResult("FW-3","Configure firewalld", True, ok, notes="\n".join(o for o in out if o),
                                    commands=[shlex.join(c) for c in cmds]))

    # Control: Ensure nftables is masked if firewalld is in use
    control_id = "FW-4"
    title = "Ensure nftables service is masked (firewalld manages nftables)"
    
    cmd_mask = ["systemctl", "mask", "nftables"]
    if dry_run:
        results.append(ActionResult(control_id, title, True, True,
                                    notes="DRY-RUN: Would mask nftables service",
                                    commands=[shlex.join(cmd_mask)]))
    else:
        cp = run(cmd_mask)
        results.append(ActionResult(control_id, title, True, cp.returncode == 0,
                                    notes=(cp.stdout + cp.stderr).strip() or "nftables service masked",
                                    commands=[shlex.join(cmd_mask)]))

    # Control: Configure loopback traffic rules
    control_id = "FW-5"
    title = "Configure firewalld loopback traffic rules"
    
    # Firewalld direct rules for loopback
    # Allow all traffic on loopback interface
    # Block traffic from 127.0.0.0/8 on non-loopback interfaces
    loopback_cmds = [
        # IPv4 loopback rules
        ["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "0", "-i", "lo", "-j", "ACCEPT"],
        ["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv4", "filter", "OUTPUT", "0", "-o", "lo", "-j", "ACCEPT"],
        ["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "1", "-s", "127.0.0.0/8", "!", "-i", "lo", "-j", "DROP"],
        # IPv6 loopback rules
        ["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv6", "filter", "INPUT", "0", "-i", "lo", "-j", "ACCEPT"],
        ["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv6", "filter", "OUTPUT", "0", "-o", "lo", "-j", "ACCEPT"],
        ["firewall-cmd", "--permanent", "--direct", "--add-rule", "ipv6", "filter", "INPUT", "1", "-s", "::1", "!", "-i", "lo", "-j", "DROP"],
    ]
    
    if dry_run:
        results.append(ActionResult(control_id, title, True, True,
                                    notes="DRY-RUN: Would configure loopback traffic rules",
                                    commands=[shlex.join(c) for c in loopback_cmds]))
    else:
        ok = True
        out = []
        for cmd in loopback_cmds:
            cp = run(cmd)
            # Rule may already exist - that's ok
            if cp.returncode != 0 and "ALREADY_ENABLED" not in (cp.stderr or ""):
                out.append(f"{shlex.join(cmd)}: {(cp.stdout + cp.stderr).strip()}")
        
        # Reload firewalld to apply changes
        run(["firewall-cmd", "--reload"])
        
        results.append(ActionResult(control_id, title, True, ok,
                                    notes="Loopback traffic rules configured" + ("; " + "; ".join(out) if out else ""),
                                    commands=[shlex.join(c) for c in loopback_cmds]))

    return results
