from typing import List, Dict, Any
from .utils import ActionResult, run
import shlex

# Legacy and insecure packages to remove
REMOVE = ["telnet","telnet-server","ftp","tftp","tftp-server","rsh","rsh-server","ypbind","ypserv","talk","talk-server","xinetd"]

# Bluetooth packages to remove for server hardening
BLUETOOTH_PACKAGES = ["bluez", "bluez-libs", "bluez-obexd"]

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results = []
    
    # Control: Remove legacy/insecure network packages
    control_id = "PKG-1"
    title = "Remove legacy/insecure network packages"
    
    cmd=["dnf","-y","remove"]+REMOVE
    if dry_run:
        results.append(ActionResult(control_id, title, False, True, 
                                    notes="DRY-RUN: would run "+shlex.join(cmd), 
                                    commands=[shlex.join(cmd)]))
    else:
        cp=run(cmd)
        ok=(cp.returncode==0)
        results.append(ActionResult(control_id, title, True, ok, 
                                    notes=(cp.stdout+cp.stderr).strip(), 
                                    commands=[shlex.join(cmd)]))
    
    # Control: Remove bluetooth packages
    control_id = "PKG-2"
    title = "Remove bluetooth packages"
    
    remove_bluetooth = cfg.get("remove_bluetooth", True)
    
    if remove_bluetooth:
        # First, stop and disable bluetooth service
        service_cmds = [
            ["systemctl", "stop", "bluetooth"],
            ["systemctl", "disable", "bluetooth"],
            ["systemctl", "mask", "bluetooth"]
        ]
        
        if not dry_run:
            for scmd in service_cmds:
                run(scmd)  # Ignore errors if service doesn't exist
        
        # Remove bluetooth packages
        cmd_bt = ["dnf", "-y", "remove"] + BLUETOOTH_PACKAGES
        
        if dry_run:
            results.append(ActionResult(control_id, title, True, True,
                                        notes="DRY-RUN: would disable bluetooth service and run " + shlex.join(cmd_bt),
                                        commands=[shlex.join(cmd_bt)]))
        else:
            cp = run(cmd_bt)
            # Success even if packages weren't installed
            ok = (cp.returncode == 0 or "No packages marked for removal" in (cp.stdout + cp.stderr))
            results.append(ActionResult(control_id, title, True, ok,
                                        notes=(cp.stdout + cp.stderr).strip(),
                                        commands=[shlex.join(cmd_bt)]))
    else:
        results.append(ActionResult(control_id, title, False, True,
                                    notes="Bluetooth removal disabled in configuration"))
    
    # Control: Ensure unnecessary services are disabled
    control_id = "PKG-3"
    title = "Disable unnecessary services"
    
    services_to_disable = cfg.get("disable_services", [
        "avahi-daemon",
        "cups",
        "dhcpd",
        "slapd",
        "named",
        "vsftpd",
        "httpd",
        "dovecot",
        "smb",
        "squid",
        "snmpd",
        "ypserv",
        "rsh.socket",
        "rlogin.socket",
        "rexec.socket"
    ])
    
    disabled = []
    for svc in services_to_disable:
        if not dry_run:
            cp = run(["systemctl", "is-enabled", svc])
            if cp.returncode == 0:  # Service exists and is enabled
                run(["systemctl", "stop", svc])
                run(["systemctl", "disable", svc])
                disabled.append(svc)
    
    if dry_run:
        results.append(ActionResult(control_id, title, True, True,
                                    notes=f"DRY-RUN: Would disable services: {', '.join(services_to_disable)}"))
    else:
        if disabled:
            results.append(ActionResult(control_id, title, True, True,
                                        notes=f"Disabled services: {', '.join(disabled)}"))
        else:
            results.append(ActionResult(control_id, title, False, True,
                                        notes="No unnecessary services found to disable"))
    
    return results
