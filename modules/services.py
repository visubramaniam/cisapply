"""
Service Hardening and Management
CIS Reference: 2.2.x - Services Configuration
"""
from typing import List, Dict, Any
from .utils import ensure_service_enabled, ensure_pkg, run, ActionResult
import os

# Services that should be masked/disabled for CIS compliance
UNWANTED = [
    "avahi-daemon",
    "cups",
    "dhcpd",
    "slapd",
    "nfs-server",
    "rpcbind",
    "smb",
    "snmpd",
    "rsyncd",
    "ypserv",
    "telnet.socket",
    "tftp.socket",
    "systemd-journal-remote.service",
    "systemd-journal-upload.service"
]

# Services that should be enabled/started for CIS compliance
REQUIRED = {
    "aidecheck.service": "AIDE file integrity monitoring service",
    "aidecheck.timer": "AIDE file integrity monitoring timer",
    "auditd": "Audit daemon for security logging",
}

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply service hardening:
    - Disable unnecessary/dangerous services
    - Enable required security services (auditd, aidecheck)
    - Manage systemd-journal-remote
    """
    results = []
    
    # Disable unwanted services
    for svc in UNWANTED:
        ensure_service_enabled(svc, dry_run, results, f"SVC-{svc}", f"Disable service: {svc}", state="mask")
    
    # Ensure AIDE package is installed
    control_id = "SVC-AIDE-PKG"
    title = "Ensure aide package is installed"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    if not dry_run:
        ensure_pkg("aide", results, control_id, title)
    else:
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=False,
            ok=True,
            notes="DRY-RUN: Would ensure aide package installed",
            commands=["yum install aide"],
            files=[]
        ))
    
    # Initialize AIDE database if needed
    control_id = "SVC-AIDE-INIT"
    title = "Ensure AIDE database is initialized"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        aide_db = "/var/lib/aide/aide.db"
        aide_new_db = "/var/lib/aide/aide.db.new"
        
        # Check if AIDE database exists, initialize if not
        if not os.path.exists(aide_db) and not os.path.exists(aide_new_db):
            notes = "AIDE database not found, initializing..."
            if not dry_run:
                # Initialize AIDE database
                cmd = ["aide", "--init", "-B", "database_in=/var/lib/aide/aide.db"]
                cp = run(cmd)
                commands.append(" ".join(cmd))
                if cp.returncode == 0:
                    changed = True
                    notes = "AIDE database initialized successfully"
                else:
                    ok = False
                    notes = f"Failed to initialize AIDE database: {cp.stderr}"
            else:
                notes = "DRY-RUN: Would initialize AIDE database"
                commands.append("aide --init -B database_in=/var/lib/aide/aide.db")
        else:
            notes = "AIDE database already exists"
    except Exception as e:
        ok = False
        notes = f"Error: {str(e)}"
    
    results.append(ActionResult(
        id=control_id,
        title=title,
        changed=changed,
        ok=ok,
        notes=notes,
        commands=commands,
        files=files
    ))
    
    # Enable and start AIDE services/timers
    for service, description in REQUIRED.items():
        if service in ["aidecheck.service", "aidecheck.timer"]:
            # Check if these services exist before trying to enable them
            try:
                cmd = ["systemctl", "list-unit-files", service]
                cp = run(cmd)
                if cp.returncode == 0 and service in cp.stdout:
                    ensure_service_enabled(service, dry_run, results, f"SVC-{service}", f"Enable {description}", state="enable")
                else:
                    results.append(ActionResult(
                        id=f"SVC-{service}",
                        title=f"Enable {description}",
                        changed=False,
                        ok=True,
                        notes=f"{service} not available on this system",
                        commands=[],
                        files=[]
                    ))
            except Exception as e:
                results.append(ActionResult(
                    id=f"SVC-{service}",
                    title=f"Enable {description}",
                    changed=False,
                    ok=False,
                    notes=f"Error checking service: {str(e)}",
                    commands=[],
                    files=[]
                ))
        else:
            ensure_service_enabled(service, dry_run, results, f"SVC-{service}", f"Enable {description}", state="enable")
    
    # Ensure systemd-journal-remote is disabled
    control_id = "SVC-JOURNAL-REMOTE"
    title = "Ensure systemd-journal-remote is disabled"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        # Check if systemd-journal-remote.service is disabled
        cmd = ["systemctl", "is-enabled", "systemd-journal-remote.service"]
        cp = run(cmd)
        
        if "disabled" not in cp.stdout and "masked" not in cp.stdout:
            if not dry_run:
                # Disable and mask the service
                run(["systemctl", "disable", "systemd-journal-remote.service"])
                run(["systemctl", "mask", "systemd-journal-remote.service"])
                changed = True
                notes = "systemd-journal-remote.service disabled and masked"
                commands.append("systemctl disable systemd-journal-remote.service")
                commands.append("systemctl mask systemd-journal-remote.service")
            else:
                notes = "DRY-RUN: Would disable and mask systemd-journal-remote.service"
                commands.append("systemctl disable systemd-journal-remote.service")
                commands.append("systemctl mask systemd-journal-remote.service")
        else:
            notes = "systemd-journal-remote.service already disabled"
    except Exception as e:
        ok = False
        notes = f"Error: {str(e)}"
    
    results.append(ActionResult(
        id=control_id,
        title=title,
        changed=changed,
        ok=ok,
        notes=notes,
        commands=commands,
        files=files
    ))
    
    return results
