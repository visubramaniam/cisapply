"""
Postfix/Mail Service Hardening
CIS Reference: 2.2.x series - Mail Transfer Agent Configuration
"""
from typing import List, Dict, Any
from .utils import ActionResult, run, ensure_kv_in_file
import os
import subprocess

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply mail service hardening:
    - Configure Postfix for local delivery only
    - Remove unnecessary mail services
    - Restrict mail relay
    """
    results = []
    
    # Control: Ensure mail transfer agent is configured for local-only mode
    control_id = "MAIL-1"
    title = "Configure MTA for local-only mode"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        postfix_main_cf = "/etc/postfix/main.cf"
        
        # Check if postfix is installed
        postfix_installed = os.path.exists(postfix_main_cf)
        
        if postfix_installed:
            # Configure postfix for local-only delivery
            settings = [
                ("inet_interfaces", "loopback-only"),
                ("inet_protocols", "ipv4"),
                ("mydestination", "$myhostname, localhost.$mydomain, localhost"),
                ("mynetworks", "127.0.0.0/8"),
                ("relayhost", ""),
                ("smtpd_relay_restrictions", "permit_mynetworks, reject_unauth_destination"),
            ]
            
            changes = []
            for key, value in settings:
                c, n = ensure_kv_in_file(postfix_main_cf, key, value, sep=" = ", dry_run=dry_run)
                changes.append((c, n))
            
            if any(c for c, _ in changes):
                changed = True
                notes = "Configured Postfix for local-only delivery; "
                notes += "; ".join(n for _, n in changes if n)
                
                # Restart postfix if not dry-run
                if not dry_run:
                    result = run(["systemctl", "restart", "postfix"])
                    if result.returncode != 0:
                        notes += "; Warning: Failed to restart postfix"
                
                commands.append("systemctl restart postfix")
            else:
                notes = "Postfix already configured for local-only delivery"
            
            files.append(postfix_main_cf)
        else:
            # Check for sendmail or other MTAs
            sendmail_path = "/etc/mail/sendmail.cf"
            if os.path.exists(sendmail_path):
                notes = "Sendmail detected; recommend replacing with Postfix or removing"
                ok = True  # Informational, not a failure
            else:
                notes = "No MTA (Postfix/Sendmail) installed - acceptable for minimal systems"
        
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=changed,
            ok=ok,
            notes=notes,
            commands=commands,
            files=files
        ))
        
    except Exception as e:
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=False,
            ok=False,
            notes=f"Error: {str(e)}",
            commands=[],
            files=[]
        ))
    
    # Control: Remove or disable unnecessary mail services
    control_id = "MAIL-2"
    title = "Remove or disable unnecessary mail services"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        # Services to check and potentially disable
        mail_services = [
            "sendmail",
            "dovecot",
            "cyrus-imapd",
            "saslauthd",
        ]
        
        remove_unused = cfg.get("remove_unused_mail_services", False)
        services_found = []
        services_disabled = []
        
        for service in mail_services:
            # Check if service exists
            check_result = run(["systemctl", "list-unit-files", f"{service}.service"])
            output = check_result.stdout if check_result else ""
            
            if service in output:
                services_found.append(service)
                
                # Check if enabled
                is_enabled = run(["systemctl", "is-enabled", service])
                
                if is_enabled.returncode == 0:
                    if not dry_run and remove_unused:
                        run(["systemctl", "stop", service])
                        run(["systemctl", "disable", service])
                        services_disabled.append(service)
                        changed = True
                    elif remove_unused:
                        services_disabled.append(service)
                        changed = True
                    
                    commands.append(f"systemctl disable --now {service}")
        
        if services_disabled:
            notes = f"Disabled mail services: {', '.join(services_disabled)}"
        elif services_found:
            notes = f"Found mail services (not disabled): {', '.join(services_found)}; set postfix.remove_unused_mail_services=true to disable"
            ok = True  # Informational, not a failure
        else:
            notes = "No unnecessary mail services found"
        
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=changed,
            ok=ok,
            notes=notes,
            commands=commands,
            files=files
        ))
        
    except Exception as e:
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=False,
            ok=True,  # Don't fail on check errors
            notes=f"Mail services check skipped: {str(e)}",
            commands=[],
            files=[]
        ))
    
    return results
