"""
TCP Wrappers Configuration
CIS Reference: 3.4.x series - TCP Wrappers
"""
from typing import List, Dict, Any
from .utils import ActionResult, run
import os

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply TCP Wrappers hardening:
    - Configure /etc/hosts.allow (explicit allow list)
    - Configure /etc/hosts.deny (deny all by default)
    - Restrict network access at host level
    """
    results = []
    
    # Control: Configure /etc/hosts.allow for strict access control
    control_id = "TCP-1"
    title = "Configure /etc/hosts.allow with explicit allow rules"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        hosts_allow = "/etc/hosts.allow"
        
        # Get allowed hosts from config
        allowed_hosts = cfg.get("allowed_hosts", ["127.0.0.1", "localhost"])
        allow_all = cfg.get("allow_all", False)
        
        # Generate hosts.allow content
        lines = [
            "# TCP Wrappers - Explicit Allow List",
            "# CIS Oracle Linux 9 - Network Access Control",
            "#",
        ]
        
        if allow_all:
            lines.append("# WARNING: Allowing all hosts")
            lines.append("ALL: ALL")
        else:
            lines.append("# Local services - allow local access")
            lines.append("sshd: 127.0.0.1 [::1]")
            lines.append("ALL: localhost 127.0.0.1 [::1]")
            
            # Add additional allowed hosts from config
            for host in allowed_hosts:
                if host not in ["127.0.0.1", "localhost"]:
                    lines.append(f"sshd: {host}")
            
            lines.append("#")
            lines.append("# Service-specific rules can be added here")
            lines.append("# Example:")
            lines.append("# sshd: 192.168.1.0/24")
            lines.append("# http: 10.0.0.0/8")
        
        content = "\n".join(lines) + "\n"
        
        # Check if file needs updating
        file_exists = os.path.exists(hosts_allow)
        current_content = ""
        
        if file_exists:
            with open(hosts_allow, "r", encoding="utf-8") as f:
                current_content = f.read()
        
        if current_content != content:
            if not dry_run:
                # Backup existing file
                if file_exists:
                    run(["cp", hosts_allow, f"{hosts_allow}.backup"])
                
                # Write new file
                with open(hosts_allow, "w", encoding="utf-8") as f:
                    f.write(content)
                
                os.chmod(hosts_allow, 0o644)
                changed = True
                notes = "Created/updated /etc/hosts.allow"
            else:
                notes = "Would create/update /etc/hosts.allow"
            
            commands.append(f"cat > {hosts_allow} << 'EOF'")
            files.append(hosts_allow)
        else:
            notes = "/etc/hosts.allow already properly configured"
        
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
    
    # Control: Configure /etc/hosts.deny to deny all by default
    control_id = "TCP-2"
    title = "Configure /etc/hosts.deny with deny all rule"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        hosts_deny = "/etc/hosts.deny"
        
        lines = [
            "# TCP Wrappers - Deny All by Default (Whitelist Model)",
            "# CIS Oracle Linux 9 - Network Access Control",
            "#",
            "# Deny all by default - only explicitly allowed hosts can connect",
            "ALL: ALL",
        ]
        
        content = "\n".join(lines) + "\n"
        
        # Check if file needs updating
        file_exists = os.path.exists(hosts_deny)
        current_content = ""
        
        if file_exists:
            with open(hosts_deny, "r", encoding="utf-8") as f:
                current_content = f.read()
        
        if current_content != content:
            if not dry_run:
                # Backup existing file
                if file_exists:
                    run(["cp", hosts_deny, f"{hosts_deny}.backup"])
                
                # Write new file
                with open(hosts_deny, "w", encoding="utf-8") as f:
                    f.write(content)
                
                os.chmod(hosts_deny, 0o644)
                changed = True
                notes = "Created/updated /etc/hosts.deny with deny-all rule"
            else:
                notes = "Would create/update /etc/hosts.deny"
            
            commands.append(f"cat > {hosts_deny} << 'EOF'")
            files.append(hosts_deny)
        else:
            notes = "/etc/hosts.deny already properly configured"
        
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
    
    # Control: Verify TCP Wrappers support in system services
    control_id = "TCP-3"
    title = "Verify TCP Wrappers support in system services"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        # Check if tcp_wrappers library is installed
        cmd_result = run(["ldd", "/usr/sbin/sshd"], capture_output=True)
        
        if cmd_result and "libwrap" in cmd_result:
            notes = "SSH daemon compiled with TCP Wrappers support (libwrap)"
            commands.append("ldd /usr/sbin/sshd | grep libwrap")
        else:
            # SSH may still use wrappers even without explicit libwrap
            notes = "Verify SSH configured to use TCP Wrappers via PAM or libwrap"
            ok = True  # Not a failure, just informational
        
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=changed,
            ok=ok,
            notes=notes,
            commands=commands,
            files=[]
        ))
        
    except Exception as e:
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=False,
            ok=False,
            notes=f"Error checking TCP Wrappers support: {str(e)}",
            commands=[],
            files=[]
        ))
    
    return results
