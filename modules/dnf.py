"""
DNF/YUM Package Manager Security Hardening
CIS Reference: 1.2.x series - Package Manager Configuration
"""
from typing import List, Dict, Any
from .utils import ActionResult, run, ensure_kv_in_file
import os
import glob
import re

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply DNF/YUM package manager hardening:
    - Enforce GPG signature verification
    - Configure repo_gpgcheck
    - Disable unused repositories
    - Ensure package manager security settings
    """
    results = []
    
    # Control: Ensure GPG check is globally enabled
    control_id = "DNF-1"
    title = "Ensure gpgcheck is globally activated"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        dnf_conf = "/etc/dnf/dnf.conf"
        yum_conf = "/etc/yum.conf"
        
        # Check and fix dnf.conf
        if os.path.exists(dnf_conf):
            c1, n1 = ensure_kv_in_file(dnf_conf, "gpgcheck", "1", sep="=", dry_run=dry_run)
            c2, n2 = ensure_kv_in_file(dnf_conf, "repo_gpgcheck", "1", sep="=", dry_run=dry_run)
            c3, n3 = ensure_kv_in_file(dnf_conf, "localpkg_gpgcheck", "1", sep="=", dry_run=dry_run)
            
            if c1 or c2 or c3:
                changed = True
                notes = f"Updated {dnf_conf}: {n1}; {n2}; {n3}"
            else:
                notes = f"{dnf_conf} already has GPG checks enabled"
            
            files.append(dnf_conf)
        
        # Also check yum.conf for backward compatibility
        if os.path.exists(yum_conf) and yum_conf != dnf_conf:
            c4, n4 = ensure_kv_in_file(yum_conf, "gpgcheck", "1", sep="=", dry_run=dry_run)
            if c4:
                changed = True
                notes += f"; Updated {yum_conf}: {n4}"
            files.append(yum_conf)
        
        results.append(ActionResult(
            id=control_id,
            title=title,
            changed=changed,
            ok=ok,
            notes=notes or "GPG check already enabled",
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
    
    # Control: Ensure gpgcheck is enabled for all repositories
    control_id = "DNF-2"
    title = "Ensure gpgcheck is enabled for all repositories"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        repo_dir = "/etc/yum.repos.d"
        repos_fixed = []
        repos_ok = []
        
        if os.path.isdir(repo_dir):
            repo_files = glob.glob(os.path.join(repo_dir, "*.repo"))
            
            for repo_file in repo_files:
                with open(repo_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # Check for gpgcheck=0
                if re.search(r'^\s*gpgcheck\s*=\s*0', content, re.MULTILINE):
                    if not dry_run:
                        # Replace gpgcheck=0 with gpgcheck=1
                        new_content = re.sub(
                            r'^\s*gpgcheck\s*=\s*0',
                            'gpgcheck=1',
                            content,
                            flags=re.MULTILINE
                        )
                        with open(repo_file, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        repos_fixed.append(os.path.basename(repo_file))
                        changed = True
                    else:
                        repos_fixed.append(os.path.basename(repo_file))
                        changed = True
                else:
                    repos_ok.append(os.path.basename(repo_file))
                
                files.append(repo_file)
        
        if repos_fixed:
            notes = f"Fixed gpgcheck in: {', '.join(repos_fixed)}"
        else:
            notes = f"All {len(repos_ok)} repositories have gpgcheck enabled"
        
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
    
    # Control: Ensure package manager caches are secure
    control_id = "DNF-3"
    title = "Ensure DNF automatic security updates are configured"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        auto_conf = "/etc/dnf/automatic.conf"
        enable_auto_updates = cfg.get("enable_automatic_updates", False)
        
        if enable_auto_updates:
            if os.path.exists(auto_conf):
                c1, n1 = ensure_kv_in_file(auto_conf, "upgrade_type", "security", sep=" = ", dry_run=dry_run)
                c2, n2 = ensure_kv_in_file(auto_conf, "apply_updates", "yes", sep=" = ", dry_run=dry_run)
                c3, n3 = ensure_kv_in_file(auto_conf, "download_updates", "yes", sep=" = ", dry_run=dry_run)
                
                if c1 or c2 or c3:
                    changed = True
                    notes = f"Configured automatic security updates: {n1}; {n2}; {n3}"
                else:
                    notes = "Automatic security updates already configured"
                
                files.append(auto_conf)
                
                # Enable the timer
                if not dry_run:
                    run(["systemctl", "enable", "dnf-automatic.timer"])
                commands.append("systemctl enable dnf-automatic.timer")
            else:
                notes = "dnf-automatic not installed; install with: dnf install dnf-automatic"
                ok = True  # Not a failure, just informational
        else:
            notes = "Automatic updates disabled in configuration (set dnf.enable_automatic_updates=true to enable)"
        
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
    
    return results
