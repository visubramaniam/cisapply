"""
Boot and Bootloader Hardening
CIS Reference: 1.3.x, 1.4.x - Boot Settings and Bootloader Configuration
"""
from typing import List, Dict, Any
from .utils import ActionResult, run, ensure_kv_in_file
import os, re, subprocess, shlex

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply bootloader hardening:
    - Protect GRUB with password
    - Restrict /boot/grub2/grub.cfg permissions
    - Restrict kernel parameters including audit
    - Disable unnecessary boot options
    """
    results = []
    
    # Control: Ensure /boot/grub2/grub.cfg has restricted permissions
    control_id = "BOOT-1"
    title = "Ensure /boot/grub2/grub.cfg has restricted permissions (600)"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        grub_cfg = "/boot/grub2/grub.cfg"
        target_mode = 0o600
        
        if os.path.exists(grub_cfg):
            current_stat = os.stat(grub_cfg)
            current_mode = current_stat.st_mode & 0o777
            
            if current_mode != target_mode:
                if not dry_run:
                    os.chmod(grub_cfg, target_mode)
                    changed = True
                    notes = f"Changed permissions from {oct(current_mode)} to {oct(target_mode)}"
                else:
                    notes = f"Would change permissions from {oct(current_mode)} to {oct(target_mode)}"
                
                commands.append(f"chmod 600 {grub_cfg}")
                files.append(grub_cfg)
            else:
                notes = "Permissions already correct (600)"
        else:
            notes = f"{grub_cfg} not found (EFI system?)"
            ok = True  # Not necessarily an error
        
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
    
    # Control: Ensure /boot/grub2/user.cfg has restricted permissions
    control_id = "BOOT-2"
    title = "Ensure /boot/grub2/user.cfg has restricted permissions (600)"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        user_cfg = "/boot/grub2/user.cfg"
        target_mode = 0o600
        
        if os.path.exists(user_cfg):
            current_stat = os.stat(user_cfg)
            current_mode = current_stat.st_mode & 0o777
            
            if current_mode != target_mode:
                if not dry_run:
                    os.chmod(user_cfg, target_mode)
                    changed = True
                    notes = f"Changed permissions from {oct(current_mode)} to {oct(target_mode)}"
                else:
                    notes = f"Would change permissions from {oct(current_mode)} to {oct(target_mode)}"
                
                commands.append(f"chmod 600 {user_cfg}")
                files.append(user_cfg)
            else:
                notes = "Permissions already correct (600)"
        else:
            notes = f"{user_cfg} not found (may not be configured)"
            ok = True  # Not an error if not present
        
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
    
    # Control: Ensure bootloader is password protected
    control_id = "BOOT-3"
    title = "Ensure GRUB bootloader has password protection"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        enforce_grub_password = cfg.get("grub_password", True)
        user_cfg = "/boot/grub2/user.cfg"
        
        if enforce_grub_password:
            # Check if superuser is set in user.cfg
            has_password = False
            if os.path.exists(user_cfg):
                with open(user_cfg, "r", encoding="utf-8") as f:
                    content = f.read()
                    if "superusers" in content:
                        has_password = True
                        notes = "GRUB superuser already configured"
            
            if not has_password:
                notes = "GRUB password not configured - manual intervention required"
                ok = True  # This requires user interaction (grub-mkpasswd-pbkdf2)
                commands.append("grub-mkpasswd-pbkdf2  # Generate password hash")
                commands.append("# Add to /etc/grub.d/40_custom or /boot/grub2/user.cfg")
        else:
            notes = "GRUB password protection disabled in configuration"
        
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
    
    # Control: Ensure audit and audit_backlog_limit kernel parameters in /etc/default/grub
    control_id = "BOOT-4"
    title = "Ensure audit kernel parameters are set in /etc/default/grub"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = ["/etc/default/grub"]
    
    try:
        grub_default = "/etc/default/grub"
        if os.path.exists(grub_default):
            # Read current content
            with open(grub_default, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Check and update GRUB_CMDLINE_LINUX
            pattern = r'GRUB_CMDLINE_LINUX="([^"]*)"'
            match = re.search(pattern, content)
            
            current_params = ""
            if match:
                current_params = match.group(1)
            
            # Ensure audit parameters are present
            required_params = ["audit=1", "audit_backlog_limit=8192"]
            updated_params = current_params
            
            for param in required_params:
                if param not in updated_params:
                    updated_params = (updated_params + " " + param).strip()
                    changed = True
            
            if changed:
                if not dry_run:
                    # Update the file
                    new_content = re.sub(
                        pattern,
                        f'GRUB_CMDLINE_LINUX="{updated_params}"',
                        content
                    )
                    with open(grub_default, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    
                    # Regenerate grub configuration
                    cmd = ["grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"]
                    cp = run(cmd)
                    commands.append(shlex.join(cmd))
                    notes = f"Updated kernel parameters to: {updated_params}\n" + (cp.stdout + cp.stderr).strip()
                    ok = (cp.returncode == 0)
                else:
                    notes = f"DRY-RUN: Would update kernel parameters to: {updated_params}"
                    commands.append("grub2-mkconfig -o /boot/grub2/grub.cfg")
            else:
                notes = f"Audit kernel parameters already configured: {updated_params}"
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
    
    # Control: Ensure secure boot options in GRUB
    control_id = "BOOT-5"
    title = "Ensure GRUB kernel parameters are secure"
    changed = False
    ok = True
    notes = ""
    commands = []
    files = []
    
    try:
        # Check /proc/cmdline for security parameters
        kernel_params_file = "/proc/cmdline"
        desired_params = {
            "audit=1": "Auditd enabled",
        }
        
        if os.path.exists(kernel_params_file):
            with open(kernel_params_file, "r", encoding="utf-8") as f:
                current_params = f.read()
            
            missing = []
            for param, desc in desired_params.items():
                if param not in current_params:
                    missing.append(f"{param} ({desc})")
            
            if missing:
                notes = f"Missing kernel parameters: {', '.join(missing)}"
                notes += "\nTo apply, add to /etc/default/grub GRUB_CMDLINE_LINUX and run 'grub2-mkconfig -o /boot/grub2/grub.cfg'"
            else:
                notes = "Kernel parameters are secure"
        
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
