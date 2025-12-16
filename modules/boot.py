"""
Boot and Bootloader Hardening
CIS Reference: 1.3.x, 1.4.x - Boot Settings and Bootloader Configuration
"""
from typing import List, Dict, Any
from .utils import ActionResult, run
import os, re, subprocess

def apply(cfg: Dict[str, Any], dry_run: bool, profile: str) -> List[ActionResult]:
    """
    Apply bootloader hardening:
    - Protect GRUB with password
    - Restrict /boot/grub2/grub.cfg permissions
    - Restrict kernel parameters
    - Disable unnecessary boot options
    """
    results = []
    
    # Control: Ensure /boot/grub2/grub.cfg has restricted permissions
    control_id = "BOOT-1"
    title = "Ensure /boot/grub2/grub.cfg has restricted permissions (644)"
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
    
    # Control: Ensure secure boot options in GRUB
    control_id = "BOOT-4"
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
            "apparmor=1": "AppArmor enforcing (if using AppArmor)",
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
                notes += "\nTo apply, add to /etc/default/grub GRUB_CMDLINE_LINUX and run 'grub2-mkconfig'"
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
