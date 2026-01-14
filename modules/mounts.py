from typing import List, Dict, Any
from .utils import ActionResult, run, write_file
import shlex
import os
import re

TMP_UNIT="/etc/systemd/system/tmp.mount"
VARTMP_UNIT="/etc/systemd/system/var-tmp.mount"

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results = []
    
    # Enable tmpfs mounts for /tmp and /var/tmp
    enable=bool(cfg.get("enable_tmp_mount_units", True))
    if not enable:
        results.append(ActionResult("MNT-0","tmpfs mount units (skipped by config)", False, True, notes="mounts.enable_tmp_mount_units=false"))
    else:
        tmp_size=str(cfg.get("tmp_size","1G"))
        vartmp_size=str(cfg.get("var_tmp_size","1G"))
        tmp_unit=f"""[Unit]
Description=Temporary Directory (/tmp)
Before=local-fs.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nodev,nosuid,noexec,size={tmp_size}

[Install]
WantedBy=local-fs.target
"""
        vartmp_unit=f"""[Unit]
Description=Temporary Directory (/var/tmp)
Before=local-fs.target

[Mount]
What=tmpfs
Where=/var/tmp
Type=tmpfs
Options=mode=1777,strictatime,nodev,nosuid,noexec,size={vartmp_size}

[Install]
WantedBy=local-fs.target
"""
        cmd=["bash","-lc", f"cat > {shlex.quote(TMP_UNIT)} <<'EOF'\n{tmp_unit}EOF\ncat > {shlex.quote(VARTMP_UNIT)} <<'EOF'\n{vartmp_unit}EOF\nsystemctl daemon-reload\nsystemctl enable --now tmp.mount var-tmp.mount"]
        if dry_run:
            results.append(ActionResult("MNT-1","Configure tmpfs mounts for /tmp and /var/tmp", True, True,
                                 notes="DRY-RUN: would create systemd mount units and enable them",
                                 commands=[shlex.join(cmd)], files=[TMP_UNIT,VARTMP_UNIT]))
        else:
            cp=run(cmd)
            results.append(ActionResult("MNT-1","Configure tmpfs mounts for /tmp and /var/tmp", True, cp.returncode==0,
                                         notes=(cp.stdout+cp.stderr).strip(), commands=[shlex.join(cmd)], files=[TMP_UNIT,VARTMP_UNIT]))

    # Control: Ensure noexec,nodev,nosuid on /dev/shm
    control_id = "MNT-2"
    title = "Ensure noexec,nodev,nosuid options on /dev/shm"
    
    fstab = "/etc/fstab"
    shm_options = "defaults,nodev,nosuid,noexec"
    
    try:
        if os.path.exists(fstab):
            with open(fstab, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Check if /dev/shm is already configured
            shm_pattern = r'^[^\s#]+\s+/dev/shm\s+'
            shm_match = re.search(shm_pattern, content, re.MULTILINE)
            
            new_content = content
            changed = False
            
            if shm_match:
                # Check if options are correct
                shm_line_pattern = r'^([^\s#]+\s+/dev/shm\s+\S+\s+)(\S+)(\s+.*)$'
                match = re.search(shm_line_pattern, content, re.MULTILINE)
                if match:
                    current_opts = match.group(2)
                    if not all(opt in current_opts for opt in ['noexec', 'nodev', 'nosuid']):
                        # Update the options
                        new_opts = shm_options
                        new_content = re.sub(shm_line_pattern, rf'\g<1>{new_opts}\g<3>', content, flags=re.MULTILINE)
                        changed = True
            else:
                # Add /dev/shm entry
                shm_entry = f"\ntmpfs\t/dev/shm\ttmpfs\t{shm_options}\t0 0\n"
                new_content = content.rstrip() + shm_entry
                changed = True
            
            if changed and not dry_run:
                with open(fstab, "w", encoding="utf-8") as f:
                    f.write(new_content)
                # Remount /dev/shm
                run(["mount", "-o", "remount", "/dev/shm"])
                results.append(ActionResult(control_id, title, True, True,
                                            notes="Updated /etc/fstab and remounted /dev/shm",
                                            files=[fstab]))
            elif changed:
                results.append(ActionResult(control_id, title, True, True,
                                            notes="DRY-RUN: Would update /dev/shm mount options in /etc/fstab",
                                            files=[fstab]))
            else:
                results.append(ActionResult(control_id, title, False, True,
                                            notes="/dev/shm already has noexec,nodev,nosuid options"))
        else:
            results.append(ActionResult(control_id, title, False, False,
                                        notes="/etc/fstab not found"))
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False,
                                    notes=f"Error: {str(e)}"))

    # Control: Ensure nodev,nosuid on /home
    control_id = "MNT-3"
    title = "Ensure nodev,nosuid options on /home partition"
    
    home_options = ["nodev", "nosuid"]
    
    try:
        if os.path.exists(fstab):
            with open(fstab, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            home_pattern = r'^([^\s#]+\s+/home\s+\S+\s+)(\S+)(\s+.*)$'
            match = re.search(home_pattern, content, re.MULTILINE)
            
            if match:
                current_opts = match.group(2)
                missing_opts = [opt for opt in home_options if opt not in current_opts]
                
                if missing_opts:
                    new_opts = current_opts + "," + ",".join(missing_opts)
                    new_content = re.sub(home_pattern, rf'\g<1>{new_opts}\g<3>', content, flags=re.MULTILINE)
                    
                    if not dry_run:
                        with open(fstab, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        run(["mount", "-o", "remount", "/home"])
                        results.append(ActionResult(control_id, title, True, True,
                                                    notes=f"Added {','.join(missing_opts)} to /home mount options",
                                                    files=[fstab]))
                    else:
                        results.append(ActionResult(control_id, title, True, True,
                                                    notes=f"DRY-RUN: Would add {','.join(missing_opts)} to /home",
                                                    files=[fstab]))
                else:
                    results.append(ActionResult(control_id, title, False, True,
                                                notes="/home already has nodev,nosuid options"))
            else:
                results.append(ActionResult(control_id, title, False, True,
                                            notes="/home partition not found in /etc/fstab (may not be separate partition)"))
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False,
                                    notes=f"Error: {str(e)}"))

    # Control: Ensure nodev,nosuid on /var
    control_id = "MNT-4"
    title = "Ensure nodev,nosuid options on /var partition"
    
    var_options = ["nodev", "nosuid"]
    
    try:
        if os.path.exists(fstab):
            with open(fstab, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            var_pattern = r'^([^\s#]+\s+/var\s+\S+\s+)(\S+)(\s+.*)$'
            match = re.search(var_pattern, content, re.MULTILINE)
            
            if match:
                current_opts = match.group(2)
                missing_opts = [opt for opt in var_options if opt not in current_opts]
                
                if missing_opts:
                    new_opts = current_opts + "," + ",".join(missing_opts)
                    new_content = re.sub(var_pattern, rf'\g<1>{new_opts}\g<3>', content, flags=re.MULTILINE)
                    
                    if not dry_run:
                        with open(fstab, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        run(["mount", "-o", "remount", "/var"])
                        results.append(ActionResult(control_id, title, True, True,
                                                    notes=f"Added {','.join(missing_opts)} to /var mount options",
                                                    files=[fstab]))
                    else:
                        results.append(ActionResult(control_id, title, True, True,
                                                    notes=f"DRY-RUN: Would add {','.join(missing_opts)} to /var",
                                                    files=[fstab]))
                else:
                    results.append(ActionResult(control_id, title, False, True,
                                                notes="/var already has nodev,nosuid options"))
            else:
                results.append(ActionResult(control_id, title, False, True,
                                            notes="/var partition not found in /etc/fstab (may not be separate partition)"))
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False,
                                    notes=f"Error: {str(e)}"))

    # Control: Ensure nodev on /var/log/audit
    control_id = "MNT-5"
    title = "Ensure nodev option on /var/log/audit partition"
    
    try:
        if os.path.exists(fstab):
            with open(fstab, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            audit_pattern = r'^([^\s#]+\s+/var/log/audit\s+\S+\s+)(\S+)(\s+.*)$'
            match = re.search(audit_pattern, content, re.MULTILINE)
            
            if match:
                current_opts = match.group(2)
                if "nodev" not in current_opts:
                    new_opts = current_opts + ",nodev"
                    new_content = re.sub(audit_pattern, rf'\g<1>{new_opts}\g<3>', content, flags=re.MULTILINE)
                    
                    if not dry_run:
                        with open(fstab, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        run(["mount", "-o", "remount", "/var/log/audit"])
                        results.append(ActionResult(control_id, title, True, True,
                                                    notes="Added nodev to /var/log/audit mount options",
                                                    files=[fstab]))
                    else:
                        results.append(ActionResult(control_id, title, True, True,
                                                    notes="DRY-RUN: Would add nodev to /var/log/audit",
                                                    files=[fstab]))
                else:
                    results.append(ActionResult(control_id, title, False, True,
                                                notes="/var/log/audit already has nodev option"))
            else:
                results.append(ActionResult(control_id, title, False, True,
                                            notes="/var/log/audit not in /etc/fstab - MANUAL: Create separate partition for /var/log/audit"))
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False,
                                    notes=f"Error: {str(e)}"))

    # Control: Check for separate /var/log partition
    control_id = "MNT-6"
    title = "Ensure separate partition for /var/log"
    
    try:
        if os.path.exists(fstab):
            with open(fstab, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            if re.search(r'^\S+\s+/var/log\s+', content, re.MULTILINE):
                results.append(ActionResult(control_id, title, False, True,
                                            notes="Separate partition for /var/log exists"))
            else:
                results.append(ActionResult(control_id, title, False, True,
                                            notes="MANUAL ACTION REQUIRED: Create separate partition for /var/log"))
    except Exception as e:
        results.append(ActionResult(control_id, title, False, False,
                                    notes=f"Error: {str(e)}"))

    return results
