from typing import List, Dict, Any
from .utils import ActionResult, ensure_pkg, ensure_service_enabled, write_file, run
import shlex

RULES = """## CIS baseline audit rules (starter)
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-e 2
"""

def apply(cfg: Dict[str,Any], dry_run: bool, profile: str):
    results=[]
    ensure_pkg(["audit","audit-libs"], dry_run, results, "AUD-1", "Install auditd")
    ensure_service_enabled("auditd", dry_run, results, "AUD-2", "Enable auditd")
    changed, note = write_file("/etc/audit/rules.d/99-cis-hardening.rules", RULES, mode=0o640, dry_run=dry_run)
    cmd=["augenrules","--load"]
    if dry_run:
        results.append(ActionResult("AUD-3","Install CIS audit rules and load", changed, True,
                                    notes=note+"\nDRY-RUN: would run "+shlex.join(cmd),
                                    commands=[shlex.join(cmd)], files=["/etc/audit/rules.d/99-cis-hardening.rules"]))
        return results
    cp=run(cmd); ok=(cp.returncode==0)
    results.append(ActionResult("AUD-3","Install CIS audit rules and load", changed, ok,
                                notes=note+"\n"+(cp.stdout+cp.stderr).strip(),
                                commands=[shlex.join(cmd)], files=["/etc/audit/rules.d/99-cis-hardening.rules"]))
    return results
