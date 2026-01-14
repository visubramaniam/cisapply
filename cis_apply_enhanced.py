#!/usr/bin/env python3
"""
Enhanced CIS Oracle Enterprise Linux 9 Hardening Script
With improved error handling, validation, and control mapping
"""
import argparse, json, os, sys, importlib, logging
from typing import Dict, Any, List, Tuple
from datetime import datetime
import yaml
from modules.utils import is_root

DEFAULT_CONFIG = "cis_config.yaml"
LOG_LEVEL = os.environ.get("CIS_LOG_LEVEL", "INFO")

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('/var/log/cis_apply.log'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Map internal control IDs to CIS Benchmark control numbers
CONTROL_MAPPING = {
    # Kernel and Boot Security
    "KERN-1": "1.1.1-1.1.24",
    "SYSCTL-1": "3.1.1-3.3.2",
    
    # Cryptography
    "CRYPTO-1": "1.5.1",
    
    # Access Control
    "BANNER-1": "5.4.4",
    "SSH-1": "5.2.1-5.2.21",
    "SUDO-1": "5.3.7",
    
    # Service Management
    "SVC-avahi-daemon": "2.1.1",
    "SVC-cups": "2.2.1",
    "SVC-dhcpd": "2.1.2",
    "SVC-slapd": "2.1.3",
    "SVC-nfs-server": "2.1.4",
    "SVC-rpcbind": "2.1.5",
    "SVC-smb": "2.2.2",
    "SVC-snmpd": "2.2.3",
    "SVC-rsyncd": "2.2.4",
    "SVC-ypserv": "2.1.6",
    "SVC-telnet.socket": "2.3.1",
    "SVC-tftp.socket": "2.3.2",
    
    # Package Management
    "PKG-1": "2.4.1-2.4.2",
    
    # Audit and Logging
    "AUD-1": "4.1.1",
    "AUD-2": "4.1.2",
    "AUD-3": "4.1.3-4.1.18",
    "LOG-1": "4.2.2.1",
    "LOG-2": "4.2.1.1",
    "LOG-3": "4.2.1.2",
    
    # File Integrity and Permissions
    "PERM-1": "5.6.1-5.6.5",
    "AIDE-1": "6.2.1",
    "AIDE-2": "6.2.1",
    
    # Firewall and Network
    "FW-1": "3.4.1",
    "FW-2": "3.4.2",
    "FW-3": "3.4.3-3.4.4",
    
    # SELinux and MAC
    "SEL-1": "1.6.1",
    
    # Authentication and Authorization
    "AUTH-1": "5.4.1",
    "AUTH-2": "5.4.2",
    "AUTH-3": "5.4.5",
    "AUTH-4": "5.4.6",
    
    # System Limits
    "CORE-1": "1.5.3",
    "CRON-1": "5.1.1",
    "CRON-2": "5.1.2",
    "CRON-3": "5.1.3-5.1.5",
    
    # Mount Points
    "MNT-1": "1.4.2",
    
    # IPv6
    "IPV6-0": "3.3.1-3.3.2",
    
    # PAM Controls
    "PAM-1": "5.3.1",
    "PAM-2": "5.3.2",
    "PAM-3": "5.4.4",
    "PAM-4": "5.3.3",
    
    # Boot Hardening
    "BOOT-1": "1.4.1",
    "BOOT-2": "1.4.2",
    "BOOT-3": "1.4.3",
    "BOOT-4": "1.3.1",
    "BOOT-5": "1.3.2",
    
    # TCP Wrappers
    "TCP-1": "3.4.1",
    "TCP-2": "3.4.2",
    "TCP-3": "3.4.3",
    
    # DNF/Package Manager Security
    "DNF-1": "1.2.1",
    "DNF-2": "1.2.2",
    "DNF-3": "1.2.3",
    
    # Postfix/Mail
    "MAIL-1": "2.2.14",
    "MAIL-2": "2.2.15",
}

# Module dependencies for proper ordering
MODULE_DEPENDENCIES = {
    "sysctl": ["kernel"],
    "ssh": ["crypto"],
    "auth": ["pam"],
    "firewalld": ["services"],
}

PROFILES = {
    "l1-server": [
        "kernel",
        "sysctl",
        "crypto",
        "banners",
        "ssh",
        "sudo",
        "services",
        "packages",
        "audit",
        "logging",
        "fileperms",
        "firewalld"
    ],
    "l2-server": [
        "kernel",
        "sysctl",
        "crypto",
        "banners",
        "ssh",
        "sudo",
        "services",
        "packages",
        "audit",
        "logging",
        "fileperms",
        "firewalld",
        "selinux",
        "auth",
        "coredumps",
        "cron",
        "aide",
        "mounts",
        "ipv6",
        "pam",
        "boot",
        "tcpwrappers",
        "dnf",
        "postfix"
    ],
    "l2-workstation": [
        "kernel",
        "sysctl",
        "crypto",
        "banners",
        "ssh",
        "sudo",
        "services",
        "packages",
        "audit",
        "logging",
        "fileperms",
        "firewalld",
        "selinux",
        "auth",
        "coredumps",
        "cron",
        "aide",
        "mounts",
        "ipv6",
        "pam",
        "boot",
        "tcpwrappers",
        "dnf"
    ],
    "l3-server": [
        "kernel",
        "sysctl",
        "crypto",
        "banners",
        "ssh",
        "sudo",
        "services",
        "packages",
        "audit",
        "logging",
        "fileperms",
        "firewalld",
        "selinux",
        "auth",
        "coredumps",
        "cron",
        "aide",
        "mounts",
        "ipv6",
        "pam",
        "boot",
        "tcpwrappers",
        "dnf",
        "postfix"
    ]
}

def load_config(path: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    if not os.path.exists(path):
        logger.warning(f"Config file not found: {path}, using defaults")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {path}")
            return cfg
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return {}

def get_system_info() -> Dict[str, str]:
    """Gather system information for reporting"""
    return {
        "hostname": os.uname().nodename,
        "kernel": os.uname().release,
        "machine": os.uname().machine,
        "timestamp": datetime.now().isoformat(),
    }

def apply_modules(profile: str, cfg: Dict[str, Any], dry_run: bool) -> Tuple[List[Any], bool]:
    """
    Apply all modules in the specified profile
    Returns: (results_list, overall_ok)
    """
    results = []
    overall_ok = True
    module_list = PROFILES.get(profile, [])
    
    logger.info(f"Starting {profile} hardening {'(DRY-RUN)' if dry_run else '(APPLY)'}")
    logger.info(f"Will apply {len(module_list)} modules")
    
    for modname in module_list:
        try:
            logger.info(f"Loading module: {modname}")
            mod = importlib.import_module(f"modules.{modname}")
            res = mod.apply(cfg.get(modname, {}), dry_run=dry_run, profile=profile)
            
            # Add CIS control mapping
            for r in res:
                if hasattr(r, 'id') and r.id in CONTROL_MAPPING:
                    if not hasattr(r, 'cis_control'):
                        r.cis_control = CONTROL_MAPPING[r.id]
            
            results.extend(res)
            
            # Check if any control failed
            if any((not r.ok) for r in res):
                overall_ok = False
                logger.error(f"Module {modname} had failures")
            else:
                logger.info(f"Module {modname} completed successfully")
                
        except ImportError as e:
            logger.error(f"Failed to import module {modname}: {e}")
            overall_ok = False
        except Exception as e:
            logger.error(f"Error applying module {modname}: {e}")
            overall_ok = False
    
    return results, overall_ok

def generate_report(
    profile: str,
    dry_run: bool,
    results: List[Any],
    overall_ok: bool,
    system_info: Dict[str, str]
) -> Dict[str, Any]:
    """Generate comprehensive compliance report"""
    
    # Categorize results
    passed = sum(1 for r in results if r.ok)
    failed = sum(1 for r in results if not r.ok)
    remediated = sum(1 for r in results if r.changed and r.ok)
    
    # Calculate compliance percentage
    total = len(results)
    compliance = (passed / total * 100) if total > 0 else 0
    
    report = {
        "metadata": {
            **system_info,
            "cis_benchmark": "Oracle Linux 9 v2.0.0",
            "script_version": "2.0",
        },
        "profile": profile,
        "dry_run": dry_run,
        "execution": {
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "compliance_percentage": round(compliance, 1),
        },
        "remediation": {
            "remediated": remediated,
            "already_compliant": passed - remediated,
            "failed": failed,
        },
        "results": [r.__dict__ if hasattr(r, '__dict__') else r for r in results],
        "ok": overall_ok,
    }
    
    return report

def save_report(report: Dict[str, Any], report_path: str) -> bool:
    """Save report to JSON file"""
    try:
        os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"Report saved to {report_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save report to {report_path}: {e}")
        return False

def print_summary(report: Dict[str, Any]):
    """Print compliance summary to console"""
    exec_data = report.get("execution", {})
    total = exec_data.get("total_controls", 0)
    passed = exec_data.get("passed", 0)
    failed = exec_data.get("failed", 0)
    compliance = exec_data.get("compliance_percentage", 0)
    
    print(f"\n{'='*60}")
    print(f"CIS {report.get('profile', 'unknown').upper()} Hardening Report")
    print(f"{'='*60}")
    print(f"Total Controls:        {total}")
    print(f"Passed:                {passed}")
    print(f"Failed:                {failed}")
    print(f"Compliance:            {compliance}%")
    print(f"Overall Status:        {'✅ PASS' if report.get('ok') else '❌ FAIL'}")
    print(f"{'='*60}\n")
    
    # Show remediation summary
    if not report.get('dry_run'):
        remediation = report.get("remediation", {})
        print(f"Remediation Summary:")
        print(f"  Remediated:          {remediation.get('remediated', 0)}")
        print(f"  Already Compliant:   {remediation.get('already_compliant', 0)}")
        print(f"  Failed:              {remediation.get('failed', 0)}")
        print(f"{'='*60}\n")
    
    # Show reboot requirements if any
    reboot_required = report.get("reboot_required", False)
    if reboot_required:
        print("⚠️  REBOOT REQUIRED: Some changes require a system reboot to take effect.")
        print(f"{'='*60}\n")

def generate_html_report(report: Dict[str, Any], html_path: str) -> bool:
    """Generate HTML compliance report"""
    try:
        exec_data = report.get("execution", {})
        total = exec_data.get("total_controls", 0)
        passed = exec_data.get("passed", 0)
        failed = exec_data.get("failed", 0)
        compliance = exec_data.get("compliance_percentage", 0)
        remediation = report.get("remediation", {})
        
        # Generate status color
        status_color = "#28a745" if report.get("ok") else "#dc3545"
        compliance_color = "#28a745" if compliance >= 90 else ("#ffc107" if compliance >= 70 else "#dc3545")
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Compliance Report - {report.get('profile', 'unknown').upper()}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #0066cc; }}
        .card.passed {{ border-left-color: #28a745; }}
        .card.failed {{ border-left-color: #dc3545; }}
        .card.remediated {{ border-left-color: #17a2b8; }}
        .card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; text-transform: uppercase; }}
        .card .value {{ font-size: 36px; font-weight: bold; color: #333; }}
        .status {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; background: {status_color}; }}
        .compliance {{ font-size: 48px; font-weight: bold; color: {compliance_color}; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .pass {{ color: #28a745; }}
        .fail {{ color: #dc3545; }}
        .changed {{ color: #17a2b8; font-weight: bold; }}
        .metadata {{ color: #666; font-size: 14px; margin-bottom: 20px; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CIS Compliance Report</h1>
        <div class="metadata">
            <strong>Profile:</strong> {report.get('profile', 'unknown').upper()} |
            <strong>Hostname:</strong> {report.get('metadata', {}).get('hostname', 'N/A')} |
            <strong>Generated:</strong> {report.get('metadata', {}).get('timestamp', 'N/A')} |
            <strong>Benchmark:</strong> {report.get('metadata', {}).get('cis_benchmark', 'N/A')}
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <div class="compliance">{compliance}%</div>
            <div style="color: #666; margin-top: 5px;">Compliance Score</div>
            <div style="margin-top: 15px;">
                <span class="status">{'PASS' if report.get('ok') else 'FAIL'}</span>
            </div>
        </div>
        
        <div class="summary">
            <div class="card">
                <h3>Total Controls</h3>
                <div class="value">{total}</div>
            </div>
            <div class="card passed">
                <h3>Passed</h3>
                <div class="value">{passed}</div>
            </div>
            <div class="card failed">
                <h3>Failed</h3>
                <div class="value">{failed}</div>
            </div>
            <div class="card remediated">
                <h3>Remediated</h3>
                <div class="value">{remediation.get('remediated', 0)}</div>
            </div>
        </div>
        
        <h2>Control Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Control ID</th>
                    <th>CIS Ref</th>
                    <th>Title</th>
                    <th>Changed</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for r in report.get("results", []):
            status_icon = "✅" if r.get("ok") else "❌"
            status_class = "pass" if r.get("ok") else "fail"
            changed_text = "Yes" if r.get("changed") else "No"
            changed_class = "changed" if r.get("changed") else ""
            cis_ref = r.get("cis_control", CONTROL_MAPPING.get(r.get("id", ""), "N/A"))
            notes = r.get("notes", "")[:100] + ("..." if len(r.get("notes", "")) > 100 else "")
            
            html_content += f"""                <tr>
                    <td class="{status_class}">{status_icon}</td>
                    <td><code>{r.get('id', 'N/A')}</code></td>
                    <td>{cis_ref}</td>
                    <td>{r.get('title', 'N/A')}</td>
                    <td class="{changed_class}">{changed_text}</td>
                    <td>{notes}</td>
                </tr>
"""
        
        html_content += f"""            </tbody>
        </table>
        
        <div class="footer">
            Generated by CIS Oracle Linux 9 Hardening Tool v2.0 |
            Mode: {'DRY-RUN' if report.get('dry_run') else 'APPLY'} |
            Kernel: {report.get('metadata', {}).get('kernel', 'N/A')}
        </div>
    </div>
</body>
</html>
"""
        
        os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {html_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        return False

def detect_drift(profile: str, cfg: Dict[str, Any], baseline_path: str) -> Dict[str, Any]:
    """
    Compare current system state with a baseline report.
    Returns drift information.
    """
    drift_results = {
        "has_drift": False,
        "drifted_controls": [],
        "new_failures": [],
        "new_passes": [],
        "baseline_timestamp": None,
        "current_timestamp": datetime.now().isoformat(),
    }
    
    if not os.path.exists(baseline_path):
        logger.warning(f"Baseline file not found: {baseline_path}")
        return {"error": "Baseline file not found", "has_drift": None}
    
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        
        drift_results["baseline_timestamp"] = baseline.get("metadata", {}).get("timestamp")
        
        # Run current state check (dry-run mode)
        current_results, _ = apply_modules(profile, cfg, dry_run=True)
        
        # Build lookup for baseline results
        baseline_by_id = {}
        for r in baseline.get("results", []):
            r_id = r.get("id") or r.get("control_id")
            if r_id:
                baseline_by_id[r_id] = r
        
        # Compare current with baseline
        for current in current_results:
            control_id = current.id if hasattr(current, 'id') else current.get('id')
            current_ok = current.ok if hasattr(current, 'ok') else current.get('ok')
            
            if control_id in baseline_by_id:
                baseline_ok = baseline_by_id[control_id].get("ok")
                
                if baseline_ok != current_ok:
                    drift_results["has_drift"] = True
                    drift_results["drifted_controls"].append({
                        "id": control_id,
                        "title": current.title if hasattr(current, 'title') else current.get('title'),
                        "baseline_status": "pass" if baseline_ok else "fail",
                        "current_status": "pass" if current_ok else "fail",
                    })
                    
                    if baseline_ok and not current_ok:
                        drift_results["new_failures"].append(control_id)
                    elif not baseline_ok and current_ok:
                        drift_results["new_passes"].append(control_id)
        
        return drift_results
        
    except Exception as e:
        logger.error(f"Error detecting drift: {e}")
        return {"error": str(e), "has_drift": None}

def validate_permissions():
    """Ensure script runs with sufficient privileges"""
    if not is_root():
        logger.error("This script must run as root (use sudo)")
        print("ERROR: must run as root (sudo).", file=sys.stderr)
        sys.exit(2)

def main():
    ap = argparse.ArgumentParser(
        description="CIS Oracle Enterprise Linux 9 Hardening Tool",
        epilog="Examples:\n"
               "  sudo ./cis_apply_enhanced.py --profile l2-server --dry-run --report /tmp/report.json\n"
               "  sudo ./cis_apply_enhanced.py --profile l2-server --apply --report /tmp/report.json\n"
               "  sudo ./cis_apply_enhanced.py --profile l2-server --detect-drift --baseline /tmp/baseline.json\n"
               "  sudo ./cis_apply_enhanced.py --profile l2-server --apply --html-report /tmp/report.html\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    ap.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        default="l1-server",
        help="Hardening profile (default: l1-server)"
    )
    ap.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help=f"Configuration file (default: {DEFAULT_CONFIG})"
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in dry-run mode (no changes applied)"
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Apply hardening (requires confirmation)"
    )
    ap.add_argument(
        "--report",
        default="",
        help="Save report to JSON file"
    )
    ap.add_argument(
        "--html-report",
        default="",
        help="Save report to HTML file"
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="Verify compliance without applying changes"
    )
    ap.add_argument(
        "--detect-drift",
        action="store_true",
        help="Detect configuration drift from baseline"
    )
    ap.add_argument(
        "--baseline",
        default="",
        help="Baseline JSON report for drift detection"
    )
    ap.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default=LOG_LEVEL,
        help=f"Logging level (default: {LOG_LEVEL})"
    )
    
    args = ap.parse_args()
    
    # Set logging level
    logger.setLevel(getattr(logging, args.log_level))
    
    # Validate mode selection
    if not args.dry_run and not args.apply and not args.verify and not args.detect_drift:
        args.dry_run = True
        logger.info("No mode specified; defaulting to --dry-run")
    
    # Validate permissions
    validate_permissions()
    
    # Load configuration
    cfg = load_config(args.config)
    
    # Get system information
    sys_info = get_system_info()
    
    # Handle drift detection mode
    if args.detect_drift:
        if not args.baseline:
            print("ERROR: --baseline required for drift detection", file=sys.stderr)
            sys.exit(1)
        
        drift = detect_drift(args.profile, cfg, args.baseline)
        
        if drift.get("error"):
            print(f"ERROR: {drift['error']}", file=sys.stderr)
            sys.exit(1)
        
        print(f"\n{'='*60}")
        print("Drift Detection Report")
        print(f"{'='*60}")
        print(f"Baseline: {args.baseline}")
        print(f"Baseline Timestamp: {drift.get('baseline_timestamp', 'N/A')}")
        print(f"Current Timestamp:  {drift.get('current_timestamp', 'N/A')}")
        print(f"Drift Detected:     {'YES' if drift.get('has_drift') else 'NO'}")
        
        if drift.get("has_drift"):
            print(f"\nDrifted Controls ({len(drift.get('drifted_controls', []))}):")
            for d in drift.get("drifted_controls", []):
                print(f"  {d['id']:20} {d['baseline_status']} -> {d['current_status']} : {d['title']}")
            
            if drift.get("new_failures"):
                print(f"\n⚠️  New Failures: {', '.join(drift['new_failures'])}")
            if drift.get("new_passes"):
                print(f"\n✅ New Passes: {', '.join(drift['new_passes'])}")
        
        print(f"{'='*60}\n")
        sys.exit(0 if not drift.get("has_drift") else 1)
    
    # Apply hardening
    results, overall_ok = apply_modules(args.profile, cfg, dry_run=args.dry_run or args.verify)
    
    # Generate report
    report = generate_report(args.profile, args.dry_run or args.verify, results, overall_ok, sys_info)
    
    # Save JSON report if specified
    if args.report:
        save_report(report, args.report)
    
    # Save HTML report if specified
    if args.html_report:
        generate_html_report(report, args.html_report)
    
    # Print summary
    print_summary(report)
    
    # Print results (compact)
    print("Control Results:")
    for r in results:
        status = "✅" if r.ok else "❌"
        changed = "*" if r.changed else " "
        r_id = r.id if hasattr(r, 'id') else "UNKNOWN"
        title = r.title if hasattr(r, 'title') else "Unknown"
        print(f"  {status} {changed} {r_id:20} {title}")
    
    sys.exit(0 if overall_ok else 1)

if __name__ == "__main__":
    main()
