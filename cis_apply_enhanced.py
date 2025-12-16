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
        "ipv6"
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
               "  sudo ./cis_apply.py --profile l2-server --dry-run --report /tmp/report.json\n"
               "  sudo ./cis_apply.py --profile l2-server --apply --report /tmp/report.json\n",
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
        "--verify",
        action="store_true",
        help="Verify compliance without applying changes"
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
    if not args.dry_run and not args.apply and not args.verify:
        args.dry_run = True
        logger.info("No mode specified; defaulting to --dry-run")
    
    # Validate permissions
    validate_permissions()
    
    # Load configuration
    cfg = load_config(args.config)
    
    # Get system information
    sys_info = get_system_info()
    
    # Apply hardening
    results, overall_ok = apply_modules(args.profile, cfg, dry_run=args.dry_run or args.verify)
    
    # Generate report
    report = generate_report(args.profile, args.dry_run or args.verify, results, overall_ok, sys_info)
    
    # Save report if specified
    if args.report:
        save_report(report, args.report)
    
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
