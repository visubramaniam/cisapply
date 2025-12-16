#!/usr/bin/env python3
import argparse, json, os, sys, importlib
from typing import Dict, Any
import yaml
from modules.utils import is_root

DEFAULT_CONFIG = "cis_config.yaml"

PROFILES = {
  "l1-server": ["kernel","sysctl","crypto","banners","ssh","sudo","services","packages","audit","logging","fileperms","firewalld"],
  "l2-server": ["kernel","sysctl","crypto","banners","ssh","sudo","services","packages","audit","logging","fileperms","firewalld",
                "selinux","auth","coredumps","cron","aide","mounts","ipv6"]
}

def load_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path,"r",encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def main():
    ap=argparse.ArgumentParser(description="CIS Oracle Enterprise Linux 9 hardening runner (Level 1/2)")
    ap.add_argument("--profile", choices=sorted(PROFILES.keys()), default="l1-server")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--report", default="")
    args=ap.parse_args()

    if not args.dry_run and not args.apply:
        args.dry_run = True

    if not is_root():
        print("ERROR: must run as root (sudo).", file=sys.stderr)
        sys.exit(2)

    cfg=load_config(args.config)
    results=[]
    overall_ok=True
    for modname in PROFILES[args.profile]:
        mod=importlib.import_module(f"modules.{modname}")
        res = mod.apply(cfg.get(modname, {}), dry_run=args.dry_run, profile=args.profile)
        results.extend(res)
        if any((not r.ok) for r in res):
            overall_ok=False

    report = {
        "profile": args.profile,
        "dry_run": args.dry_run,
        "host": os.uname().nodename,
        "results": [r.__dict__ for r in results],
        "ok": overall_ok
    }
    txt=json.dumps(report, indent=2)
    if args.report:
        with open(args.report,"w",encoding="utf-8") as f:
            f.write(txt+"\n")
        print(f"Wrote report to {args.report}")
    else:
        print(txt)
    sys.exit(0 if overall_ok else 1)

if __name__=="__main__":
    main()
