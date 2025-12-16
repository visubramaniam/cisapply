# CIS Oracle Enterprise Linux 9 Hardening (Python)

## Usage
```bash
sudo ./cis_apply.py --profile l1-server --dry-run --report /root/cis-l1.json
sudo ./cis_apply.py --profile l1-server --apply   --report /root/cis-l1.json

sudo ./cis_apply.py --profile l2-server --dry-run --report /root/cis-l2.json
sudo ./cis_apply.py --profile l2-server --apply   --report /root/cis-l2.json
```

## Firewalld
This bundle is pre-configured to allowlist **ssh** and **https** in `cis_config.yaml`.
