# Async Port Scanner

Fast, dependency-free async TCP port scanner with banner grabbing and common-vuln annotations.

## Files

- `scan.py` — the scanner

## Usage

```bash
python scan.py --host scanme.example.com --ports 21,22,80,443,3306,8080 --timeout 1.5
```

Output:

```
Host: scanme.example.com (93.184.216.34)
 22/tcp  OPEN  ssh: OpenSSH 7.2p2 Ubuntu
 80/tcp  OPEN  http: nginx/1.16.1
[!] 22/tcp — possible default-admin risk on older OpenSSH builds
```

## Pitfalls

- Always get written authorization before scanning hosts you don't own. In many jurisdictions, unauthorized scanning is illegal. Use this on your own lab/VPS/CTF targets only.