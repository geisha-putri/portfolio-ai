"""
Async TCP port scanner with banner grab + quick vuln notes.
Usage: python scan.py --host <host> [--ports 22,80,443] [--timeout 1.0]
"""
import argparse
import asyncio
import socket

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

VULN_NOTES = {
    21: "FTP — consider vsftpd version check / anonymous login test",
    22: "SSH — older OpenSSH (<7.4) has known CVEs (CVE-2016-8859 family)",
    23: "Telnet — cleartext protocol, never expose",
    445: "SMB — EternalBlue class risks on unpatched Windows (MS17-010)",
    3306: "MySQL — check for default/blank root, CVE-2012-2122 DoS",
    3389: "RDP — BlueKeep (CVE-2019-0708) if unpatched",
    6379: "Redis — unauthenticated RCE if exposed without auth",
    9200: "Elasticsearch — CVE-2015-1427 RCE class if unauthenticated",
    27017: "MongoDB — unauthenticated access = data breach",
}


async def probe(host, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        banner = ""
        try:
            writer.write(b"\r\n")
            await writer.wait_closed() if False else None
            try:
                banner = (await asyncio.wait_for(reader.read(128), timeout)).decode(errors="ignore").strip()
            except Exception:
                banner = ""
        finally:
            writer.close()
        return port, True, banner
    except Exception:
        return port, False, ""


async def run(host, ports, timeout):
    results = []
    sem = asyncio.Semaphore(200)
    async def bounded(p):
        async with sem:
            return await probe(host, p, timeout)
    results = await asyncio.gather(*(bounded(p) for p in ports))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--ports", default=",".join(map(str, COMMON_PORTS)))
    ap.add_argument("--timeout", type=float, default=1.0)
    args = ap.parse_args()

    ports = [int(x) for x in args.ports.split(",") if x.strip()]
    print(f"Scanning {args.host} ({len(ports)} ports, timeout={args.timeout}s)...")
    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(run(args.host, ports, args.timeout))

    open_ports = [r for r in results if r[1]]
    for port, _, banner in open_ports:
        print(f" {port:>5}/tcp  OPEN  {banner[:60]}")
        note = VULN_NOTES.get(port)
        if note:
            print(f"        [!] {note}")
    if not open_ports:
        print(" No open ports found in the given range.")


if __name__ == "__main__":
    main()