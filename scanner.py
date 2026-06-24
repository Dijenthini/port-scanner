import socket
import threading
import time
from datetime import datetime
from vulnerabilities import parse_banner_for_vulnerabilities

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
    3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
}

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443]


def scan_port(target, port, timeout=1):
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_banner(target, port, timeout=3):
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        
        if port in [80, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port in [443, 8443]:
            sock.close()
            return "TLS (no raw banner)"
        elif port == 25:
            sock.send(b"EHLO test.com\r\n")
        elif port == 110:
            sock.send(b"CAPA\r\n")
        elif port == 143:
            sock.send(b"CAPABILITY\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if banner:
            banner = banner.split('\n')[0]
            banner = ''.join(c for c in banner if 32 <= ord(c) < 127)
            return banner[:150] + ("..." if len(banner) > 150 else "")

        return "No banner received"

    except Exception as e:
        return f"No banner ({str(e)[:40]})"


def scan_target_threaded(target, ports=None, progress_callback=None, max_threads=20):

    if ports is None:
        ports = DEFAULT_PORTS

    lock = threading.Lock()
    results = {}
    banners = {}
    services = {}
    vulnerabilities = {}
    completed_count = [0]

    total_ports = len(ports)
    print(f"\n🔍 Scanning target: {target} (multi-threaded, {max_threads} threads)")
    print(f"📡 Ports to scan: {ports}")
    print("=" * 50)

    start_time = datetime.now()

    def scan_worker(port):
        is_open = scan_port(target, port)

        if is_open:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(target, port)

            vuln_findings = []
            if banner and "No banner" not in banner and "TLS" not in banner:
                vuln_findings = parse_banner_for_vulnerabilities(banner, port)

            with lock:
                results[port] = True
                services[port] = service
                banners[port] = banner
                if vuln_findings:
                    vulnerabilities[port] = vuln_findings

                completed_count[0] += 1
                progress = int((completed_count[0] / total_ports) * 100)

            print(f"  ✅ Port {port}: OPEN ({service}) — {banner[:60]}")
            if vuln_findings:
                print(f"     ⚠️  {vuln_findings[0]['cve']} ({vuln_findings[0]['severity']})")

        else:
            with lock:
                results[port] = False
                completed_count[0] += 1
                progress = int((completed_count[0] / total_ports) * 100)

        if progress_callback:
            with lock:
                current_open = sorted(p for p, v in results.items() if v)
            progress_callback(progress, current_open)

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_worker, args=(port,), daemon=True)
        threads.append(t)
        t.start()

        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    open_ports = sorted(p for p, v in results.items() if v)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("=" * 50)
    print(f"✅ Scan complete in {duration:.2f}s — {len(open_ports)} open port(s): {open_ports}")

    return {
        'target': target,
        'open_ports': open_ports,
        'banners': banners,
        'services': services,
        'vulnerabilities': vulnerabilities,
        'duration': duration
    }


if __name__ == "__main__":
    print("=" * 60)
    print("  PORT SCANNER")
    print("=" * 60)

    target = input("\nEnter target IP or hostname (default: localhost): ").strip() or "localhost"

    result = scan_target_threaded(target)

    print("\n📋 Summary:")
    print(f"  Target : {result['target']}")
    print(f"  Ports  : {result['open_ports']}")
    print(f"  Time   : {result['duration']:.2f}s")

    print("\n📊 Service Details:")
    for port in result['open_ports']:
        service = result['services'].get(port, "Unknown")
        banner = result['banners'].get(port, "No banner")
        print(f"  Port {port}: {service} — {banner}")

    if result.get('vulnerabilities'):
        print("\n⚠️  Vulnerabilities Found:")
        for port, vulns in result['vulnerabilities'].items():
            for v in vulns:
                print(f"  Port {port}: {v['cve']} — {v['description']} ({v['severity']})")
    else:
        print("\n✅ No vulnerabilities detected")