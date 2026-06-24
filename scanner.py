import socket
import threading
from datetime import datetime
from vulnerabilities import parse_banner_for_vulnerabilities   


COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
    3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    20: 'FTP-Data', 69: 'TFTP', 79: 'Finger', 109: 'POP2',
    111: 'RPCBind', 119: 'NNTP', 123: 'NTP', 137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM', 161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP',
    194: 'IRC', 389: 'LDAP', 427: 'SLP', 465: 'SMTPS',
    500: 'IKE', 514: 'Syslog', 515: 'LPD', 543: 'Klogin',
    544: 'Kshell', 587: 'SMTP-Submit', 631: 'IPP', 636: 'LDAPS',
    873: 'rsync', 902: 'VMware', 989: 'FTPS-Data', 990: 'FTPS',
    1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL', 1434: 'MSSQL-UDP',
    1521: 'Oracle', 1701: 'L2TP', 1812: 'RADIUS', 2049: 'NFS',
    2082: 'cPanel', 2083: 'cPanel-SSL', 2086: 'WHM', 2087: 'WHM-SSL',
    2181: 'ZooKeeper', 2375: 'Docker', 2376: 'Docker-TLS',
    3000: 'Dev-Server', 3001: 'Dev-Server-Alt', 3128: 'Squid',
    3268: 'LDAP-GC', 3269: 'LDAPS-GC', 4444: 'Metasploit',
    4848: 'GlassFish', 5000: 'Flask/UPnP', 5432: 'PostgreSQL',
    5631: 'pcAnywhere', 5900: 'VNC', 5985: 'WinRM-HTTP',
    5986: 'WinRM-HTTPS', 6379: 'Redis', 6443: 'Kubernetes',
    7001: 'WebLogic', 7002: 'WebLogic-SSL', 8000: 'HTTP-Dev',
    8008: 'HTTP-Alt2', 8009: 'AJP', 8161: 'ActiveMQ',
    8443: 'HTTPS-Alt', 8888: 'Jupyter', 9000: 'SonarQube/PHP-FPM',
    9090: 'Prometheus', 9200: 'Elasticsearch', 9300: 'Elasticsearch-Cluster',
    9418: 'Git', 10000: 'Webmin', 11211: 'Memcached',
    27017: 'MongoDB', 27018: 'MongoDB-Shard', 50000: 'SAP',
}


QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143,
    443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443
]

FULL_PORTS = list(range(1, 1025))   


def get_ports_for_mode(mode):

    if mode == 'full':
        return FULL_PORTS
    return QUICK_PORTS   


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

        if port in [80, 8080, 8000, 8008]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port in [443, 8443, 990, 989]:
            sock.close()
            return "TLS (no raw banner)"
        elif port == 25 or port == 587:
            sock.send(b"EHLO test.com\r\n")
        elif port == 110:
            sock.send(b"CAPA\r\n")
        elif port == 143:
            sock.send(b"CAPABILITY\r\n")
        elif port == 21:
            pass   
        elif port == 22:
            pass   
        elif port == 3306:
            pass   
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if banner:
            banner = banner.split('\n')[0]
            banner = ''.join(c for c in banner if 32 <= ord(c) < 127)
            return banner[:150] + ("..." if len(banner) > 150 else "")

        return "No banner received"

    except Exception as e:
        return f"No banner ({str(e)[:40]})"


def scan_target_threaded(target, ports=None, progress_callback=None, max_threads=50, live_ref=None):

    if ports is None:
        ports = QUICK_PORTS

    lock            = threading.Lock()
    results         = {}
    banners         = {}
    services        = {}
    vulnerabilities = {}
    completed_count = [0]
    total_ports     = len(ports)

    print(f"\n🔍 Scanning {target} — {total_ports} ports, {max_threads} threads")
    print("=" * 50)
    start_time = datetime.now()

    def scan_worker(port):
        is_open = scan_port(target, port)

        
        port_service = None
        port_banner  = None
        port_vulns   = []

        if is_open:
            port_service = COMMON_PORTS.get(port, "Unknown")
            port_banner  = grab_banner(target, port)

            if port_banner and "No banner" not in port_banner and "TLS" not in port_banner:
                port_vulns = parse_banner_for_vulnerabilities(port_banner, port)

            print(f"  ✅ Port {port}: OPEN ({port_service}) — {port_banner[:60]}")
            if port_vulns:
                print(f"     ⚠️  {port_vulns[0]['cve']} ({port_vulns[0]['severity']})")

    
        with lock:
            results[port] = is_open
            if is_open:
                services[port] = port_service
                banners[port]  = port_banner
                if port_vulns:
                    vulnerabilities[port] = port_vulns
            completed_count[0] += 1
            progress     = int((completed_count[0] / total_ports) * 100)
            current_open = sorted(p for p, v in results.items() if v)
            
            if live_ref is not None:
                live_ref['banners']         = dict(banners)
                live_ref['vulnerabilities'] = dict(vulnerabilities)

        
        if progress_callback:
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
    duration   = (datetime.now() - start_time).total_seconds()

    print("=" * 50)
    print(f"✅ Done in {duration:.2f}s — {len(open_ports)} open: {open_ports}")

    return {
        'target':          target,
        'open_ports':      open_ports,
        'banners':         banners,
        'services':        services,
        'vulnerabilities': vulnerabilities,
        'duration':        duration
    }



if __name__ == "__main__":
    print("=" * 60)
    print("  PORT SCANNER")
    print("=" * 60)

    target = input("\nTarget IP or hostname (default: localhost): ").strip() or "localhost"
    mode   = input("Scan mode — quick / full (default: quick): ").strip() or "quick"
    ports  = get_ports_for_mode(mode)

    print(f"\nMode: {mode.upper()} — scanning {len(ports)} ports")
    result = scan_target_threaded(target, ports)

    print("\n📋 Summary:")
    print(f"  Target : {result['target']}")
    print(f"  Ports  : {result['open_ports']}")
    print(f"  Time   : {result['duration']:.2f}s")

    for port in result['open_ports']:
        service = result['services'].get(port, "Unknown")
        banner  = result['banners'].get(port, "No banner")
        print(f"  Port {port}: {service} — {banner}")

    if result.get('vulnerabilities'):
        print("\n⚠️  Vulnerabilities:")
        for port, vulns in result['vulnerabilities'].items():
            for v in vulns:
                print(f"  Port {port}: {v['cve']} — {v['description']} ({v['severity']})")
    else:
        print("\n✅ No vulnerabilities detected")