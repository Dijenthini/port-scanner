import socket
import threading
import time
from datetime import datetime
from vulnerabilities import parse_banner_for_vulnerabilities


COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    135: 'RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt'
}


DEFAULT_PORTS = [22, 80, 443, 3306, 3389, 21, 25, 53, 110, 139, 445, 8080, 8443]

def scan_port(target, port, timeout=1):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def grab_banner(target, port, timeout=3):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        
        if port in [80, 443, 8080, 8443]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port == 21:  
            pass
        elif port == 22:  
            pass
        elif port == 25:  
            sock.send(b"EHLO test.com\r\n")
        elif port == 110:  
            sock.send(b"CAPA\r\n")
        elif port == 143:  
            sock.send(b"CAPABILITY\r\n")
        elif port == 3306:  
            pass
        else:
            sock.send(b"\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner:
            banner = banner.split('\n')[0]
            banner = ''.join(c for c in banner if 32 <= ord(c) < 127 or c == ' ')
            if len(banner) > 150:
                banner = banner[:150] + "..."
        else:
            banner = "No banner received"
        
        return banner
    except Exception as e:
        return f"No banner (error: {str(e)[:30]})"

def scan_target(target, ports=None, progress_callback=None):

    if ports is None:
        ports = DEFAULT_PORTS
    
    open_ports = []
    banners = {}
    services = {}
    vulnerabilities = {}
    
    total_ports = len(ports)
    print(f"\n🔍 Scanning target: {target}")
    print(f"📡 Scanning {total_ports} common ports...")
    print("=" * 50)
    
    start_time = datetime.now()
    
    for idx, port in enumerate(ports):
        if scan_port(target, port):
            open_ports.append(port)
            services[port] = COMMON_PORTS.get(port, "Unknown")
            banners[port] = grab_banner(target, port)
            print(f"✅ Port {port}: OPEN ({services[port]})")
            
            
            if banners[port] != "No banner received":
                vuln_findings = parse_banner_for_vulnerabilities(banners[port], port)
                if vuln_findings:
                    vulnerabilities[port] = vuln_findings
                    print(f"  ⚠️  Vulnerability found on port {port}: {vuln_findings[0]['cve']}")
        else:
            progress = int(((idx + 1) / total_ports) * 100)
            print(f"⏳ Progress: {progress}%", end="\r")
        
        if progress_callback:
            progress = int(((idx + 1) / total_ports) * 100)
            progress_callback(progress, open_ports.copy())
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 50)
    print(f"✅ Scan complete in {duration:.2f} seconds")
    print(f"📊 Found {len(open_ports)} open ports")
    
    return {
        'target': target,
        'open_ports': open_ports,
        'banners': banners,
        'services': services,
        'vulnerabilities': vulnerabilities,
        'duration': duration
    }

def scan_target_threaded(target, ports=None, progress_callback=None, max_threads=20):

    if ports is None:
        ports = DEFAULT_PORTS
    
    open_ports = []
    banners = {}
    services = {}
    results = {}
    vulnerabilities = {}
    
    print(f"\n🔍 Scanning target: {target} (Multi-threaded)")
    print(f"📡 Scanning {len(ports)} ports with {max_threads} threads...")
    print("=" * 50)
    
    start_time = datetime.now()
    
    def scan_worker(port):
        is_open = scan_port(target, port)
        results[port] = is_open
        if is_open:
            services[port] = COMMON_PORTS.get(port, "Unknown")
            banners[port] = grab_banner(target, port)
            print(f"✅ Port {port}: OPEN ({services[port]})")
            
            
            if banners[port] != "No banner received":
                vuln_findings = parse_banner_for_vulnerabilities(banners[port], port)
                if vuln_findings:
                    vulnerabilities[port] = vuln_findings
                    print(f"  ⚠️  Vulnerability found on port {port}: {vuln_findings[0]['cve']}")
    
    
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_worker, args=(port,))
        threads.append(thread)
        thread.start()
        
        
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []
    
    
    for thread in threads:
        thread.join()
    
    
    open_ports = []
    for port, is_open in results.items():
        if is_open:
            open_ports.append(port)
            print(f"✅ Port {port}: OPEN ({services.get(port, 'Unknown')})")
    
    open_ports.sort()
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("=" * 50)
    print(f"✅ Scan complete in {duration:.2f} seconds")
    print(f"📊 Found {len(open_ports)} open ports")
    
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
    print("  PORT SCANNER TEST")
    print("=" * 60)
    
    target = input("\nEnter target IP or hostname (default: localhost): ") or "localhost"
    
    print("\n--- Testing Multi-threaded Scan ---")
    result = scan_target_threaded(target)
    
    print("\n📋 Summary:")
    print(f"  Target: {result['target']}")
    print(f"  Open Ports: {result['open_ports']}")
    print(f"  Duration: {result['duration']:.2f} seconds")
    
    print("\n📊 Service Details:")
    for port in result['open_ports']:
        service = result['services'].get(port, "Unknown")
        banner = result['banners'].get(port, "No banner")
        print(f"  Port {port}: {service} - {banner}")
    
    if result.get('vulnerabilities'):
        print("\n⚠️ Vulnerabilities Found:")
        for port, vulns in result['vulnerabilities'].items():
            for vuln in vulns:
                print(f"  Port {port}: {vuln['cve']} - {vuln['description']} ({vuln['severity']})")
    else:
        print("\n✅ No vulnerabilities detected")