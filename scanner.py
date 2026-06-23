from vulnerabilities import parse_banner_for_vulnerabilities
import socket
import threading
import time
from datetime import datetime

# Common ports and their services
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

# Ports to scan (ordered by commonality)
DEFAULT_PORTS = [22, 80, 443, 3306, 3389, 21, 25, 53, 110, 139, 445, 8080, 8443]

def scan_port(target, port, timeout=1):
    """
    Check if a single port is open on the target.
    
    Args:
        target (str): IP address or hostname
        port (int): Port number to check
        timeout (int): Timeout in seconds
    
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Attempt to connect
        result = sock.connect_ex((target, port))
        sock.close()
        
        # connect_ex returns 0 if successful
        return result == 0
    except Exception as e:
        # Any error means the port is closed or unreachable
        return False

def grab_banner(target, port, timeout=3):
    """
    Attempt to grab a service banner from an open port.
    
    Args:
        target (str): IP address or hostname
        port (int): Port number
        timeout (int): Timeout in seconds
    
    Returns:
        str: Banner text or error message
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        # Send different probes based on service type
        if port in [80, 443, 8080, 8443]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port == 21:  # FTP
            pass  # Just connect, banner is sent automatically
        elif port == 22:  # SSH
            pass  # SSH sends banner on connection
        elif port == 25:  # SMTP
            sock.send(b"EHLO test.com\r\n")
        elif port == 110:  # POP3
            sock.send(b"CAPA\r\n")
        elif port == 143:  # IMAP
            sock.send(b"CAPABILITY\r\n")
        elif port == 3306:  # MySQL
            pass  # MySQL sends banner on connection
        else:
            sock.send(b"\r\n")
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        # Clean up the banner
        if banner:
            # Take first line only
            banner = banner.split('\n')[0]
            # Remove special characters
            banner = ''.join(c for c in banner if 32 <= ord(c) < 127 or c == ' ')
            # Limit length
            if len(banner) > 150:
                banner = banner[:150] + "..."
        else:
            banner = "No banner received"
        
        return banner
    except Exception as e:
        return f"No banner (error: {str(e)[:30]})"
    
def scan_target(target, ports=None, progress_callback=None):
    """
    Scan a target for open ports.
    
    Args:
        target (str): IP address or hostname
        ports (list): List of ports to scan (default: DEFAULT_PORTS)
        progress_callback (function): Called with (progress, open_ports)
    
    Returns:
        dict: {
            'target': str,
            'open_ports': list,
            'banners': dict,
            'services': dict,
            'duration': float
        }
    """
    if ports is None:
        ports = DEFAULT_PORTS
    
    open_ports = []
    banners = {}
    services = {}
    
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
        else:
            # Show progress without cluttering
            progress = int(((idx + 1) / total_ports) * 100)
            print(f"⏳ Progress: {progress}%", end="\r")
        
        # Update callback if provided
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
        'duration': duration
    }

def scan_target_threaded(target, ports=None, progress_callback=None, max_threads=20):
    """
    Multi-threaded scan for better performance.
    
    Args:
        target (str): IP address or hostname
        ports (list): List of ports to scan
        progress_callback (function): Called with (progress, open_ports)
        max_threads (int): Maximum threads to use
    
    Returns:
        dict: Same as scan_target()
    """
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
        
        # ← ADD VULNERABILITY CHECK
            if banners[port] != "No banner received":
                vuln_findings = parse_banner_for_vulnerabilities(banners[port], port)
                if vuln_findings:
                    vulnerabilities[port] = vuln_findings
                    print(f"  ⚠️  Vulnerability found on port {port}: {vuln_findings[0]['cve']}")
    

    # Create and start threads
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_worker, args=(port,))
        threads.append(thread)
        thread.start()
        
        # Limit concurrent threads
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []
    
    # Wait for remaining threads
    for thread in threads:
        thread.join()
    
    # Collect results
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
        'duration': duration
    }

# Test the scanner (run this file directly)
if __name__ == "__main__":
    print("=" * 60)
    print("  PORT SCANNER TEST")
    print("=" * 60)
    
    target = input("\nEnter target IP or hostname (default: localhost): ") or "localhost"
    
    print("\n--- Testing Single-threaded Scan ---")
    result = scan_target(target)
    
    print("\n--- Testing Multi-threaded Scan ---")
    result_threaded = scan_target_threaded(target)
    
    print("\n📋 Summary:")
    print(f"  Target: {result['target']}")
    print(f"  Open Ports: {result['open_ports']}")
    print(f"  Duration: {result['duration']:.2f} seconds")
    
    print("\n📊 Service Details:")
    for port in result['open_ports']:
        service = result['services'].get(port, "Unknown")
        banner = result['banners'].get(port, "No banner")
        print(f"  Port {port}: {service} - {banner}")