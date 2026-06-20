import csv
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now()
        self.filename_base = f"scan_report_{target}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}"
    
    def generate_txt(self, open_ports, service_names=None):
        """Generate a plain text report"""
        filename = f"{self.filename_base}.txt"
        
        with open(filename, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("  NETWORK RECONNAISSANCE REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Open Ports Found: {len(open_ports)}\n")
            f.write("-" * 60 + "\n\n")

            f.write("OPEN PORTS:\n")
            f.write("-" * 40 + "\n")
            for port in open_ports:
                service = service_names.get(port, "Unknown") if service_names else "Unknown"
                f.write(f"  Port {port}: OPEN ({service})\n")
            f.write("\n")

            f.write("RISK ASSESSMENT:\n")
            f.write("-" * 40 + "\n")
            risky_ports = {21: "FTP", 23: "Telnet", 25: "SMTP", 3389: "RDP", 5900: "VNC"}
            found_risks = []
            for port in open_ports:
                if port in risky_ports:
                    found_risks.append(f"  ⚠️  Port {port} ({risky_ports[port]}) is considered high-risk")
            
            if found_risks:
                for risk in found_risks:
                    f.write(risk + "\n")
            else:
                f.write("  ✅ No high-risk ports detected\n")
            f.write("\n")
            
            f.write("=" * 60 + "\n")
            f.write("  END OF REPORT\n")
            f.write("=" * 60 + "\n")
        
        print(f"✅ TXT report saved to: {filename}")
        return filename
    
    def generate_csv(self, open_ports):
        """Generate a CSV report for data analysis"""
        filename = f"{self.filename_base}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status', 'Service'])
            if open_ports:
                for port in open_ports:
                    writer.writerow([port, 'OPEN', 'Unknown'])
            else:
                writer.writerow(['No open ports found', '', ''])
        
        print(f"✅ CSV saved to: {filename}")
        return filename
    
    def generate_json(self, open_ports):
        """Generate a JSON report for API consumption"""
        filename = f"{self.filename_base}.json"
        
        port_details = []
        if open_ports:
            for port in open_ports:
                port_details.append({
                    'port': port,
                    'status': 'OPEN',
                    'service': 'Unknown'
                })
        
        data = {
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'open_ports': open_ports,
            'total_open': len(open_ports),
            'ports': port_details
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ JSON saved to: {filename}")
        return filename
    
    def generate_all(self, open_ports, service_names=None):
        """Generate all report types at once"""
        txt = self.generate_txt(open_ports, service_names)
        csv = self.generate_csv(open_ports)
        json = self.generate_json(open_ports)
        return {
            'txt': txt,
            'csv': csv,
            'json': json
        }

if __name__ == "__main__":
    test_ports = [22, 80, 443]
    test_services = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS'}
    report = ReportGenerator("192.168.1.1")
    report.generate_all(test_ports, test_services)
    print("\n✅ All reports generated successfully!")