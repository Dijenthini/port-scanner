import csv
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now()
        self.filename_base = f"scan_report_{target}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}"
    
    def generate_txt(self, open_ports, banners=None):
        """Generate a plain text report"""
        filename = f"{self.filename_base}.txt"
        
        with open(filename, 'w') as f:
            # Header
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
                f.write(f"  Port {port}: OPEN\n")
                if banners and port in banners:
                    f.write(f"    Banner: {banners[port][:100]}\n")
            f.write("\n")

            f.write("RISK ASSESSMENT:\n")
            f.write("-" * 40 + "\n")
            risky_ports = [21, 23, 25, 3389, 5900]
            for port in open_ports:
                if port in risky_ports:
                    f.write(f"  ⚠️  Port {port} is considered high-risk\n")
            if not any(p in open_ports for p in risky_ports):
                f.write("  ✅ No high-risk ports detected\n")
            f.write("\n")
            
            f.write("=" * 60 + "\n")
            f.write("  END OF REPORT\n")
            f.write("=" * 60 + "\n")
        
        print(f"✅ Report saved to: {filename}")
        return filename
    
    def generate_csv(self, open_ports):
        """Generate a CSV report for data analysis"""
        filename = f"{self.filename_base}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status', 'Service'])
            for port in open_ports:
                writer.writerow([port, 'OPEN', 'Unknown'])
        
        print(f"✅ CSV saved to: {filename}")
        return filename
    
    def generate_json(self, open_ports):
        """Generate a JSON report for API consumption"""
        filename = f"{self.filename_base}.json"
        data = {
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'open_ports': open_ports,
            'total_open': len(open_ports)
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ JSON saved to: {filename}")
        return filename

if __name__ == "__main__":
    test_ports = [22, 80, 443]
    report = ReportGenerator("192.168.1.1")
    report.generate_txt(test_ports)
    report.generate_csv(test_ports)
    report.generate_json(test_ports)