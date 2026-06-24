import csv
import json as json_lib
import os
from datetime import datetime

REPORTS_DIR = "reports"


class ReportGenerator:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now()
        # Sanitize target so it's safe as a filename
        safe_target = target.replace(':', '_').replace('/', '_').replace('\\', '_')
        self.filename_base = os.path.join(
            REPORTS_DIR,
            f"scan_report_{safe_target}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}"
        )
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def generate_txt(self, open_ports, service_names=None, banners=None, vulnerabilities=None):
        """Generate a plain-text report."""
        filename = f"{self.filename_base}.txt"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("  NETWORK RECONNAISSANCE REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target    : {self.target}\n")
            f.write(f"Scan Date : {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Open Ports: {len(open_ports)}\n")
            f.write("-" * 60 + "\n\n")

            f.write("OPEN PORTS\n")
            f.write("-" * 40 + "\n")
            if open_ports:
                for port in open_ports:
                    service = (service_names or {}).get(port, "Unknown")
                    banner  = (banners or {}).get(port, "")
                    f.write(f"  Port {port:5d}: OPEN  ({service})")
                    if banner:
                        f.write(f"  —  {banner}")
                    f.write("\n")
            else:
                f.write("  No open ports found.\n")
            f.write("\n")

            f.write("VULNERABILITIES\n")
            f.write("-" * 40 + "\n")
            vuln_data = vulnerabilities or {}
            found_any = False
            for port in open_ports:
                if port in vuln_data:
                    found_any = True
                    for v in vuln_data[port]:
                        f.write(f"  [⚠️  {v['severity']}] Port {port} — {v['cve']}: {v['description']}\n")
                        f.write(f"       Reference: {v.get('link', 'N/A')}\n")
            if not found_any:
                f.write("  No known vulnerabilities detected.\n")
            f.write("\n")

            f.write("RISK ASSESSMENT\n")
            f.write("-" * 40 + "\n")
            risky = {21: "FTP (unencrypted)", 23: "Telnet (unencrypted)",
                     25: "SMTP", 3389: "RDP", 5900: "VNC"}
            risks = [f"  [WARNING] Port {p} ({risky[p]})" for p in open_ports if p in risky]
            if risks:
                for r in risks:
                    f.write(r + "\n")
            else:
                f.write("  No high-risk ports detected.\n")
            f.write("\n")

            f.write("=" * 60 + "\n")
            f.write("  END OF REPORT\n")
            f.write("=" * 60 + "\n")

        print(f"[OK] TXT report: {filename}")
        return filename

    def generate_csv(self, open_ports, service_names=None, banners=None, vulnerabilities=None):
        """Generate a CSV report."""
        filename = f"{self.filename_base}.csv"

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status', 'Service', 'Banner', 'CVE', 'Severity'])
            if open_ports:
                for port in open_ports:
                    service = (service_names or {}).get(port, "Unknown")
                    banner  = (banners or {}).get(port, "")
                    vulns   = (vulnerabilities or {}).get(port, [])
                    if vulns:
                        for v in vulns:
                            writer.writerow([port, 'OPEN', service, banner, v['cve'], v['severity']])
                    else:
                        writer.writerow([port, 'OPEN', service, banner, '', ''])
            else:
                writer.writerow(['No open ports found', '', '', '', '', ''])

        print(f"[OK] CSV report: {filename}")
        return filename

    def generate_json(self, open_ports, service_names=None, banners=None, vulnerabilities=None):
        """Generate a JSON report."""
        filename = f"{self.filename_base}.json"

        port_details = []
        for port in open_ports:
            service = (service_names or {}).get(port, "Unknown")
            banner  = (banners or {}).get(port, "")
            vulns   = (vulnerabilities or {}).get(port, [])
            port_details.append({
                'port': port,
                'status': 'OPEN',
                'service': service,
                'banner': banner,
                'vulnerabilities': vulns
            })

        data = {
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'total_open_ports': len(open_ports),
            'ports': port_details
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json_lib.dump(data, f, indent=2)

        print(f"[OK] JSON report: {filename}")
        return filename

    def generate_pdf(self, open_ports, service_names=None, banners=None, vulnerabilities=None):
        """Generate a PDF report (requires reportlab)."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch

            filename = f"{self.filename_base}.pdf"
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                'CustomTitle', parent=styles['Heading1'],
                fontSize=22, textColor=colors.darkblue, spaceAfter=20
            )
            story.append(Paragraph("Network Reconnaissance Report", title_style))
            story.append(Paragraph(f"<b>Target:</b> {self.target}", styles['Normal']))
            story.append(Paragraph(f"<b>Date:</b> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph(f"<b>Open Ports:</b> {len(open_ports)}", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))

            if open_ports:
                story.append(Paragraph("Open Ports", styles['Heading2']))
                table_data = [['Port', 'Service', 'Banner', 'Vulnerability']]
                for port in open_ports:
                    service = (service_names or {}).get(port, "Unknown")
                    banner  = (banners or {}).get(port, "N/A")
                    vulns   = (vulnerabilities or {}).get(port, [])
                    vuln_text = "None detected"
                    if vulns:
                        vuln_text = f"{vulns[0]['cve']} ({vulns[0]['severity']})"
                        if len(vulns) > 1:
                            vuln_text += f" +{len(vulns)-1} more"
                    table_data.append([str(port), service, banner[:50], vuln_text])

                tbl = Table(table_data, colWidths=[0.8*inch, 1.2*inch, 2.5*inch, 1.8*inch])
                tbl.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a4a8a')),
                    ('TEXTCOLOR',  (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE',   (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lavender),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ]))
                story.append(tbl)
            else:
                story.append(Paragraph("No open ports found.", styles['Normal']))

            story.append(Spacer(1, 0.3 * inch))
            story.append(Paragraph("Risk Assessment", styles['Heading2']))
            risky = {21: "FTP (unencrypted)", 23: "Telnet (unencrypted)", 3389: "RDP", 5900: "VNC"}
            found_risks = [f"Port {p}: {risky[p]}" for p in open_ports if p in risky]
            if found_risks:
                story.append(Paragraph("High-risk services detected:", styles['Normal']))
                for r in found_risks:
                    story.append(Paragraph(f"<font color='red'>⚠️  {r}</font>", styles['Normal']))
            else:
                story.append(Paragraph("<font color='green'>✅ No high-risk ports detected</font>", styles['Normal']))

            doc.build(story)
            print(f"[OK] PDF report: {filename}")
            return filename

        except ImportError:
            print("⚠️  reportlab not installed — skipping PDF. Run: pip install reportlab")
            return None
        except Exception as e:
            print(f"❌ PDF error: {e}")
            return None

    def generate_all(self, open_ports, service_names=None, banners=None, vulnerabilities=None):
        """Generate TXT, CSV, JSON, and optionally PDF reports."""
        txt_file  = self.generate_txt(open_ports, service_names, banners, vulnerabilities)
        csv_file  = self.generate_csv(open_ports, service_names, banners, vulnerabilities)
        json_file = self.generate_json(open_ports, service_names, banners, vulnerabilities)

        pdf_file = None
        try:
            pdf_file = self.generate_pdf(open_ports, service_names, banners, vulnerabilities)
        except Exception as e:
            print(f"⚠️  PDF skipped: {e}")

        return {
            'txt':  txt_file,
            'csv':  csv_file,
            'json': json_file,
            'pdf':  pdf_file
        }


# ── CLI test ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_ports = [22, 80, 443]
    test_services = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS'}
    test_banners = {22: 'SSH-2.0-OpenSSH_8.9', 80: 'Apache/2.4.49'}
    test_vulns = {
        80: [{'cve': 'CVE-2021-41773', 'description': 'Path traversal', 'severity': 'CRITICAL',
              'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'}]
    }

    report = ReportGenerator("192.168.1.1")
    files = report.generate_all(test_ports, test_services, test_banners, test_vulns)
    print("\n[OK] All reports generated:")
    for fmt, path in files.items():
        print(f"  {fmt.upper()}: {path}")