from flask import Flask, render_template, request, jsonify
import threading
import time

app = Flask(__name__)

scan_status = {
    "running": False,
    "target": "",
    "progress": 0,
    "open_ports": [],
    "banners": {},
    "vulnerabilities": {},
    "completed": False
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', 'localhost')

    scan_status['running'] = True
    scan_status['target'] = target
    scan_status['progress'] = 0
    scan_status['open_ports'] = []
    scan_status['completed'] = False

    thread = threading.Thread(target=run_scan_background, args=(target,))
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "started", "message": f"Scanning {target}"})

@app.route('/api/scan/status')
def get_status():
    return jsonify(scan_status)

@app.route('/api/scan/report', methods=['POST'])
def generate_report():
    """Generate reports from scan results"""
    from reports import ReportGenerator
    
    try:
        open_ports = scan_status.get('open_ports', [])
        if not open_ports:
            return jsonify({"error": "No scan results to export"}), 400
        
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
            139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
            3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        
        report = ReportGenerator(scan_status['target'])
        files = report.generate_all(open_ports, services,scan_status.get('banners', {}),scan_status.get('vulnerabilities', {}))
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_scan_background(target):
    """SUPER SIMPLE TEST - NO SCANNER, NO IMPORTS"""
    print("=" * 50)
    print("🔥🔥🔥 TEST FUNCTION IS RUNNING! 🔥🔥🔥")
    print(f"Target received: {target}")
    print("=" * 50)
    
    # Fake a scan so the dashboard shows something
    import time
    fake_ports = []
    
    for i in range(5):
        time.sleep(0.5)
        fake_ports.append(22 + (i * 10))  # Adds 22, 32, 42, 52, 62
        scan_status['progress'] = (i + 1) * 20
        scan_status['open_ports'] = fake_ports.copy()
        print(f"Fake progress: {scan_status['progress']}%")
    
    scan_status['progress'] = 100
    scan_status['completed'] = True
    scan_status['running'] = False
    print("🔥🔥🔥 TEST COMPLETE! 🔥🔥🔥")

def run_scan_simulation(target):
    """Fallback simulation (your original code)"""
    try:
        simulated_ports = [22, 80, 443, 3306, 3389]
        open_ports = []
        
        for i, port in enumerate(simulated_ports):
            time.sleep(0.8)
            open_ports.append(port)
            scan_status['open_ports'] = open_ports.copy()
            progress = int(((i + 1) / len(simulated_ports)) * 100)
            scan_status['progress'] = progress
            print(f"✅ Found open port: {port} (Progress: {progress}%)")
        
        scan_status['progress'] = 100
        scan_status['completed'] = True
        print("✅ Simulation complete!")
        
    except Exception as e:
        print(f"❌ Simulation error: {e}")
        scan_status['completed'] = True

if __name__ == '__main__':
    print("🚀 Starting Flask server...")
    app.run(debug=True, host='0.0.0.0', port=5000)