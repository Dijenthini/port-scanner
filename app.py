from flask import Flask, render_template, request, jsonify
import threading
import time

app = Flask(__name__)

scan_status = {
    "running": False,
    "target": "",
    "progress": 0,
    "open_ports": [],
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
        files = report.generate_all(open_ports, services)
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_scan_background(target):
    """Run the real port scanner (or fallback to simulation)"""
    try:
        from scanner import scan_target_threaded
        
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                        993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        print(f"🔍 Starting REAL scan on {target}...")
        
        def update_progress(progress, open_ports):
            scan_status['progress'] = progress
            scan_status['open_ports'] = open_ports
        
        result = scan_target_threaded(target, ports_to_scan, update_progress)
        
        scan_status['open_ports'] = result['open_ports']
        scan_status['progress'] = 100
        scan_status['completed'] = True
        
        print(f"✅ Scan complete! Found {len(result['open_ports'])} open ports")
        
    except ImportError:
        print("⚠️ scanner.py not found! Using simulation...")
        run_scan_simulation(target)
    except Exception as e:
        print(f"❌ Scan error: {e}")
        scan_status['completed'] = True
    finally:
        scan_status['running'] = False

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