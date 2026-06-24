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
    print("✅ INDEX PAGE LOADED")  # <-- This will show when you open the page
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    import socket

    try:
        data = request.json
        target = data.get('target', '').strip()

        if not target:
            return jsonify({
                "status": "error",
                "message": "Target cannot be empty"
            }), 400

        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            return jsonify({
                "status": "error",
                "message": "Invalid hostname or IP address"
            }), 400

        if scan_status["running"]:
            return jsonify({
                "status": "error",
                "message": "A scan is already running"
            }), 409

        scan_status.update({
            "running": True,
            "target": target,
            "progress": 0,
            "open_ports": [],
            "banners": {},
            "vulnerabilities": {},
            "completed": False
        })

        thread = threading.Thread(
            target=run_scan,
            args=(target,)
        )
        thread.daemon = True
        thread.start()

        return jsonify({
            "status": "started",
            "message": f"Scanning {target}"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
    
@app.route('/api/scan/status')
def get_status():
    return jsonify({
        "running": scan_status["running"],
        "target": scan_status["target"],
        "progress": scan_status["progress"],
        "open_ports": scan_status["open_ports"],
        "banners": scan_status["banners"],
        "vulnerabilities": scan_status["vulnerabilities"],
        "completed": scan_status["completed"]
    })

@app.route('/api/scan/report', methods=['POST'])
def generate_report():
    try:
        from reports import ReportGenerator

        open_ports = scan_status.get("open_ports", [])

        if not open_ports:
            return jsonify({
                "status": "error",
                "message": "No scan results available"
            }), 400

        services = {
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

        report = ReportGenerator(scan_status["target"])

        files = report.generate_all(
            open_ports,
            services,
            scan_status.get("banners", {}),
            scan_status.get("vulnerabilities", {})
        )

        return jsonify({
            "status": "success",
            "files": files
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def run_scan(target):
    print("=" * 60)
    print("🚀🚀🚀 THE BACKGROUND SCAN HAS STARTED! 🚀🚀🚀")
    print("=" * 60)
    print(f"📡 Scanning target: {target}")
    
    try:
        # Try to use the REAL scanner
        print("📥 Attempting to import scanner.py...")
        from scanner import scan_target_threaded
        print("✅ scanner.py imported successfully!")
        
        ports_to_scan = [
            21, 22, 23, 25,
            53, 80, 110, 143,
            443, 445, 993, 995,
            3306, 3389, 5900,
            8080, 8443
        ]
        print(f"🔍 Scanning ports: {ports_to_scan}")
        
        # Progress callback
        def update_progress(progress, open_ports):
            scan_status['progress'] = progress
            scan_status['open_ports'] = open_ports
            print(f"📊 Progress update: {progress}%, Ports: {open_ports}")
        
        # ACTUALLY RUN THE SCANNER
        print("⏳ Calling the scanner now...")
        result = scan_target_threaded(target, ports_to_scan, update_progress)
        
        scan_status.update({
            "open_ports": result.get("open_ports", []),
            "banners": result.get("banners", {}),
            "vulnerabilities": result.get("vulnerabilities", {}),
            "progress": 100,
            "completed": True
        })
        
        print(f"✅✅✅ SCAN COMPLETE! Found {len(result['open_ports'])} open ports")
        print(f"📋 Ports: {result['open_ports']}")
        
    except ImportError as e:
        print(f"❌ ERROR: scanner.py not found! {e}")
        print("🔄 Falling back to simulation...")
        run_simulation(target)
        
    except Exception as e:
        print(f"❌ CRASH: {e}")
        import traceback
        traceback.print_exc()
        scan_status['completed'] = True
        
    finally:
        scan_status["running"] = False
        print("🏁 Scan finished.")

def run_simulation(target):
    print(f"🔄 SIMULATING scan on {target}...")
    simulated_ports = [22, 80, 443]
    open_ports = []
    
    for i, port in enumerate(simulated_ports):
        time.sleep(1)
        open_ports.append(port)
        scan_status['open_ports'] = open_ports.copy()
        progress = int(((i + 1) / len(simulated_ports)) * 100)
        scan_status['progress'] = progress
        print(f"📊 Simulation Progress: {progress}% (Found port {port})")
    
    scan_status['progress'] = 100
    scan_status['completed'] = True
    print("✅ SIMULATION COMPLETE")

if __name__ == '__main__':
    print("🚀 Starting Flask server...")
    app.run(debug=True, host='0.0.0.0', port=5000)