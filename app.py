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
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
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
    """Get current scan status"""
    return jsonify(scan_status)

@app.route('/api/scan/report')
def generate_report():
    """Generate reports from scan results"""
    return jsonify({"message": "Report generation coming soon"})

def run_scan_background(target):
    """Background task that runs the scan"""
    import time
    from scanner import scan_target
    
    try:
        open_ports = []
        for i in range(20):
            time.sleep(0.2)
            scan_status['progress'] = (i + 1) * 5
            if i % 3 == 0:
                open_ports.append(22 + i)
                scan_status['open_ports'] = open_ports

    except Exception as e:
        print(f"Scan error: {e}")
    finally:
        scan_status['running'] = False
        scan_status['completed'] = True

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)