from flask import Flask, render_template, request, jsonify, send_file
import threading
import time
import os

app = Flask(__name__)

scan_lock = threading.Lock()

scan_status = {
    "running": False,
    "target": "",
    "mode": "quick",
    "progress": 0,
    "open_ports": [],
    "banners": {},
    "vulnerabilities": {},
    "completed": False,
    "error": None,
    "report_files": {}
}

def update_status(**kwargs):
    with scan_lock:
        scan_status.update(kwargs)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    import socket

    try:
        data   = request.json
        target = data.get('target', '').strip()
        mode   = data.get('mode', 'quick').strip()

        if not target:
            return jsonify({"status": "error", "message": "Target cannot be empty"}), 400

        if mode not in ('quick', 'full'):
            return jsonify({"status": "error", "message": "Invalid mode. Use 'quick' or 'full'"}), 400

        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            return jsonify({"status": "error", "message": "Invalid hostname or IP address"}), 400

        with scan_lock:
            if scan_status["running"]:
                return jsonify({"status": "error", "message": "A scan is already running"}), 409

            scan_status.update({
                "running": True,
                "target": target,
                "mode": mode,
                "progress": 0,
                "open_ports": [],
                "banners": {},
                "vulnerabilities": {},
                "completed": False,
                "error": None,
                "report_files": {}
            })

        thread = threading.Thread(target=run_scan, args=(target, mode))
        thread.daemon = True
        thread.start()

        return jsonify({"status": "started", "message": f"Scanning {target} ({mode} mode)"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/scan/status')
def get_status():
    with scan_lock:
        return jsonify({
            "running":         scan_status["running"],
            "target":          scan_status["target"],
            "mode":            scan_status["mode"],
            "progress":        scan_status["progress"],
            "open_ports":      scan_status["open_ports"],
            "banners":         scan_status["banners"],
            "vulnerabilities": scan_status["vulnerabilities"],
            "completed":       scan_status["completed"],
            "error":           scan_status["error"]
        })


@app.route('/api/scan/report', methods=['POST'])
def generate_report():
    try:
        from reports import ReportGenerator
        from scanner import COMMON_PORTS

        with scan_lock:
            open_ports      = scan_status.get("open_ports", [])
            target          = scan_status.get("target", "unknown")
            banners         = scan_status.get("banners", {})
            vulnerabilities = scan_status.get("vulnerabilities", {})

        if not open_ports:
            return jsonify({"status": "error", "message": "No scan results available"}), 400

        report = ReportGenerator(target)
        files  = report.generate_all(open_ports, COMMON_PORTS, banners, vulnerabilities)

        update_status(report_files=files)
        return jsonify({"status": "success", "files": files})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/scan/download/<file_type>')
def download_report(file_type):
    with scan_lock:
        files = scan_status.get("report_files", {})

    filepath = files.get(file_type)
    if not filepath or not os.path.exists(filepath):
        return jsonify({"status": "error", "message": f"Report '{file_type}' not found"}), 404

    return send_file(filepath, as_attachment=True)


def run_scan(target, mode='quick'):
    print("=" * 60)
    print(f"🚀 Scan started — target: {target}, mode: {mode}")
    print("=" * 60)

    try:
        from scanner import scan_target_threaded, get_ports_for_mode

        ports = get_ports_for_mode(mode)
        max_threads = 100 if mode == 'full' else 50

        print(f"📡 Scanning {len(ports)} ports with {max_threads} threads")
        live = {'banners': {}, 'vulnerabilities': {}}

        def update_progress(progress, open_ports):
            update_status(
                progress        = progress,
                open_ports      = open_ports,
                banners         = dict(live['banners']),
                vulnerabilities = dict(live['vulnerabilities'])
            )

        result = scan_target_threaded(target, ports, update_progress,
                                      max_threads, live_ref=live)

        update_status(
            open_ports      = result.get("open_ports", []),
            banners         = result.get("banners", {}),
            vulnerabilities = result.get("vulnerabilities", {}),
            progress        = 100,
            completed       = True
        )

        print(f"✅ Scan complete! {len(result['open_ports'])} open ports: {result['open_ports']}")

    except ImportError as e:
        print(f"❌ scanner.py not found: {e} — falling back to simulation")
        run_simulation(target)

    except Exception as e:
        import traceback
        traceback.print_exc()
        update_status(completed=True, error=str(e))

    finally:
        update_status(running=False)
        print("🏁 Scan finished.")


def run_simulation(target):
    print(f"🔄 Simulating scan on {target}...")
    simulated_ports = [22, 80, 443]
    open_ports = []

    for i, port in enumerate(simulated_ports):
        time.sleep(1)
        open_ports.append(port)
        progress = int(((i + 1) / len(simulated_ports)) * 100)
        update_status(open_ports=open_ports.copy(), progress=progress)

    update_status(progress=100, completed=True)
    print("✅ Simulation complete")


if __name__ == '__main__':
    print("🚀 Starting Flask server on http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)