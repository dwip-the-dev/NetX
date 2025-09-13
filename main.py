# netx_main_updated.py
"""
NetX Toolkit — Ultimate Network Analysis Suite (updated)
- This version prevents automatic updating of *active connection* results during the periodic system info refresh.
- System info (CPU, memory, disk, network totals, etc.) is still updated regularly by the background thread and returned via /api/netinfo.
- Active connections are **no longer included** inside /api/netinfo. They can be fetched on-demand from /api/connections (so the UI won't auto-refresh them unless you ask).

Usage:
    python netx_main_updated.py web    # run web UI
    python netx_main_updated.py        # CLI mode

Requirements:
    pip install flask requests psutil netifaces py-cpuinfo

Note: this file is a one-file edit of your uploaded main.py with the requested behavior change.
"""

from flask import Flask, request, jsonify, render_template_string
import socket
import requests
import platform
import sys
import concurrent.futures
import time
import json
import os
import subprocess
import re
import psutil
import netifaces
import cpuinfo
import datetime
import threading

app = Flask(__name__)

COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080, 8443]

# Global variable to store the latest system info
latest_system_info = {}
update_interval = 0.5  # seconds
update_thread = None
stop_monitoring = False


def get_system_info() -> dict:
    """Return the currently cached system info (updated in background)."""
    return latest_system_info


def monitor_system_info():
    """Background thread that continuously updates system information."""
    global latest_system_info, stop_monitoring

    while not stop_monitoring:
        try:
            cpu_info = cpuinfo.get_cpu_info()
            cpu_model = cpu_info.get('brand_raw', 'Unknown')
            cpu_cores = psutil.cpu_count(logical=False) or 1
            cpu_threads = psutil.cpu_count(logical=True) or 1

            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            disk = psutil.disk_usage('/')

            net_io = psutil.net_io_counters()
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            process_count = len(psutil.pids())

            latest_system_info = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "cpu_model": cpu_model,
                "cpu_cores": cpu_cores,
                "cpu_threads": cpu_threads,
                "cpu_usage": psutil.cpu_percent(interval=0.1),
                "memory_total": round(mem.total / (1024 ** 3), 2),
                "memory_used": round(mem.used / (1024 ** 3), 2),
                "memory_available": round(mem.available / (1024 ** 3), 2),
                "memory_percent": mem.percent,
                "swap_total": round(swap.total / (1024 ** 3), 2),
                "swap_used": round(swap.used / (1024 ** 3), 2),
                "swap_percent": swap.percent,
                "disk_total": round(disk.total / (1024 ** 3), 2),
                "disk_used": round(disk.used / (1024 ** 3), 2),
                "disk_free": round(disk.free / (1024 ** 3), 2),
                "disk_percent": disk.percent,
                "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
                "uptime": str(datetime.datetime.now() - boot_time).split('.')[0],
                "network_sent": round(net_io.bytes_sent / (1024 ** 2), 2),
                "network_recv": round(net_io.bytes_recv / (1024 ** 2), 2),
                "process_count": process_count,
                "last_update": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            }
        except Exception as e:
            latest_system_info = {"error": f"System info error: {str(e)}"}

        time.sleep(update_interval)


def start_system_monitoring():
    """Start the background system monitoring thread"""
    global update_thread, stop_monitoring
    stop_monitoring = False
    if update_thread is None or not update_thread.is_alive():
        update_thread = threading.Thread(target=monitor_system_info, daemon=True)
        update_thread.start()
        time.sleep(0.1)


def stop_system_monitoring():
    global stop_monitoring
    stop_monitoring = True


@app.before_request
def startup():
    # Ensure monitoring is started when running the web UI
    start_system_monitoring()


def get_public_ip():
    providers = [
        "https://api.ipify.org",
        "https://ident.me",
        "https://checkip.amazonaws.com",
        "https://ipinfo.io/ip"
    ]
    for provider in providers:
        try:
            return requests.get(provider, timeout=3).text.strip()
        except:
            continue
    return "unavailable"


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_info() -> dict:
    """Return network info WITHOUT the live 'connections' list to avoid constantly updating active connections in the UI."""
    try:
        hostname = socket.gethostname()
        local_ip = get_local_ip()
        public_ip = get_public_ip()

        # DNS information
        dns_servers = []
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
        except:
            pass

        # Default gateway
        gateway = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, (None, None))[0]

        # IMPORTANT: do NOT include 'connections' here. Connections are fetched by /api/connections on-demand.
        data = {
            "hostname": hostname,
            "local_ip": local_ip,
            "public_ip": public_ip,
            "gateway": gateway or "Unknown",
            "dns_servers": dns_servers,
        }

        # Merge with system info cached by background thread
        data.update(get_system_info())
        return data
    except Exception as e:
        return {"error": f"Network info error: {str(e)}"}


def get_connections_snapshot(limit=50):
    """Return a snapshot of current inet connections (on-demand)."""
    conns = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.raddr and conn.status:
                conns.append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status,
                    "pid": conn.pid or "N/A"
                })
    except Exception as e:
        return {"error": str(e)}
    return conns[:limit]


def get_whois_info(ip: str) -> dict:
    try:
        if ip in ["127.0.0.1", "localhost"]:
            return {"error": "Cannot get WHOIS for localhost"}
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        whois_data = result.stdout
        info = {}
        patterns = {
            "org": r"OrgName:\s*(.+)",
            "country": r"Country:\s*(.+)",
            "city": r"City:\s*(.+)",
            "net_range": r"NetRange:\s*(.+)",
            "cidr": r"CIDR:\s*(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, whois_data, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()
        return info if info else {"raw": whois_data[:500] + "..." if len(whois_data) > 500 else whois_data}
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}


def get_geolocation(ip: str) -> dict:
    try:
        if ip in ["127.0.0.1", "localhost"]:
            return {"error": "Cannot geolocate localhost"}
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
            }
        else:
            return {"error": data.get("message", "Geolocation failed")}
    except Exception as e:
        return {"error": f"Geolocation error: {str(e)}"}


# -------------------- Port scanning --------------------

def scan_port_target(args):
    ip, port, timeout = args
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        r = sock.connect_ex((ip, port))
        return port, (r == 0)
    except Exception:
        return port, False
    finally:
        sock.close()


def port_scan(ip, ports=None, timeout=0.5, workers=200):
    if ports is None:
        ports = COMMON_PORTS
    ports = list(ports)
    results = {}
    args = [(ip, p, timeout) for p in ports]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        futures = {ex.submit(scan_port_target, a): a[1] for a in args}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            try:
                p, is_open = fut.result()
                results[p] = "open" if is_open else "closed"
            except Exception as e:
                results[port] = f"error: {e}"
    return results


# -------------------- Website ping (enhanced) --------------------

def ping_site(url, timeout=5):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    try:
        start_time = time.time()
        r = requests.get(url, timeout=timeout)
        response_time = round((time.time() - start_time) * 1000, 2)
        ssl_info = {}
        if url.startswith("https://"):
            try:
                import ssl
                hostname = url.split("//")[1].split("/")[0]
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info = {
                            "issuer": dict(x[0] for x in cert.get('issuer', [])),
                            "valid_from": cert.get('notBefore'),
                            "valid_to": cert.get('notAfter'),
                            "version": cert.get('version'),
                        }
            except:
                ssl_info = {"error": "SSL info unavailable"}
        return {
            "ok": r.ok,
            "status_code": r.status_code,
            "url": r.url,
            "response_time_ms": response_time,
            "content_length": len(r.content),
            "headers": dict(r.headers),
            "ssl": ssl_info,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}


# -------------------- Flask endpoints (AJAX) --------------------

# NOTE: INDEX_HTML is the same UI but we removed rendering of live 'connections' from fetchNetInfo JS
INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetX Toolkit - Ultimate Network Analysis</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
    :root {
      --bg-dark: #0f172a;
      --bg-card: #1e293b;
      --bg-card-hover: #334155;
      --primary: #3b82f6;
      --primary-light: #60a5fa;
      --primary-dark: #2563eb;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --border: #334155;
      --radius: 12px;
      --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.2);
      --neomorph: inset 2px 2px 5px rgba(255, 255, 255, 0.05), inset -2px -2px 5px rgba(0, 0, 0, 0.3);
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg-dark);
      color: var(--text);
      line-height: 1.6;
      padding: 20px;
      min-height: 100vh;
    }

    .container {
      max-width: 1800px;
      margin: 0 auto;
    }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 25px;
      padding: 20px;
      background: var(--bg-card);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      border: 1px solid var(--border);
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 15px;
    }

    .logo-icon {
      width: 50px;
      height: 50px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
      color: white;
      border-radius: 12px;
      font-size: 24px;
      box-shadow: 0 4px 6px rgba(37, 99, 235, 0.3);
    }

    .logo-text {
      font-size: 28px;
      font-weight: 700;
      background: linear-gradient(135deg, var(--primary-light) 0%, var(--primary) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }

    @media (max-width: 1200px) {
      .grid {
        grid-template-columns: 1fr;
      }
    }

    .card {
      background: var(--bg-card);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: var(--shadow);
      border: 1px solid var(--border);
      transition: transform 0.3s ease, box-shadow 0.3s ease;
      margin-bottom: 20px;
    }

    .card:hover {
      transform: translateY(-3px);
      box-shadow: 0 15px 30px -5px rgba(0, 0, 0, 0.4);
    }

    .card-header {
      display: flex;
      align-items: center;
      margin-bottom: 20px;
      color: var(--primary);
      border-bottom: 1px solid var(--border);
      padding-bottom: 15px;
    }

    .card-header i {
      font-size: 22px;
      margin-right: 12px;
    }

    .card-header h2 {
      font-size: 18px;
      font-weight: 600;
    }

    .form-group {
      margin-bottom: 15px;
    }

    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 500;
      color: var(--text);
      font-size: 14px;
    }

    input[type="text"], input[type="number"] {
      width: 100%;
      padding: 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: rgba(30, 41, 59, 0.5);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      font-size: 14px;
      transition: all 0.3s ease;
    }

    input[type="text"]:focus, input[type="number"]:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
    }

    button {
      background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
      color: white;
      border: none;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: 'Inter', sans-serif;
      font-weight: 500;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 4px 6px rgba(37, 99, 235, 0.3);
    }

    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 12px rgba(37, 99, 235, 0.4);
    }

    button:active {
      transform: translateY(0);
    }

    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
      gap: 15px;
    }

    .info-item {
      background: rgba(30, 41, 59, 0.6);
      padding: 15px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .info-label {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 5px;
    }

    .info-value {
      font-size: 14px;
      font-weight: 500;
      color: var(--text);
      word-break: break-all;
    }

    .result-area {
      margin-top: 20px;
      background: rgba(30, 41, 59, 0.6);
      border-radius: 8px;
      padding: 15px;
      border: 1px solid var(--border);
      max-height: 300px;
      overflow-y: auto;
    }

    .port-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    .port-table th, .port-table td {
      padding: 10px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .port-table th {
      font-weight: 600;
      color: var(--text-muted);
      font-size: 12px;
    }

    .port-status {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 500;
    }

    .status-open {
      background: rgba(16, 185, 129, 0.15);
      color: var(--success);
    }

    .status-closed {
      background: rgba(239, 68, 68, 0.15);
      color: var(--danger);
    }

    .status-error {
      background: rgba(245, 158, 11, 0.15);
      color: var(--warning);
    }

    .spinner {
      display: inline-block;
      width: 18px;
      height: 18px;
      border: 3px solid rgba(59, 130, 246, 0.3);
      border-radius: 50%;
      border-top-color: var(--primary);
      animation: spin 1s linear infinite;
      margin-right: 10px;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .loading {
      display: flex;
      align-items: center;
      color: var(--primary);
      font-weight: 500;
      font-size: 14px;
    }

    .ping-result {
      line-height: 1.8;
      font-size: 14px;
    }

    .ping-result strong {
      color: var(--text);
      display: inline-block;
      min-width: 140px;
      color: var(--text-muted);
    }

    .raw-json {
      background: rgba(15, 23, 42, 0.5);
      padding: 15px;
      border-radius: 8px;
      font-family: 'Fira Code', monospace;
      font-size: 12px;
      max-height: 400px;
      overflow-y: auto;
      border: 1px solid var(--border);
      color: var(--text);
    }

    .tab-container {
      margin-top: 20px;
    }

    .tabs {
      display: flex;
      margin-bottom: 15px;
      border-bottom: 1px solid var(--border);
    }

    .tab {
      padding: 10px 20px;
      background: transparent;
      cursor: pointer;
      font-weight: 500;
      font-size: 13px;
      color: var(--text-muted);
      border-bottom: 2px solid transparent;
      transition: all 0.3s ease;
    }

    .tab.active {
      color: var(--primary);
      border-bottom: 2px solid var(--primary);
    }

    .tab-content {
      display: none;
      padding: 15px;
      background: rgba(15, 23, 42, 0.3);
      border-radius: 0 0 8px 8px;
      border: 1px solid var(--border);
      border-top: none;
    }

    .tab-content.active {
      display: block;
    }

    footer {
      text-align: center;
      margin-top: 40px;
      padding: 20px;
      color: var(--text-muted);
      font-size: 13px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }

    .stat-card {
      background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(30, 41, 59, 0.9) 100%);
      padding: 15px;
      border-radius: 8px;
      border: 1px solid var(--border);
      text-align: center;
    }

    .stat-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--primary);
      margin-bottom: 5px;
    }

    .stat-label {
      font-size: 12px;
      color: var(--text-muted);
    }

    .connection-item {
      padding: 10px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }

    .connection-item:last-child {
      border-bottom: none;
    }

    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 10px;
      font-size: 11px;
      font-weight: 500;
      margin-left: 8px;
    }

    .badge-success {
      background: rgba(16, 185, 129, 0.15);
      color: var(--success);
    }

    .badge-warning {
      background: rgba(245, 158, 11, 0.15);
      color: var(--warning);
    }

    .badge-info {
      background: rgba(59, 130, 246, 0.15);
      color: var(--primary);
    }

    .section-title {
      font-size: 16px;
      font-weight: 600;
      margin: 20px 0 15px 0;
      color: var(--primary-light);
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <div class="logo-icon">
          <i class="fas fa-network-wired"></i>
        </div>
        <div class="logo-text">NetX Toolkit</div>
      </div>
      <div class="version">v3.0 Ultimate</div>
    </header>

    <div class="grid">
      <div>
        <div class="card">
          <div class="card-header">
            <i class="fas fa-network-wired"></i>
            <h2>System & Network Information</h2>
          </div>
          <div id="netinfo">
            <div class="loading">
              <div class="spinner"></div>
              Loading comprehensive system information...
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <i class="fas fa-satellite-dish"></i>
            <h2>Website Analysis</h2>
          </div>
          <div class="form-group">
            <label for="ping-url">URL (with or without https://)</label>
            <input type="text" id="ping-url" placeholder="example.com or https://example.com">
          </div>
          <button id="btn-ping">
            <i class="fas fa-paper-plane"></i> Analyze Website
          </button>
          <div id="ping-result" class="result-area" style="display: none;"></div>
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-header">
            <i class="fas fa-search"></i>
            <h2>Port Scanner</h2>
          </div>
          <div class="form-group">
            <label for="scan-ip">Target IP / Hostname</label>
            <input type="text" id="scan-ip" placeholder="e.g., 192.168.1.1 or example.com">
          </div>
          <div class="form-group">
            <label for="scan-ports">Ports (comma or dash ranges). e.g., 22,80,443 or 1-1024</label>
            <input type="text" id="scan-ports" placeholder="leave empty to scan common ports">
          </div>
          <div class="form-group">
            <label for="scan-timeout">Timeout (seconds)</label>
            <input type="number" id="scan-timeout" value="0.5" step="0.1" min="0.1">
          </div>
          <button id="btn-scan">
            <i class="fas fa-radar"></i> Scan Ports
          </button>
          <div id="scan-progress" style="margin-top: 20px;"></div>
          <div id="scan-result" class="result-area" style="display: none;"></div>
        </div>

        <div class="card">
          <div class="card-header">
            <i class="fas fa-code"></i>
            <h2>Output & Results</h2>
          </div>
          <div class="tab-container">
            <div class="tabs">
              <div class="tab active" data-tab="json">JSON Output</div>
              <div class="tab" data-tab="ports">Port Results</div>
              <div class="tab" data-tab="ping">Ping Results</div>
            </div>
            <div class="tab-content active" id="json-tab">
              <div class="raw-json" id="raw-json">{}</div>
            </div>
            <div class="tab-content" id="ports-tab">
              <div id="ports-result"></div>
            </div>
            <div class="tab-content" id="ping-tab">
              <div id="ping-detail"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <footer>
      <p>NetX Toolkit v3.0 Ultimate &copy; 2023 | Built with Flask & Python</p>
    </footer>
  </div>

  <script>
  // Auto-refresh system info every second
let autoRefreshInterval;

function startAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    autoRefreshInterval = setInterval(async () => {
        await fetchNetInfo();
    }, 1000);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

window.addEventListener('load', () => {
    fetchNetInfo();
    startAutoRefresh();
});

// Tab functionality
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
  });
});

// Network info
async function fetchNetInfo() {
  try {
    const res = await fetch('/api/netinfo');
    const j = await res.json();
    
    let html = `
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${j.cpu_usage || 0}%</div>
          <div class="stat-label">CPU Usage</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${j.memory_used || 0} GB</div>
          <div class="stat-label">Memory Used</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${j.disk_used || 0} GB</div>
          <div class="stat-label">Disk Used</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${j.cpu_cores || 1}</div>
          <div class="stat-label">CPU Cores</div>
        </div>
      </div>
      
      <div class="section-title">System Information</div>
      <div class="info-grid">
        <div class="info-item">
          <div class="info-label">Hostname</div>
          <div class="info-value">${j.hostname || 'N/A'}</div>
        </div>
        <div class="info-item">
          <div class="info-label">System</div>
          <div class="info-value">${j.system || 'N/A'} ${j.release || ''}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Processor</div>
          <div class="info-value">${j.cpu_model || 'N/A'}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Boot Time</div>
          <div class="info-value">${j.boot_time || 'N/A'}</div>
        </div>
      </div>
      
      <div class="section-title">Network Information</div>
      <div class="info-grid">
        <div class="info-item">
          <div class="info-label">Local IP</div>
          <div class="info-value">${j.local_ip || 'N/A'}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Public IP</div>
          <div class="info-value">${j.public_ip || 'N/A'}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Gateway</div>
          <div class="info-value">${j.gateway || 'N/A'}</div>
        </div>
        <div class="info-item">
          <div class="info-label">DNS Servers</div>
          <div class="info-value">${j.dns_servers ? j.dns_servers.join(', ') : 'N/A'}</div>
        </div>
      </div>
    `;

    // NOTE: active connections are NOT automatically rendered here anymore.

    document.getElementById('netinfo').innerHTML = html;
    document.getElementById('raw-json').textContent = JSON.stringify({netinfo: j}, null, 2);
  } catch (e) {
    document.getElementById('netinfo').innerHTML = `<div style="color:var(--danger)">Error loading network info: ${e.message}</div>`;
  }
}

// Website ping (unchanged)
document.getElementById('btn-ping').addEventListener('click', async () => {
  const url = document.getElementById('ping-url').value.trim();
  if (!url) { alert('Please enter a URL'); return; }
  const out = document.getElementById('ping-result');
  out.style.display = 'block';
  out.innerHTML = '<div class="loading"><div class="spinner"></div>Analyzing website...</div>';
  try {
    const res = await fetch('/api/ping', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}) });
    const j = await res.json();
    let resultHtml = '<div class="ping-result">';
    if (j.ok !== undefined) {
      resultHtml += `<div><strong>Status:</strong> ${j.ok ? '<span style="color:var(--success)">✅ Success</span>' : '<span style="color:var(--danger)">❌ Failed</span>'}</div>`;
    }
    if (j.status_code) resultHtml += `<div><strong>Status Code:</strong> ${j.status_code}</div>`;
    if (j.url) resultHtml += `<div><strong>URL:</strong> ${j.url}</div>`;
    if (j.response_time_ms) resultHtml += `<div><strong>Response Time:</strong> ${j.response_time_ms} ms</div>`;
    if (j.content_length) resultHtml += `<div><strong>Content Length:</strong> ${j.content_length} bytes</div>`;
    if (j.error) resultHtml += `<div><strong>Error:</strong> <span style="color:var(--danger)">${j.error}</span></div>`;
    if (j.ssl && !j.ssl.error) {
      resultHtml += `<div class="section-title">SSL Certificate</div>`;
      if (j.ssl.issuer) {
        let issuerHtml = '';
        if (typeof j.ssl.issuer === 'object') {
          for (const [key, value] of Object.entries(j.ssl.issuer)) {
            issuerHtml += `<div style="margin-left: 20px;"><strong>${key}:</strong> ${value}</div>`;
          }
          resultHtml += `<div><strong>Issuer:</strong>${issuerHtml}</div>`;
        } else {
          resultHtml += `<div><strong>Issuer:</strong> ${j.ssl.issuer}</div>`;
        }
      }
      if (j.ssl.valid_from) resultHtml += `<div><strong>Valid From:</strong> ${j.ssl.valid_from}</div>`;
      if (j.ssl.valid_to) resultHtml += `<div><strong>Valid To:</strong> ${j.ssl.valid_to}</div>`;
      if (j.ssl.version) resultHtml += `<div><strong>Version:</strong> ${j.ssl.version}</div>`;
    }
    resultHtml += '</div>';
    out.innerHTML = resultHtml;
    document.getElementById('ping-detail').innerHTML = resultHtml;
    document.getElementById('raw-json').textContent = JSON.stringify({ping: j}, null, 2);
  } catch (e) {
    out.innerHTML = `<div style="color:var(--danger)">Error: ${e.message}</div>`;
  }
});

// Port scanner (unchanged)
function parsePortsInput(s) {
  s = s.trim(); if (!s) return null;
  const parts = s.split(','); const out = new Set();
  for (const p of parts) {
    if (p.includes('-')) {
      const [a,b] = p.split('-').map(x => parseInt(x.trim()));
      if (!isNaN(a) && !isNaN(b)) { for (let i = Math.max(1,a); i<=Math.min(65535,b); i++) out.add(i); }
    } else { const n = parseInt(p.trim()); if (!isNaN(n)) out.add(n); }
  }
  return Array.from(out).sort((a,b)=>a-b);
}

document.getElementById('btn-scan').addEventListener('click', async () => {
  const ip = document.getElementById('scan-ip').value.trim(); if (!ip) { alert('Please enter a target IP/hostname'); return; }
  const portsRaw = document.getElementById('scan-ports').value; const timeout = parseFloat(document.getElementById('scan-timeout').value) || 0.5; const ports = parsePortsInput(portsRaw);
  const progress = document.getElementById('scan-progress'); const resultEl = document.getElementById('scan-result');
  progress.innerHTML = '<div class="loading"><div class="spinner"></div>Scanning ports...</div>';
  resultEl.style.display = 'block'; resultEl.innerHTML = '';
  try {
    const payload = { ip, timeout }; if (ports) payload.ports = ports;
    const res = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
    const j = await res.json();
    progress.innerHTML = `<div style="color:var(--success)">Scan completed in ${j.took_seconds} seconds</div>`;
    if (j.results) {
      let tableHtml = `
        <h3 style="margin-bottom:15px;">Scan Results for ${j.target} (${j.resolved})</h3>
        <table class="port-table">
          <thead>
            <tr><th>Port</th><th>Status</th></tr>
          </thead>
          <tbody>
      `;
      const sortedPorts = Object.keys(j.results).sort((a,b)=>a-b);
      for (const port of sortedPorts) {
        const status = j.results[port]; let statusClass = 'status-closed'; if (status === 'open') statusClass = 'status-open'; if (status.includes('error')) statusClass = 'status-error';
        tableHtml += `<tr><td>${port}</td><td><span class="port-status ${statusClass}">${status}</span></td></tr>`;
      }
      tableHtml += '</tbody></table>';
      resultEl.innerHTML = tableHtml;
      document.getElementById('ports-result').innerHTML = tableHtml;
    }
    document.getElementById('raw-json').textContent = JSON.stringify({scan: j}, null, 2);
  } catch (e) {
    progress.innerHTML = `<div style="color:var(--danger)">Error: ${e.message}</div>`;
  }
});

// Note: No automatic connections rendering. Connections are available via /api/connections on-demand.

  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/api/netinfo")
def api_netinfo():
    # Returns only system + basic network info (no active connections list)
    return jsonify(get_network_info())

@app.route("/api/connections")
def api_connections():
    # On-demand endpoint to fetch current active connections (not auto-updated by the UI)
    try:
        conns = get_connections_snapshot(limit=200)
        return jsonify({"connections": conns})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ping", methods=["POST"]) 
def api_ping():
    data = request.get_json() or {}
    url = data.get("url") or ""
    return jsonify(ping_site(url))

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error":"no ip provided"}), 400
    try:
        resolved = socket.gethostbyname(ip)
    except Exception:
        return jsonify({"error":"could not resolve hostname"}), 400
    ports = data.get("ports")
    timeout = float(data.get("timeout", 0.5))
    if ports:
        try:
            ports = [int(p) for p in ports if 1 <= int(p) <= 65535]
        except Exception:
            ports = None
    if not ports:
        ports = COMMON_PORTS
    start = time.time()
    result = port_scan(resolved, ports=ports, timeout=timeout)
    took = time.time() - start
    return jsonify({"target": ip, "resolved": resolved, "took_seconds": round(took, 3), "results": result})

# -------------------- CLI --------------------

def cli_menu():
    print("⚡ NetX Toolkit CLI ⚡")
    print("1. Network Info")
    print("2. Website Ping")
    print("3. Port Scan")
    print("4. Run Flask Web UI")
    choice = input("Choose option: ").strip()
    if choice == "1":
        print(json.dumps(get_network_info(), indent=2))
    elif choice == "2":
        url = input("Enter URL: ").strip()
        print(json.dumps(ping_site(url), indent=2))
    elif choice == "3":
        ip = input("Enter IP/host: ").strip()
        ports = input("Enter ports (comma or ranges, leave blank for common ports): ").strip()
        if ports:
            parsed = []
            for p in ports.split(','):
                p = p.strip()
                if '-' in p:
                    a,b = p.split('-',1)
                    parsed += list(range(int(a), int(b)+1))
                else:
                    parsed.append(int(p))
        else:
            parsed = None
        print("Scanning... (this may take a bit)")
        res = port_scan(ip, ports=parsed)
        print(json.dumps(res, indent=2))
    elif choice == "4":
        print("Starting Flask web UI on http://127.0.0.1:5000")
        start_system_monitoring()
        app.run(host="0.0.0.0", port=5000, debug=False)
    else:
        print("invalid choice")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "web":
        start_system_monitoring()
        app.run(host="0.0.0.0", port=5000, debug=False)
    else:
        cli_menu()
