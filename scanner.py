"""
Network Port Scanner - by Arijus Atmanavičius
A cybersecurity tool that scans a host for open ports
and flags potential security risks.
"""

import socket
import concurrent.futures
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ─────────────────────────────────────────
#   PORT KNOWLEDGE BASE
#   Common ports with descriptions & risk levels
# ─────────────────────────────────────────

PORT_INFO = {
    21:   {"name": "FTP",        "desc": "File Transfer Protocol — transfers files. Often misconfigured and exploitable.",          "risk": "high"},
    22:   {"name": "SSH",        "desc": "Secure Shell — encrypted remote access. Generally safe but brute-force target.",          "risk": "medium"},
    23:   {"name": "Telnet",     "desc": "Unencrypted remote access — transmits data including passwords in plaintext.",            "risk": "high"},
    25:   {"name": "SMTP",       "desc": "Email sending protocol. Can be exploited for spam relay if misconfigured.",               "risk": "medium"},
    53:   {"name": "DNS",        "desc": "Domain Name System — resolves domain names. Can be used for DNS amplification attacks.", "risk": "medium"},
    80:   {"name": "HTTP",       "desc": "Unencrypted web traffic. Exposes data in transit — HTTPS preferred.",                    "risk": "low"},
    110:  {"name": "POP3",       "desc": "Email retrieval protocol. Unencrypted version transmits credentials in plaintext.",      "risk": "medium"},
    135:  {"name": "RPC",        "desc": "Windows Remote Procedure Call. Frequently targeted by malware and worms.",               "risk": "high"},
    139:  {"name": "NetBIOS",    "desc": "Windows file sharing. Common attack vector for lateral movement in networks.",           "risk": "high"},
    143:  {"name": "IMAP",       "desc": "Email access protocol. Unencrypted version exposes email content.",                      "risk": "medium"},
    443:  {"name": "HTTPS",      "desc": "Encrypted web traffic. Standard secure web protocol.",                                   "risk": "safe"},
    445:  {"name": "SMB",        "desc": "Windows file sharing. Exploited by WannaCry ransomware — high priority to secure.",     "risk": "high"},
    1433: {"name": "MSSQL",      "desc": "Microsoft SQL Server. Database exposure — should never be public-facing.",               "risk": "high"},
    1723: {"name": "PPTP VPN",   "desc": "Old VPN protocol with known cryptographic weaknesses.",                                  "risk": "high"},
    3306: {"name": "MySQL",      "desc": "MySQL database. Publicly exposed databases are a major security risk.",                   "risk": "high"},
    3389: {"name": "RDP",        "desc": "Windows Remote Desktop. Frequent ransomware entry point — brute-force target.",         "risk": "high"},
    5432: {"name": "PostgreSQL", "desc": "PostgreSQL database. Should never be exposed to the internet.",                          "risk": "high"},
    5900: {"name": "VNC",        "desc": "Remote desktop (VNC). Often weakly secured — common attack target.",                    "risk": "high"},
    6379: {"name": "Redis",      "desc": "Redis database. Frequently found exposed with no authentication by default.",            "risk": "high"},
    8080: {"name": "HTTP-Alt",   "desc": "Alternate HTTP port — often used for development servers or proxies.",                   "risk": "low"},
    8443: {"name": "HTTPS-Alt",  "desc": "Alternate HTTPS port — commonly used for admin panels.",                                 "risk": "medium"},
    27017:{"name": "MongoDB",    "desc": "MongoDB database. Historically exposed without auth — major data breach source.",       "risk": "high"},
}

COMMON_PORTS = list(PORT_INFO.keys()) + [
    8888, 9090, 9200, 6443, 2049, 111, 512, 513, 514
]

# ─────────────────────────────────────────
#   CORE SCANNING LOGIC
# ─────────────────────────────────────────

def scan_port(host, port, timeout=1.0):
    """Try to connect to a single port. Returns True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except (socket.gaierror, OSError):
        return False

def resolve_host(host):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def scan_host(host, ports=None):
    """Scan a host for open ports using parallel threads."""
    if ports is None:
        ports = COMMON_PORTS

    ip = resolve_host(host)
    if not ip:
        return {"error": f"Could not resolve host: {host}"}

    open_ports = []

    # Scan ports in parallel (much faster than one by one)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                info = PORT_INFO.get(port, {
                    "name": "Unknown",
                    "desc": "No information available for this port.",
                    "risk": "unknown"
                })
                open_ports.append({
                    "port": port,
                    "name": info["name"],
                    "desc": info["desc"],
                    "risk": info["risk"]
                })

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    # Count risk levels
    risk_counts = {"high": 0, "medium": 0, "low": 0, "safe": 0, "unknown": 0}
    for p in open_ports:
        risk_counts[p["risk"]] += 1

    return {
        "host": host,
        "ip": ip,
        "total_scanned": len(ports),
        "open_count": len(open_ports),
        "risk_counts": risk_counts,
        "ports": open_ports
    }

# ─────────────────────────────────────────
#   WEB SERVER
# ─────────────────────────────────────────

class ScanHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)

        # Serve the frontend
        if parsed.path == "/" or parsed.path == "/index.html":
            self.serve_file("index.html", "text/html")

        # API endpoint: /scan?host=example.com
        elif parsed.path == "/scan":
            params = parse_qs(parsed.query)
            host = params.get("host", [None])[0]

            if not host:
                self.send_json({"error": "No host provided"}, 400)
                return

            # Basic validation
            host = host.strip()
            if len(host) > 253 or not host:
                self.send_json({"error": "Invalid host"}, 400)
                return

            print(f"[SCAN] Scanning: {host}")
            result = scan_host(host)
            self.send_json(result)

        else:
            self.send_response(404)
            self.end_headers()

    def serve_file(self, filename, content_type):
        try:
            with open(filename, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def send_json(self, data, code=200):
        content = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(content))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        pass  # Suppress default request logging


# ─────────────────────────────────────────
#   ENTRY POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    PORT = 5000
    print(f"""
╔══════════════════════════════════════╗
║     Network Port Scanner v1.0        ║
║     by ArijusAtm           ║
╠══════════════════════════════════════╣
║  Server running at:                  ║
║  http://localhost:{PORT}               ║
║                                      ║
║  Press Ctrl+C to stop               ║
╚══════════════════════════════════════╝
    """)
    server = HTTPServer(("localhost", PORT), ScanHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Scanner stopped.")
