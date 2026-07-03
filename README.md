# Network Port Scanner

A lightweight cybersecurity tool that scans a host for open ports and identifies potential security risks — built with Python and vanilla HTML/CSS/JS.

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![HTML](https://img.shields.io/badge/Frontend-HTML%2FCSS%2FJS-orange) ![License](https://img.shields.io/badge/License-MIT-green)

---

## What It Does

- Scans a hostname or IP address for open ports using concurrent TCP connections
- Identifies **27 common ports** with descriptions of what each service does
- Assigns a **risk level** (High / Medium / Low / Safe) to each open port based on known vulnerabilities
- Displays results in a clean, dark-themed web dashboard
- Provides a summary of risk counts at a glance

---

## 🖥️ Screenshots

> Scan results showing open ports, risk badges, and service descriptions in a dark cybersecurity-themed UI.

---

## How to Run

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/network-port-scanner.git
cd network-port-scanner
```

### 2. Start the scanner server
```bash
python scanner.py
```

### 3. Open the dashboard
Go to [http://localhost:5000](http://localhost:5000) in your browser.

### 4. Scan a host
Enter a hostname or IP address and hit **Scan**.

> Try `scanme.nmap.org` — a public test host specifically set up for legal scanning practice.

---

## How It Works

```
User enters hostname
        ↓
Python resolves hostname → IP address
        ↓
ThreadPoolExecutor spawns 50 parallel threads
        ↓
Each thread attempts TCP connection to one port (1s timeout)
        ↓
Open ports are matched against knowledge base
        ↓
Results returned as JSON to the frontend
        ↓
Dashboard renders port list with risk levels
```

**Why parallel threads?** Scanning ports one by one would take minutes. With 50 concurrent threads, the same scan completes in seconds.

---

## Risk Levels

| Level | Colour | Examples |
|-------|--------|---------|
| 🔴 High | Red | SMB (445), RDP (3389), Telnet (23), MongoDB (27017) |
| 🟡 Medium | Amber | SSH (22), DNS (53), SMTP (25) |
| 🔵 Low | Blue | HTTP (80), HTTP-Alt (8080) |
| 🟢 Safe | Green | HTTPS (443) |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3 (stdlib only — no dependencies) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Web server | `http.server.HTTPServer` |
| Frontend | HTML, CSS, vanilla JavaScript |
| Charts | None — pure CSS styling |

**No external libraries required.** Runs on any machine with Python 3.8+.

---

## ⚠️ Legal Notice

Only scan hosts you own or have **explicit written permission** to scan. Unauthorised port scanning may be illegal in your jurisdiction. This tool is intended for educational purposes and authorised security assessments only.

---

## What I Learned Building This

- How TCP connections work at the socket level (`socket.connect_ex`)
- Why parallelism matters in network tooling — sequential vs concurrent scanning
- Common port numbers and their associated security risks
- How to build a lightweight Python HTTP server without frameworks
- Serving a REST API and consuming it from a vanilla JS frontend

---

## Future Ideas

- [ ] Add custom port range input
- [ ] Export results as PDF report
- [ ] Add OS fingerprinting
- [ ] Integrate with CVE database for known vulnerabilities per service
- [ ] Add scan history with local storage

---

## 👤 Author

**ArijusAtm**  
Information Systems & Cybersecurity student

---

*Built as part of a personal cybersecurity portfolio.*
