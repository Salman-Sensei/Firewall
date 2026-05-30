# 🛡️ Smart Shield Firewall

> A full-stack network security dashboard built with Python, Flask, React, and Scapy.  
> Real-time packet capture · Rule-based threat detection · Live analytics dashboard

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=for-the-badge&logo=flask)
![React](https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react)
![Scapy](https://img.shields.io/badge/Scapy-2.5-00d4ff?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-00ff88?style=for-the-badge)

---

## 🎯 Project Vision

Smart Shield Firewall was built to answer one question:

> *"Can a student replicate what enterprise firewall systems do , and make it look good?"*

The answer is yes.

This project mirrors the architecture of production firewall systems like **pfSense** and **OPNsense**:

- The **React dashboard** is the management console , the same role as pfSense's web UI
- The **Flask backend** is the control plane , holds rules, processes traffic, exposes an API
- The **Scapy capture engine** is the data plane , reads raw packets off the network card
- The **REST API** is the communication layer , frontend and backend are fully decoupled

Anyone on the same network can open `http://<your-ip>:5000` in their browser and access the live firewall dashboard with no installation needed on their end. This is exactly how enterprise firewall management consoles work , the firewall runs on one machine, and administrators manage it remotely through a web interface.

---

## 📌 What This Project Does

| Feature | Description |
|---------|-------------|
| 🔴 **Live Packet Capture** | Captures every IP packet on your NIC using Scapy |
| ⚖️ **Rule Engine** | Evaluates each packet against firewall rules , Allow or Block |
| 📊 **Live Dashboard** | Stats, charts, and packet feed update in real time |
| 🗺️ **Network Map** | SVG topology showing active connections |
| 📋 **Event Logs** | Full timestamped log of every network event |
| ⚙️ **Rule Manager** | Add, delete, and toggle rules from the browser , no restart |
| 🌐 **Remote Access** | Accessible from any device on the same network |
| 🔌 **REST API** | Full JSON API , every piece of data is programmable |

---

## 🧱 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HOST MACHINE                          │
│                                                          │
│   ┌──────────────────────────────────────────────────┐  │
│   │  Network Interface Card (NIC / WiFi Adapter)     │  │
│   │  Every packet in and out passes through here     │  │
│   └────────────────────┬─────────────────────────────┘  │
│                        │ raw packets                     │
│                        ▼                                 │
│   ┌──────────────────────────────────────────────────┐  │
│   │  ScapyCapture                                    │  │
│   │  scapy.sniff() binds to NIC, calls on_packet()   │  │
│   │  for every IP packet captured                    │  │
│   └────────────────────┬─────────────────────────────┘  │
│                        │ parsed packet dict              │
│                        ▼                                 │
│   ┌──────────────────────────────────────────────────┐  │
│   │  RuleEngine                                      │  │
│   │  Checks src IP, dst IP, protocol, port           │  │
│   │  against active rules → returns Allow / Block    │  │
│   └────────────────────┬─────────────────────────────┘  │
│                        │ stamped + evaluated packet      │
│                        ▼                                 │
│   ┌──────────────────────────────────────────────────┐  │
│   │  PacketStore  (thread-safe ring buffer)          │  │
│   │  Holds last 100 packets + running statistics     │  │
│   └────────────────────┬─────────────────────────────┘  │
│                        │ JSON via HTTP                   │
│                        ▼                                 │
│   ┌──────────────────────────────────────────────────┐  │
│   │  Flask REST API  (port 5000, host 0.0.0.0)       │  │
│   │  Serves all data , accessible across the LAN    │  │
│   └────────────────────┬─────────────────────────────┘  │
│                        │                                 │
└────────────────────────┼────────────────────────────────┘
                         │ HTTP (LAN accessible)
          ┌──────────────┴───────────────┐
          │                              │
   ┌──────▼────────┐            ┌────────▼──────┐
   │ Your Browser  │            │ Any device    │
   │ localhost:5000│            │ on same WiFi  │
   └───────────────┘            │ <your-ip>:5000│
                                └───────────────┘
```

---

## 🗂️ Project Structure

```
smart-shield-firewall/
├── index.html           ← Complete 9-page React app (zero build step)
├── app.py               ← Python backend , 6 OOP classes, 465 lines
├── requirements.txt     ← Python dependencies
└── README.md
```

---

## ⚙️ Backend , 6 OOP Classes

`app.py` is structured into six single-responsibility classes,
mirroring how production firewall software is architected internally.

```
app.py
│
├── FirewallConfig    , rules, settings, blocked subnet lists
├── RuleEngine        , packet evaluation logic (Allow / Block)
├── PacketStore       , thread-safe ring buffer + live statistics
├── PacketSimulator   , realistic traffic generator (demo mode)
├── ScapyCapture      , live NIC capture using Scapy
└── FirewallApp       , Flask routes, wires all classes together
```

### `FirewallConfig`
Holds all firewall rules and global settings. Rules have a name, source IP, destination IP, protocol, action (Allow/Block), priority level, and an active toggle. Rules can be added at runtime through the API without restarting the server.

### `RuleEngine`
Evaluates every packet against the active rule list sorted by priority. If no rule matches, the default action (`Deny`) is applied. Also resolves raw port numbers to protocol names , port 443 → HTTPS, port 53 → DNS, port 22 → SSH.

### `PacketStore`
A thread-safe ring buffer holding the last 100 captured packets and running totals for total, allowed, and blocked packet counts. Uses `threading.Lock()` so the Flask API thread and the Scapy capture thread can read/write simultaneously without race conditions.

### `PacketSimulator`
Generates realistic network traffic for demo mode. Produces packets with random IPs, protocols, and byte sizes , each one still runs through `RuleEngine`, so the Allow/Block logic is always exercised even without Scapy.

### `ScapyCapture`
The real capture engine. Auto-detects your NIC using `get_if_list()`, binds with `sniff()`, and calls `on_packet()` for every IP packet. Extracts src/dst IPs, resolves protocol names from port numbers, reads packet size, evaluates via `RuleEngine`, and pushes to `PacketStore`. Runs in a background daemon thread so Flask stays fully responsive.

### `FirewallApp`
The entry point. Instantiates all other classes, selects between `ScapyCapture` and `PacketSimulator` based on the `USE_REAL_CAPTURE` flag, and registers all nine Flask API routes.

---

## 🚀 Development Phases

### Phase 1 , React UI + Flask REST API

Built the complete 9-page dashboard and REST API from scratch.

**Pages built:**

| # | Page | What it shows |
|---|------|--------------|
| 1 | 🔐 Login | Animated particles, floating shield, scan line |
| 2 | 🏠 Landing | Hero page with animated orb and feature cards |
| 3 | 📊 Dashboard | Live stats, area chart, protocol donut, packet feed |
| 4 | 📡 Live Monitor | Real-time scrolling packet table with filters |
| 5 | ⚙️ Firewall Rules | Add, delete, toggle rules , live, no restart |
| 6 | 📈 Analytics | Traffic trends, top talkers, allowed vs blocked |
| 7 | 🗺️ Network Map | SVG topology with animated packet flow |
| 8 | 🔧 Settings | Tabbed config, resource meters, service status |
| 9 | 📋 Logs | Filterable color-coded event log |

**API endpoints built:**
```
GET    /api/stats              → dashboard statistics
GET    /api/packets?limit=20   → recent packet feed
GET    /api/traffic            → 25-point hourly chart data
GET    /api/rules              → all firewall rules
POST   /api/rules              → add new rule
DELETE /api/rules/:id          → delete a rule
POST   /api/rules/:id/toggle   → enable or disable a rule
GET    /api/top-blocked        → top 5 most-blocked source IPs
GET    /api/capture-mode       → current mode: real or simulated
```

---

###  Phase 2 , OOP Refactor + Scapy Integration

Refactored the backend into 6 OOP classes and integrated real packet capture.

**1. Installed Npcap** , the Windows packet driver that gives Python raw socket access:
```
Downloaded: https://npcap.com/#download
Ran as Administrator
✅ Checked "WinPcap API-compatible Mode"
Restarted machine
```

**2. Installed Scapy:**
```bash
pip install scapy
```

**3. Auto-detected the network interface:**
```python
from scapy.all import get_if_list
print(get_if_list())
# ['\Device\NPF_{A1B2C3}',   ← WiFi adapter  (used this one)
#  '\Device\NPF_{D4E5F6}']   ← Ethernet adapter
```

**4. Built `ScapyCapture`** , 80 lines of real capture, parsing, and rule evaluation.

**5. Switched to real capture** , one line:
```python
USE_REAL_CAPTURE = True   # in class FirewallApp
```

**What the Live Monitor shows with real capture:**

| Seen in dashboard | What it actually is |
|------------------|---------------------|
| `192.168.1.1` as destination | Your home router / gateway |
| `142.250.x.x` | Google servers , YouTube, Gmail, Search |
| `162.159.x.x` | Cloudflare , Discord, Notion, many websites |
| `1.1.1.1` / `8.8.8.8` | Public DNS servers |
| TCP port 443 | Every HTTPS site you have open in Chrome |
| UDP port 53 | DNS lookup , fires for every domain you visit |
| TCP port 22 | SSH connection |
| Sudden packet burst | Video buffering or active download |

---

## 🌐 Remote Access (LAN)

Flask binds to `0.0.0.0` , meaning every device on your WiFi can access the dashboard.

**Find your local IP:**
```bash
ipconfig
# Look for: IPv4 Address . . . . : 192.168.1.45
```

**Share the dashboard:**
```
http://192.168.1.45:5000
```

Anyone on the same network opens that URL and sees the full live dashboard , no install, no setup. This is exactly how pfSense works: one machine runs the firewall, everyone else manages it through a browser.

---

## 📦 Installation

### Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Python 3.11+ | Backend runtime | [python.org](https://python.org) |
| Npcap | Windows NIC driver for Scapy | [npcap.com](https://npcap.com/#download) |
| Modern browser | Runs the frontend | Already installed |

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/smart-shield-firewall.git
cd smart-shield-firewall

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install Npcap (Windows only)
#    https://npcap.com/#download
#    Run as Administrator → check "WinPcap API-compatible Mode" → restart

# 4. Run as Administrator (needed for packet capture)
python app.py

# 5. Open browser
http://localhost:5000
```

Login with **any** username and password , demo authentication.

---

## 🔌 Full API Reference

Base URL: `http://localhost:5000`

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/stats` | , | `{total, allowed, blocked, rules}` |
| GET | `/api/packets?limit=20` | , | Array of packet objects |
| GET | `/api/traffic` | , | 25-point hourly chart data |
| GET | `/api/rules` | , | Array of rule objects |
| POST | `/api/rules` | `{name,src,dst,proto,action}` | Created rule |
| DELETE | `/api/rules/:id` | , | `{deleted: id}` |
| POST | `/api/rules/:id/toggle` | , | Updated rule |
| GET | `/api/top-blocked` | , | `[{ip, hits}]` |
| GET | `/api/capture-mode` | , | `{mode, message}` |

**Example , add a rule via curl:**
```bash
curl -X POST http://localhost:5000/api/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"Block Telnet","src":"Any","dst":"Any","proto":"TCP","action":"Block"}'
```

---

## 🧠 Concepts Covered

| Concept | Where in this project |
|---------|----------------------|
| Raw packet capture | `ScapyCapture._on_packet()` |
| Network protocols | `RuleEngine.resolve_protocol()` , TCP/UDP/ICMP/DNS |
| Port number mapping | `COMMON_PORTS` dict , 443→HTTPS, 53→DNS, 22→SSH |
| Firewall rule logic | `RuleEngine.evaluate()` , priority-ordered rule scan |
| CIDR subnet matching | Source/destination IP parsing in `RuleEngine` |
| Multithreading | Scapy capture + Flask server running simultaneously |
| Thread safety | `PacketStore._lock` using `threading.Lock()` |
| OOP architecture | 6 single-responsibility classes |
| REST API design | Proper HTTP verbs , GET / POST / DELETE |
| Client-server model | React frontend ↔ Flask backend over HTTP |
| Real-time UI | `useEffect` polls `/api/packets` every 2 seconds |
| Ring buffer | `PacketStore` , fixed size, oldest packets dropped |
| Data visualization | Chart.js area charts and donut charts |

---

## 🔮 Future Improvements

- [ ] **Real blocking** , Windows Filtering Platform (WFP) / Linux `iptables`
- [ ] **GeoIP** , resolve IPs to countries, show flags on the network map
- [ ] **WebSocket** , replace polling with push for sub-second latency
- [ ] **Alerts** , email or Slack notification when blocked traffic spikes
- [ ] **Export** , download logs as CSV or PDF
- [ ] **Docker** , single `docker run` command to deploy anywhere
- [ ] **Authentication** , real login with hashed passwords and session tokens
- [ ] **HTTPS** , TLS certificate for the management console

---

## ⚠️ Troubleshooting

| Problem | Solution |
|---------|---------|
| `No module named 'scapy'` | `pip install scapy` |
| `No module named 'flask'` | `pip install flask` |
| `Sniffing requires root` | Right-click terminal → Run as Administrator |
| No interfaces found | Install Npcap and restart your machine |
| Charts not loading | Need internet (Chart.js + React load from CDN) |
| Other device can't connect | Allow port 5000 in Windows Defender Firewall |

---

## 👨‍💻 Author

**Salman Khan**  
Real-Time Packet Monitoring & Threat Detection Dashboard — A hands-on learning project for understanding network security, packet capture, and firewall architecture

---

*© 2026 Smart Shield Firewall , Learn network security by building a real firewall dashboard*
