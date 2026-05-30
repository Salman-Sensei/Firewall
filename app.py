"""
Smart Shield Firewall — Backend
================================
Author  : Salman Khan
Version : 2.0
Stack   : Python 3.11 · Flask 3.1 · Scapy 2.5

Architecture:
  FirewallConfig   — stores rules & settings
  RuleEngine       — evaluates packets against rules
  PacketStore      — thread-safe packet buffer
  PacketSimulator  — fallback simulated traffic (always active)
  ScapyCapture     — real NIC capture via Scapy (built, ready)
  FirewallApp      — Flask API that wires everything together
"""

from flask import Flask, jsonify, send_from_directory, request
from datetime import datetime
import threading
import random
import time


# ══════════════════════════════════════════════════════════════
#  CLASS 1 — FirewallConfig
#  Holds all rules and global firewall settings
# ══════════════════════════════════════════════════════════════
class FirewallConfig:
    DEFAULT_RULES = [
        {"id":1,"name":"Allow Local Network",   "src":"192.168.1.0/24","dst":"Any",           "proto":"Any",       "action":"Allow","priority":1,"active":True},
        {"id":2,"name":"Block Suspicious IPs",  "src":"Any",           "dst":"203.0.113.0/24","proto":"Any",       "action":"Block","priority":2,"active":True},
        {"id":3,"name":"Allow DNS",             "src":"Any",           "dst":"8.8.8.8",       "proto":"UDP",       "action":"Allow","priority":3,"active":True},
        {"id":4,"name":"Block P2P Traffic",     "src":"Any",           "dst":"Any",           "proto":"BitTorrent","action":"Block","priority":4,"active":False},
        {"id":5,"name":"Allow HTTP/HTTPS",      "src":"Any",           "dst":"Any",           "proto":"TCP:80,443","action":"Allow","priority":5,"active":True},
        {"id":6,"name":"Block SSH Brute Force", "src":"Any",           "dst":"Any",           "proto":"TCP:22",    "action":"Block","priority":6,"active":True},
        {"id":7,"name":"Allow ICMP Ping",       "src":"Any",           "dst":"Any",           "proto":"ICMP",      "action":"Allow","priority":7,"active":False},
    ]

    BLOCKED_SUBNETS = ["203.0.113.", "198.51.100.", "192.0.2."]

    def __init__(self):
        self.rules    = list(self.DEFAULT_RULES)
        self.enabled  = True
        self.log_level = "Info"
        self.default_action = "Deny"

    def get_active_rules(self):
        return sorted(
            [r for r in self.rules if r["active"]],
            key=lambda r: r["priority"]
        )

    def add_rule(self, data):
        new = {
            "id":       int(time.time()),
            "name":     data.get("name",   "New Rule"),
            "src":      data.get("src",    "Any"),
            "dst":      data.get("dst",    "Any"),
            "proto":    data.get("proto",  "Any"),
            "action":   data.get("action", "Allow"),
            "priority": len(self.rules) + 1,
            "active":   True,
        }
        self.rules.append(new)
        return new

    def delete_rule(self, rule_id):
        self.rules = [r for r in self.rules if r["id"] != rule_id]

    def toggle_rule(self, rule_id):
        for r in self.rules:
            if r["id"] == rule_id:
                r["active"] = not r["active"]
                return r
        return None


# ══════════════════════════════════════════════════════════════
#  CLASS 2 — RuleEngine
#  Evaluates a packet against FirewallConfig rules
# ══════════════════════════════════════════════════════════════
class RuleEngine:
    COMMON_PORTS = {
        80:"HTTP", 443:"HTTPS", 53:"DNS", 22:"SSH", 21:"FTP",
        25:"SMTP", 110:"POP3", 143:"IMAP", 3389:"RDP",
        8080:"HTTP-ALT", 8443:"HTTPS-ALT",
    }

    def __init__(self, config: FirewallConfig):
        self.config = config

    def evaluate(self, src_ip, dst_ip, proto, dport=0):
        """
        Evaluate a packet against all active rules.
        Returns 'Allowed' or 'Blocked'.
        """
        for rule in self.config.get_active_rules():

            # ── Source IP match ──────────────────────────────
            if rule["src"] != "Any":
                subnet = rule["src"].replace("/24","").rsplit(".",1)[0]
                if not src_ip.startswith(subnet):
                    continue

            # ── Destination IP match ─────────────────────────
            if rule["dst"] != "Any":
                subnet = rule["dst"].replace("/24","").rsplit(".",1)[0]
                if not dst_ip.startswith(subnet) and rule["dst"] != dst_ip:
                    continue

            # ── Protocol match ───────────────────────────────
            if rule["proto"] == "Any":
                return rule["action"]

            if ":" in rule["proto"]:
                rule_proto, ports = rule["proto"].split(":")
                if proto == rule_proto and str(dport) in ports.split(","):
                    return rule["action"]
                continue

            if rule["proto"] == proto:
                return rule["action"]

        # ── Blocked subnets (hardcoded threat list) ──────────
        for subnet in FirewallConfig.BLOCKED_SUBNETS:
            if src_ip.startswith(subnet) or dst_ip.startswith(subnet):
                return "Blocked"

        return self.config.default_action

    def resolve_protocol(self, proto_num, dport=0, sport=0):
        """Convert raw protocol number / port to human-readable name."""
        if proto_num == 6:   # TCP
            return self.COMMON_PORTS.get(dport, self.COMMON_PORTS.get(sport, "TCP"))
        if proto_num == 17:  # UDP
            return "DNS" if dport == 53 or sport == 53 else "UDP"
        if proto_num == 1:   # ICMP
            return "ICMP"
        return "IP"


# ══════════════════════════════════════════════════════════════
#  CLASS 3 — PacketStore
#  Thread-safe ring buffer of the last N captured packets
#  Also tracks running statistics
# ══════════════════════════════════════════════════════════════
class PacketStore:
    def __init__(self, max_size=100):
        self._packets  = []
        self._lock     = threading.Lock()
        self._max_size = max_size
        self.stats = {"total": 0, "allowed": 0, "blocked": 0, "rules": 7}

    def push(self, packet: dict):
        with self._lock:
            self._packets.insert(0, packet)
            self._packets = self._packets[:self._max_size]
            self.stats["total"] += 1
            if packet["status"] == "Allowed":
                self.stats["allowed"] += 1
            else:
                self.stats["blocked"] += 1

    def get_recent(self, limit=20):
        with self._lock:
            return list(self._packets[:limit])

    def get_stats(self):
        with self._lock:
            return dict(self.stats)

    def get_top_blocked(self, n=5):
        with self._lock:
            blocked = [p for p in self._packets if p["status"] == "Blocked"]
        counts = {}
        for p in blocked:
            counts[p["srcIP"]] = counts.get(p["srcIP"], 0) + 1
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
        return [{"ip": ip, "hits": hits} for ip, hits in top]


# ══════════════════════════════════════════════════════════════
#  CLASS 4 — PacketSimulator
#  Generates realistic-looking fake traffic
#  (Active in current deployment)
# ══════════════════════════════════════════════════════════════
class PacketSimulator:
    SAMPLE_IPS = [
        "192.168.1.2","10.0.0.5","172.16.0.8","8.8.8.8",
        "203.0.113.45","142.250.80.1","162.159.130.1","1.1.1.1",
        "198.51.100.23","91.198.174.192",
    ]
    PROTOCOLS = ["TCP","UDP","ICMP","HTTP","HTTPS","DNS","SSH","FTP"]
    INFOS = [
        "HTTP Request","DNS Query","Ping Request","HTTPS Connection",
        "SSH Handshake","TLS Handshake","GET /index.html",
        "POST /api/data","UDP Datagram","SYN Packet",
    ]

    def __init__(self, store: PacketStore, engine: RuleEngine, interval=0.9):
        self.store    = store
        self.engine   = engine
        self.interval = interval
        self._running = False

    def _make_packet(self):
        src   = random.choice(self.SAMPLE_IPS)
        dst   = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(0,254)}"
        proto = random.choice(self.PROTOCOLS)
        info  = random.choice(self.INFOS)
        dport = random.choice([80, 443, 53, 22, 8080, 3389, random.randint(1024,65535)])
        status = self.engine.evaluate(src, dst, proto, dport)
        return {
            "id":     int(time.time() * 1000) + random.randint(0, 999),
            "time":   datetime.now().strftime("%H:%M:%S"),
            "srcIP":  src,
            "dstIP":  dst,
            "proto":  proto,
            "info":   info,
            "status": status,
            "bytes":  random.randint(64, 65535),
        }

    def _run(self):
        while self._running:
            self.store.push(self._make_packet())
            time.sleep(self.interval)

    def start(self):
        self._running = True
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        print("  📊 PacketSimulator  → started (simulated traffic)")

    def stop(self):
        self._running = False


# ══════════════════════════════════════════════════════════════
#  CLASS 5 — ScapyCapture
#  Real packet capture from your machine's NIC using Scapy
#
#  Requirements:
#    pip install scapy
#    Install Npcap → https://npcap.com/#download  (Windows)
#    Run app.py as Administrator
#
#  Status: Built & integrated — activate by setting
#          USE_REAL_CAPTURE = True  in FirewallApp.__init__
# ══════════════════════════════════════════════════════════════
class ScapyCapture:
    """
    Captures live packets from the machine's NIC and feeds them
    into PacketStore through the RuleEngine.

    How it works:
      1. Scapy calls on_packet() for every IP packet on the NIC
      2. on_packet() extracts src/dst IP, protocol, port, size
      3. RuleEngine.evaluate() decides Allow / Block
      4. Packet dict is pushed into PacketStore
      5. Flask API serves PacketStore data to the React frontend
    """

    COMMON_PORTS = {
        80:"HTTP", 443:"HTTPS", 53:"DNS", 22:"SSH",
        21:"FTP", 25:"SMTP", 3389:"RDP", 8080:"HTTP-ALT",
    }

    def __init__(self, store: PacketStore, engine: RuleEngine):
        self.store  = store
        self.engine = engine
        self._iface = None

    def _auto_detect_interface(self):
        """Pick the first non-loopback interface Scapy can see."""
        from scapy.all import get_if_list
        ifaces = get_if_list()
        # prefer interfaces that aren't loopback
        for iface in ifaces:
            if "loopback" not in iface.lower() and iface != "lo":
                return iface
        return ifaces[0] if ifaces else None

    def _get_protocol(self, pkt):
        from scapy.all import TCP, UDP, ICMP
        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            return self.COMMON_PORTS.get(dport, self.COMMON_PORTS.get(sport, "TCP"))
        if UDP in pkt:
            return "DNS" if pkt[UDP].dport == 53 or pkt[UDP].sport == 53 else "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "IP"

    def _get_info(self, pkt):
        from scapy.all import TCP, UDP, ICMP
        if TCP in pkt:
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport
            if flags == 0x02: return "SYN — New Connection"
            if flags == 0x12: return "SYN+ACK — Handshake"
            if flags == 0x11: return "FIN+ACK — Closing"
            name = self.COMMON_PORTS.get(dport, f"TCP:{dport}")
            return f"{name} Request"
        if UDP in pkt:
            return "DNS Query" if pkt[UDP].dport == 53 else "UDP Datagram"
        if ICMP in pkt:
            t = pkt[ICMP].type
            return "Ping Request" if t == 8 else "Ping Reply" if t == 0 else f"ICMP Type {t}"
        return "IP Packet"

    def _on_packet(self, pkt):
        """Scapy calls this for every captured packet."""
        from scapy.all import IP, TCP, UDP
        if IP not in pkt:
            return

        src   = pkt[IP].src
        dst   = pkt[IP].dst
        proto = self._get_protocol(pkt)
        info  = self._get_info(pkt)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        size  = len(pkt)
        status = self.engine.evaluate(src, dst, proto, dport)

        self.store.push({
            "id":     int(time.time() * 1000) + random.randint(0, 999),
            "time":   datetime.now().strftime("%H:%M:%S"),
            "srcIP":  src,
            "dstIP":  dst,
            "proto":  proto,
            "info":   info,
            "status": status,
            "bytes":  size,
        })

    def start(self):
        """Start sniffing on the auto-detected NIC."""
        from scapy.all import sniff
        self._iface = self._auto_detect_interface()
        print(f"  📡 ScapyCapture     → capturing on {self._iface}")

        def _run():
            sniff(
                iface=self._iface,
                prn=self._on_packet,
                store=False,
                filter="ip",       # only IP packets
            )

        t = threading.Thread(target=_run, daemon=True)
        t.start()


# ══════════════════════════════════════════════════════════════
#  CLASS 6 — FirewallApp
#  Wires everything together and exposes Flask REST API
# ══════════════════════════════════════════════════════════════
class FirewallApp:

    USE_REAL_CAPTURE = False  # ← Set True + run as Admin to use ScapyCapture

    def __init__(self):
        self.flask_app = Flask(__name__, static_folder=".", static_url_path="")

        # Instantiate core components
        self.config  = FirewallConfig()
        self.engine  = RuleEngine(self.config)
        self.store   = PacketStore(max_size=100)

        # Choose capture mode
        if self.USE_REAL_CAPTURE:
            self.capture = ScapyCapture(self.store, self.engine)
        else:
            self.capture = PacketSimulator(self.store, self.engine)

        self._register_routes()

    # ── Startup ─────────────────────────────────────────────
    def start(self):
        self._print_banner()
        self.capture.start()
        self.flask_app.run(debug=False, port=5000, host="0.0.0.0")

    def _print_banner(self):
        mode = "🟢 REAL (Scapy)" if self.USE_REAL_CAPTURE else "🟡 Simulated"
        print("\n" + "="*52)
        print("  🛡️  SMART SHIELD FIREWALL")
        print("="*52)
        print(f"  Capture : {mode}")
        print(f"  URL     : http://localhost:5000")
        print(f"  API     : http://localhost:5000/api/stats")
        print("="*52 + "\n")

    # ── Routes ──────────────────────────────────────────────
    def _register_routes(self):
        app = self.flask_app

        @app.route("/")
        def index():
            return send_from_directory(".", "index.html")

        @app.route("/api/stats")
        def get_stats():
            stats = self.store.get_stats()
            stats["rules"] = len(self.config.rules)
            return jsonify(stats)

        @app.route("/api/packets")
        def get_packets():
            limit = int(request.args.get("limit", 20))
            return jsonify(self.store.get_recent(limit))

        @app.route("/api/traffic")
        def get_traffic():
            data = []
            for i in range(25):
                a = random.randint(700, 3800)
                b = random.randint(80,  900)
                data.append({
                    "time":    f"{str(i).zfill(2)}:00",
                    "packets": a + b,
                    "allowed": a,
                    "blocked": b,
                })
            return jsonify(data)

        @app.route("/api/rules", methods=["GET"])
        def get_rules():
            return jsonify(self.config.rules)

        @app.route("/api/rules", methods=["POST"])
        def add_rule():
            rule = self.config.add_rule(request.json)
            self.store.stats["rules"] = len(self.config.rules)
            return jsonify(rule), 201

        @app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
        def delete_rule(rule_id):
            self.config.delete_rule(rule_id)
            return jsonify({"deleted": rule_id})

        @app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
        def toggle_rule(rule_id):
            rule = self.config.toggle_rule(rule_id)
            if rule:
                return jsonify(rule)
            return jsonify({"error": "not found"}), 404

        @app.route("/api/top-blocked")
        def get_top_blocked():
            return jsonify(self.store.get_top_blocked())

        @app.route("/api/capture-mode")
        def capture_mode():
            return jsonify({
                "mode":    "real" if self.USE_REAL_CAPTURE else "simulated",
                "message": "ScapyCapture active" if self.USE_REAL_CAPTURE else "PacketSimulator active",
            })


# ── Entry point ────────────────────────────────────────────────
if __name__ == "__main__":
    FirewallApp().start()
