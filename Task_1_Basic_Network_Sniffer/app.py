from flask import Flask, render_template, request, jsonify, Response
import csv
import io
import threading
import datetime

"""Packet metadata capture for the CodeAlpha Basic Network Sniffer task.

Captures only a short, printable payload preview (up to 48 bytes) rather than
storing full packet payloads. Use only on networks you own or are authorized
 to monitor.
"""

import datetime
import threading


def _record_packet(pkt, layers):
    IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw = layers
    src = dst = "—"
    protocol = "OTHER"
    source_port = destination_port = ""
    ttl = ""
    info = pkt.summary()

    if pkt.haslayer(IP):
        src, dst, ttl = pkt[IP].src, pkt[IP].dst, int(pkt[IP].ttl)
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        ttl = int(pkt[IPv6].hlim)
    if pkt.haslayer(ARP):
        src, dst, protocol = pkt[ARP].psrc or "—", pkt[ARP].pdst or "—", "ARP"
    if pkt.haslayer(TCP):
        protocol = "TCP"
        source_port, destination_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        source_port, destination_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    if pkt.haslayer(DNS):
        protocol = "DNS"
        if pkt.haslayer(DNSQR):
            try:
                info = "DNS query: " + pkt[DNSQR].qname.decode("utf-8", "replace").rstrip(".")
            except Exception:
                info = "DNS packet"

    payload_preview = "No printable payload"
    payload_hex = ""
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load[:48])
        payload_hex = raw.hex(" ")
        printable = "".join(chr(b) if 32 <= b <= 126 else "·" for b in raw)
        payload_preview = printable or "Binary payload"
        if len(bytes(pkt[Raw].load)) > 48:
            payload_preview += "…"

    timestamp = datetime.datetime.fromtimestamp(
        float(pkt.time), tz=datetime.timezone.utc
    ).astimezone().isoformat(timespec="milliseconds")

    return {
        "timestamp": timestamp,
        "source_ip": src,
        "destination_ip": dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_length_bytes": len(pkt),
        "ttl": ttl,
        "payload_preview": payload_preview,
        "payload_hex": payload_hex,
        "summary": info,
    }


def capture_packets(count=25, iface=None, bpf_filter="ip or ip6 or arp", on_packet=None, stop_event=None):
    """Capture up to count packets and call on_packet immediately for each one."""
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
    except ImportError as exc:
        raise RuntimeError("Scapy is missing. Run: py -m pip install -r requirements.txt") from exc

    layers = (IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw)
    records = []
    stop_event = stop_event or threading.Event()

    def handle(pkt):
        rec = _record_packet(pkt, layers)
        records.append(rec)
        if on_packet:
            on_packet(rec)

    remaining = int(count)
    # Short capture windows allow the Stop button to take effect even when
    # traffic is quiet. The count is the maximum, not a minimum.
    while remaining > 0 and not stop_event.is_set():
        before = len(records)
        sniff(
            iface=iface or None,
            filter=bpf_filter or None,
            prn=handle,
            store=False,
            timeout=1,
            count=remaining,
            stop_filter=lambda _pkt: stop_event.is_set(),
        )
        remaining -= len(records) - before
    return records



app = Flask(__name__)
state = {
    "running": False,
    "records": [],
    "error": None,
    "requested_count": 0,
    "started_at": None,
    "stopped_by_user": False,
}
lock = threading.Lock()
stop_event = threading.Event()
MAX_RECORDS = 1000


def append_record(record):
    with lock:
        state["records"].append(record)
        state["records"] = state["records"][-MAX_RECORDS:]


def worker(count, iface, filt):
    try:
        capture_packets(count=count, iface=iface, bpf_filter=filt,
                        on_packet=append_record, stop_event=stop_event)
    except Exception as exc:
        message = str(exc)
        lowered = message.lower()
        if any(term in lowered for term in ("winpcap", "npcap", "libpcap", "socket", "permission", "access is denied", "not permitted")):
            message += " | Windows tip: install Npcap from its official website, then run the terminal as Administrator."
        with lock:
            state["error"] = message
    finally:
        with lock:
            state["running"] = False


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    with lock:
        return jsonify({
            "running": state["running"],
            "records": list(state["records"]),
            "error": state["error"],
            "requested_count": state["requested_count"],
            "started_at": state["started_at"],
            "stopped_by_user": state["stopped_by_user"],
        })


@app.post("/api/start")
def start():
    data = request.get_json(silent=True) or {}
    try:
        count = int(data.get("count", 50))
    except (TypeError, ValueError):
        return jsonify({"error": "Packet count must be a whole number."}), 400
    if not 1 <= count <= 500:
        return jsonify({"error": "Packet count must be between 1 and 500."}), 400

    iface = (data.get("iface") or "").strip() or None
    filt = (data.get("filter") or "").strip()
    if len(filt) > 200:
        return jsonify({"error": "Capture filter is too long."}), 400

    with lock:
        if state["running"]:
            return jsonify({"error": "A capture is already running. Stop it before starting another."}), 409
        state.update({
            "running": True,
            "records": [],
            "error": None,
            "requested_count": count,
            "started_at": None,
            "stopped_by_user": False,
        })
        stop_event.clear()
        import datetime
        state["started_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

    threading.Thread(target=worker, args=(count, iface, filt), daemon=True).start()
    return jsonify({"message": "Capture started. Incoming packets will appear automatically."})


@app.post("/api/stop")
def stop():
    with lock:
        if not state["running"]:
            return jsonify({"message": "No capture is currently running."})
        state["stopped_by_user"] = True
    stop_event.set()
    return jsonify({"message": "Stop requested. The capture will stop shortly."})


@app.post("/api/clear")
def clear():
    with lock:
        if state["running"]:
            return jsonify({"error": "Stop the capture before clearing results."}), 409
        state["records"] = []
        state["error"] = None
        state["requested_count"] = 0
        state["started_at"] = None
        state["stopped_by_user"] = False
    return jsonify({"message": "Results cleared."})


@app.post("/api/demo")
def demo_data():
    """Load clearly-labelled synthetic records for UI testing only."""
    with lock:
        if state["running"]:
            return jsonify({"error": "Stop live capture before loading sample data."}), 409
        now = datetime.datetime.now().astimezone()
        samples = [
            ("TCP", "192.168.1.20", "142.250.72.14", 51524, 443, 74, 64, "TCP 192.168.1.20:51524 > 142.250.72.14:443 S", "TLS traffic is encrypted"),
            ("DNS", "192.168.1.20", "192.168.1.1", 53120, 53, 82, 64, "DNS query: example.com", "example.com"),
            ("UDP", "192.168.1.20", "8.8.8.8", 53120, 53, 68, 64, "UDP DNS request", "DNS request sample"),
            ("ICMP", "192.168.1.1", "192.168.1.20", "", "", 98, 128, "ICMP echo-reply", "No printable payload"),
            ("ARP", "192.168.1.20", "192.168.1.1", "", "", 60, "", "ARP who-has 192.168.1.1", "Address resolution sample"),
        ]
        state["records"] = [{
            "timestamp": (now - datetime.timedelta(seconds=(len(samples)-i)*2)).isoformat(timespec="milliseconds"),
            "source_ip": src, "destination_ip": dst, "protocol": proto,
            "source_port": sport, "destination_port": dport,
            "packet_length_bytes": size, "ttl": ttl,
            "payload_preview": payload, "payload_hex": "", "summary": summary,
            "sample_data": True
        } for i, (proto, src, dst, sport, dport, size, ttl, summary, payload) in enumerate(samples)]
        state["error"] = None
        state["requested_count"] = len(samples)
        state["started_at"] = now.isoformat(timespec="seconds")
        state["stopped_by_user"] = False
    return jsonify({"message": "Sample data loaded. These are simulated examples, not live network packets."})


@app.get("/api/export")
def export():
    with lock:
        records = list(state["records"])
    fields = ["timestamp", "source_ip", "destination_ip", "protocol", "source_port",
              "destination_port", "packet_length_bytes", "ttl", "payload_preview", "payload_hex", "summary"]
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(records)
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=network_capture.csv"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
