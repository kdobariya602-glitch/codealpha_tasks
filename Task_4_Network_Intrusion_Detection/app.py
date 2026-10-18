"""Task 4: Network Intrusion Detection System (NIDS) learning dashboard.
Single-file Flask app. Built-in alerts are synthetic; this app does not capture live traffic.
"""
from flask import Flask, render_template_string, jsonify, request
from collections import Counter
import json

app = Flask(__name__)
HTML = r'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Network Intrusion Detection Lab</title><link rel="stylesheet" href="/static/style.css"></head><body><header><a class="brand" href="/">CA <span>INTRUSION DETECTION</span></a><span class="lab">TASK 04 · LAB MODE</span></header><main><div class="eyebrow">CODEALPHA · NETWORK DEFENSE</div><h1>Network Intrusion<br><span>Detection System</span></h1><p class="lead">Inspect Suricata-style alerts, parse EVE JSON, and review the rules used to detect suspicious activity.</p><div class="notice"><b>Important:</b> The included alert events are synthetic. Live monitoring requires Suricata installed and configured separately on an authorized network. An alert is not proof of compromise.</div>\n<section class="panel"><div class="panel-head"><h2>Alert dashboard</h2><button id="load">Load sample alerts</button></div><div class="stats"><div><b id="total">—</b><span>Total alerts</span></div><div><b id="signatures">—</b><span>Unique signatures</span></div><div><b>03</b><span>Example rules</span></div></div><p id="message" role="status">Click Load sample alerts to populate the table.</p><div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Signature</th><th>Severity</th></tr></thead><tbody id="rows"><tr><td colspan="5" class="empty">No alerts loaded.</td></tr></tbody></table></div></section>\n<section class="panel"><h2>Parse EVE JSON logs</h2><p class="muted">Paste newline-delimited JSON events from a Suricata EVE log. This local tool extracts events whose event_type is alert.</p><textarea id="log" rows="7" placeholder=\'{"event_type":"alert","src_ip":"192.0.2.10","dest_ip":"192.0.2.20","alert":{"signature":"Example alert","severity":2}}\'></textarea><button id="parse">Parse log</button><p id="parse-result" role="status"></p></section>\n<section class="panel"><h2>Example local rules</h2><pre><code>alert icmp any any -> $HOME_NET any (msg:"LAB ICMP echo request observed"; itype:8; sid:1000001; rev:1;)\nalert tcp any any -> $HOME_NET 22 (msg:"LAB inbound SSH connection attempt"; flags:S; flow:stateless; sid:1000002; rev:1;)\nalert http any any -> $HOME_NET any (msg:"LAB HTTP request for suspicious admin path"; flow:to_server,established; http.uri; content:"/admin-backup"; nocase; sid:1000003; rev:1;)</code></pre><p class="muted">Validate and tune these rules for your installed Suricata version and authorized HOME_NET. HTTPS URI paths are encrypted unless inspected at an authorized TLS termination point.</p></section>\n<section class="panel"><h2>Incident response workflow</h2><ol><li>Validate the alert and correlate related logs.</li><li>Assess impact and determine whether the activity is expected.</li><li>Follow authorized response procedures and preserve evidence.</li><li>Document actions and tune false positives.</li></ol></section><footer>Task 4 · Flask · Suricata rules · EVE JSON</footer></main><script src="/static/app.js"></script></body></html>\n'
CSS = r':root{--ink:#14243a;--blue:#1769e0;--muted:#66778d;--line:#dfe7f0;--bg:#f5f8fc}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 Inter,system-ui,Segoe UI,sans-serif}header{height:70px;background:#fff;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;padding:0 max(20px,calc((100% - 1050px)/2))}.brand{font-weight:900;text-decoration:none;color:var(--ink)}.brand span{font-size:.75rem;color:var(--blue);margin-left:10px}.lab{font-size:.68rem;color:#16794a;font-weight:850;letter-spacing:.1em}main{max-width:1050px;margin:auto;padding:48px 24px}.eyebrow{font-size:.72rem;letter-spacing:.13em;font-weight:850;color:var(--blue)}h1{font-size:clamp(2.6rem,7vw,4.2rem);line-height:1.03;letter-spacing:-.06em;margin:14px 0}h1 span{color:var(--blue)}h2{font-size:1.2rem;margin:0}.lead,.muted{color:var(--muted)}.notice{background:#fff7e8;border:1px solid #f1dfbb;padding:15px;border-radius:8px;font-size:.88rem;margin:25px 0}.panel{background:#fff;border:1px solid var(--line);border-radius:10px;padding:22px;margin:18px 0}.panel-head{display:flex;justify-content:space-between;align-items:center;gap:12px}button{background:var(--blue);border:0;border-radius:6px;color:#fff;padding:10px 14px;font:inherit;font-weight:750;cursor:pointer}.stats{display:flex;gap:45px;padding:18px 0;border-bottom:1px solid var(--line)}.stats div{display:grid}.stats b{font-size:1.55rem}.stats span{font-size:.8rem;color:var(--muted)}#message,#parse-result{font-size:.84rem;color:var(--muted)}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:650px;font-size:.82rem}th,td{text-align:left;padding:12px;border-bottom:1px solid #edf1f5;vertical-align:top}th{background:#f8fafc;color:var(--muted);font-size:.7rem;text-transform:uppercase}.empty{text-align:center;color:var(--muted);padding:25px}textarea{display:block;width:100%;border:1px solid var(--line);border-radius:6px;padding:12px;font:inherit;margin:12px 0;resize:vertical}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#14243a;color:#e3efff;padding:16px;border-radius:7px;font-size:.8rem}ol{color:var(--muted)}footer{border-top:1px solid var(--line);padding-top:20px;color:var(--muted);font-size:.8rem;margin-top:28px}@media(max-width:600px){header{padding:0 15px}.lab{font-size:.58rem}main{padding:30px 15px}.panel{padding:15px}.stats{gap:20px}}\n'
JS = r'''const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[char]));

async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function render(data) {
  const events = Array.isArray(data.events) ? data.events : [];
  $("total").textContent = data.total ?? events.length;
  $("signatures").textContent = Object.keys(data.counts || {}).length;
  $("rows").innerHTML = events.length
    ? events.map(event => `<tr><td>${esc(event.timestamp)}</td><td>${esc(event.source)}</td><td>${esc(event.destination)}</td><td>${esc(event.signature)}</td><td>${esc(event.severity)}</td></tr>`).join("")
    : '<tr><td colspan="5" class="empty">No alert events found.</td></tr>';
}

$("load").addEventListener("click", async () => {
  const button = $("load");
  button.disabled = true;
  $("message").textContent = "Loading sample alerts…";
  try {
    const data = await api("/api/sample");
    render(data);
    $("message").textContent = `Loaded ${data.total} synthetic alert(s). These are examples, not evidence of real attacks.`;
  } catch (error) {
    $("message").textContent = `Could not load sample alerts: ${error.message}. Check that the Flask server is still running, then refresh the page.`;
  } finally {
    button.disabled = false;
  }
});

$("parse").addEventListener("click", async () => {
  const button = $("parse");
  button.disabled = true;
  $("parse-result").textContent = "Parsing log…";
  try {
    const data = await api("/api/parse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: $("log").value })
    });
    render(data);
    $("parse-result").textContent = `Parsed ${data.total} alert(s). ${data.malformed} malformed line(s) skipped.`;
  } catch (error) {
    $("parse-result").textContent = `Could not parse log: ${error.message}`;
  } finally {
    button.disabled = false;
  }
});
'''
RULES = r'# CodeAlpha NIDS lab rules — use only in an authorized lab.\n# These are examples for learning and may need tuning to your network.\nalert icmp any any -> $HOME_NET any (msg:"LAB ICMP echo request observed"; itype:8; sid:1000001; rev:1;)\nalert tcp any any -> $HOME_NET 22 (msg:"LAB inbound SSH connection attempt"; flags:S; flow:stateless; sid:1000002; rev:1;)\nalert http any any -> $HOME_NET any (msg:"LAB HTTP request for suspicious admin path"; flow:to_server,established; http.uri; content:"/admin-backup"; nocase; sid:1000003; rev:1;)\n'
SAMPLE_EVE = r'{"timestamp":"2026-10-17T10:30:00.000000+0000","event_type":"alert","src_ip":"192.0.2.25","src_port":53122,"dest_ip":"198.51.100.10","dest_port":22,"alert":{"signature":"LAB inbound SSH connection attempt","severity":3,"signature_id":1000002}}\n{"timestamp":"2026-10-17T10:31:00.000000+0000","event_type":"alert","src_ip":"192.0.2.30","src_port":0,"dest_ip":"198.51.100.10","dest_port":0,"alert":{"signature":"LAB ICMP echo request observed","severity":3,"signature_id":1000001}}\n{"timestamp":"2026-10-17T10:32:00.000000+0000","event_type":"flow","src_ip":"192.0.2.30","dest_ip":"198.51.100.10"}\n'

@app.get("/")
def index():
    page = HTML.replace('<link rel="stylesheet" href="/static/style.css">', '<style>' + CSS + '</style>')
    page = page.replace('<script src="/static/app.js"></script>', '<script>' + JS + '</script>')
    page = page.replace('<!-- RULES_PLACEHOLDER -->', RULES)
    return render_template_string(page)

def parse_eve(raw):
    events, malformed = [], 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
            if e.get("event_type") != "alert":
                continue
            alert = e.get("alert") or {}
            events.append({
                "timestamp": e.get("timestamp", "?"),
                "source": f"{e.get('src_ip', '?')}:{e.get('src_port', '?')}",
                "destination": f"{e.get('dest_ip', '?')}:{e.get('dest_port', '?')}",
                "signature": alert.get("signature", "Unknown signature"),
                "severity": alert.get("severity", 3),
            })
        except (json.JSONDecodeError, TypeError):
            malformed += 1
    return events, malformed

def response_for(raw, synthetic=False):
    events, malformed = parse_eve(raw)
    return {"events": events, "total": len(events),
            "counts": dict(Counter(e["signature"] for e in events)),
            "malformed": malformed, "synthetic": synthetic}

@app.get("/api/sample")
def sample():
    return jsonify(response_for(SAMPLE_EVE, synthetic=True))

@app.post("/api/parse")
def parse_api():
    data = request.get_json(silent=True) or {}
    raw = data.get("text", "")
    if not isinstance(raw, str) or len(raw) > 1_000_000:
        return jsonify({"error": "Log text must be a string under 1 MB."}), 400
    return jsonify(response_for(raw))

if __name__ == "__main__":
    print("Task 4 NIDS dashboard: http://127.0.0.1:5004")
    print("Note: synthetic sample alerts only; live monitoring requires separately configured Suricata.")
    app.run(host="127.0.0.1", port=5004, debug=False)
