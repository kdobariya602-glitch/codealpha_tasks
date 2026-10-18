const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
let latest = [];
let lastError = "";
let sessionStart = null;

async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function setStatus(message, kind = "normal") {
  $("status").textContent = message;
  $("statusStrip").classList.toggle("error", kind === "error");
  $("statusStrip").classList.toggle("working", kind === "working");
}
function fmtBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
function protocolClass(protocol) {
  return ({TCP:"tcp", UDP:"udp", DNS:"dns", ICMP:"icmp", ARP:"arp"})[protocol] || "other";
}
function render() {
  const query = $("search").value.trim().toLowerCase();
  const selectedProtocol = $("protocolFilter").value;
  const visible = latest.slice().reverse().filter(packet => {
    const text = [packet.timestamp, packet.protocol, packet.source_ip, packet.destination_ip,
      packet.source_port, packet.destination_port, packet.summary, packet.payload_preview].join(" ").toLowerCase();
    return (!query || text.includes(query)) && (selectedProtocol === "all" || packet.protocol === selectedProtocol);
  });
  $("total").textContent = latest.length;
  $("showing").textContent = `Showing ${visible.length} of ${latest.length} packets`;
  if (latest.some(packet => packet.sample_data)) { setStatus("Sample data loaded — these are simulated examples, not live traffic."); }
  if (!visible.length) {
    $("rows").innerHTML = `<tr><td colspan="6" class="empty-cell"><span class="empty-graphic">⌁</span><b>${latest.length ? "No matching packets" : "No packets captured yet"}</b><small>${latest.length ? "Try a different search or protocol filter." : "Start a capture to see live network traffic here."}</small></td></tr>`;
  } else {
    $("rows").innerHTML = visible.map(packet => {
      const source = `${esc(packet.source_ip)}${packet.source_port !== "" ? `:${esc(packet.source_port)}` : ""}`;
      const destination = `${esc(packet.destination_ip)}${packet.destination_port !== "" ? `:${esc(packet.destination_port)}` : ""}`;
      const details = `${esc(packet.summary || "Packet observed")}`;
      const payload = esc(packet.payload_preview || "No printable payload");
      const time = esc((packet.timestamp || "").replace("T", " ").replace(/([+-]\d\d:\d\d|Z)$/, ""));
      return `<tr><td class="time-cell">${time}</td><td><span class="protocol-badge ${protocolClass(packet.protocol)}">${esc(packet.protocol)}</span></td><td class="ip-cell">${source}</td><td class="ip-cell">${destination}</td><td class="size-cell">${esc(packet.packet_length_bytes)} <small>B</small></td><td class="detail-cell"><b>${details}</b><span class="payload-preview" title="Limited to 48 bytes">${payload}</span></td></tr>`;
    }).join("");
  }
  $("statPackets").textContent = latest.length.toLocaleString();
  const protocols = [...new Set(latest.map(p => p.protocol))];
  $("statProtocols").textContent = protocols.length;
  $("protocolSummary").textContent = protocols.length ? protocols.join(" · ") : "Waiting for traffic";
  $("statBytes").innerHTML = `${fmtBytes(latest.reduce((sum, p) => sum + Number(p.packet_length_bytes || 0), 0))}`;
}
async function refresh() {
  try {
    const data = await api("/api/status");
    latest = Array.isArray(data.records) ? data.records : [];
    render();
    $("start").disabled = data.running;
    $("stop").disabled = !data.running;
    $("clear").disabled = data.running;
    $("statState").textContent = data.running ? "Capturing" : (data.error ? "Error" : (latest.some(p => p.sample_data) ? "Demo data" : (latest.length ? "Complete" : "Ready")));
    $("statSub").textContent = data.running ? "Listening for packets" : (latest.length ? "Session not running" : "No active capture");
    if (data.running) setStatus(`Capturing packets… ${latest.length} observed so far.`, "working");
    else if (data.error) {
      if (lastError !== data.error) { setStatus(data.error, "error"); lastError = data.error; }
    } else if (data.stopped_by_user) setStatus(`Capture stopped. ${latest.length} packets collected.`);
    else if (latest.some(p => p.sample_data)) setStatus("Sample data loaded — these are simulated examples, not live traffic.");
    else if (latest.length) setStatus(`Capture finished. ${latest.length} packets collected; CSV export is ready.`);
    if (data.started_at) {
      const date = new Date(data.started_at);
      $("sessionTime").textContent = `STARTED ${date.toLocaleTimeString()}`;
    } else $("sessionTime").textContent = "LOCALHOST";
  } catch (error) {
    setStatus(`Cannot contact the local server: ${error.message}. Check that py app.py is still running.`, "error");
    $("statState").textContent = "Offline";
  }
}
$("start").addEventListener("click", async () => {
  try {
    lastError = "";
    const data = await api("/api/start", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({count:$("count").value, iface:$("iface").value, filter:$("filter").value})});
    latest = [];
    render();
    setStatus(data.message, "working");
    await refresh();
  } catch (error) { setStatus(error.message, "error"); }
});
$("stop").addEventListener("click", async () => {
  try { const data = await api("/api/stop", {method:"POST"}); setStatus(data.message, "working"); await refresh(); }
  catch (error) { setStatus(error.message, "error"); }
});
$("refresh").addEventListener("click", refresh);
$("clear").addEventListener("click", async () => {
  try { const data = await api("/api/clear", {method:"POST"}); latest = []; lastError = ""; render(); setStatus(data.message); await refresh(); }
  catch (error) { setStatus(error.message, "error"); }
});
$("demo").addEventListener("click", async () => {
  try {
    const data = await api("/api/demo", {method:"POST"});
    lastError = "";
    setStatus(data.message);
    await refresh();
  } catch (error) { setStatus(error.message, "error"); }
});
$("search").addEventListener("input", render);
$("protocolFilter").addEventListener("change", render);
setInterval(refresh, 2000);
refresh();
