/* NetFend dashboard — plain JavaScript, no frameworks, no external deps.
   Polls the local read-only API and renders real measurements only. */
"use strict";

const $ = (id) => document.getElementById(id);
const state = { ifaces: new Set() };

function fmtBits(bps) {
  if (bps == null) return "—";
  if (bps > 1e9) return (bps / 1e9).toFixed(2) + " Gbit/s";
  if (bps > 1e6) return (bps / 1e6).toFixed(1) + " Mbit/s";
  if (bps > 1e3) return (bps / 1e3).toFixed(1) + " kbit/s";
  return bps.toFixed(0) + " bit/s";
}
function fmtTime(ts) {
  return ts ? new Date(ts * 1000).toLocaleTimeString() : "—";
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

async function api(name) {
  const r = await fetch("/api/" + name, { cache: "no-store" });
  if (!r.ok) throw new Error(name + " -> " + r.status);
  return r.json();
}

/* ---------------- charts (hand-rolled canvas, offline capable) --------- */
function drawLine(canvas, series, colors) {
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  let max = 1;
  for (const s of series) for (const v of s.values) if (v > max) max = v;
  // grid
  ctx.strokeStyle = "rgba(130,150,179,.15)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) {
    const y = (H / 4) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }
  series.forEach((s, si) => {
    const n = s.values.length;
    if (n < 2) return;
    ctx.strokeStyle = colors[si];
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    s.values.forEach((v, i) => {
      const x = (i / (n - 1)) * W;
      const y = H - 6 - (v / max) * (H - 20);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  });
  // max label
  ctx.fillStyle = "rgba(130,150,179,.8)";
  ctx.font = "11px system-ui";
  ctx.fillText(fmtBits(max), 6, 12);
}

/* ---------------- panels ---------------- */
async function refreshOverview() {
  const d = await api("overview");
  $("ov-iface").textContent = d.identity.interface || "—";
  $("ov-conn").textContent = d.identity.link_up ? "up" : "down";
  $("ov-ip").textContent = d.identity.my_ip || "—";
  $("ov-mac").textContent = d.identity.my_mac || "—";
  $("ov-gw").textContent = d.identity.gateway_ip || "—";
  $("ov-gwmac").textContent = d.identity.gateway_mac || "unresolved";
  const h = $("ov-health");
  h.textContent = d.health.status;
  h.className = "big " + (d.health.status === "healthy" ? "ok"
    : d.health.status === "down" ? "crit" : "warn");
  const w = d.wifi || {};
  $("ov-wifi").textContent = w.ssid
    ? `${w.ssid} (${w.rssi ?? "?"} dBm)` : (w.connected === false ? "not connected" : "—");
  $("ov-verdict").textContent = d.health.explanation;

  const hist = d.metrics.history || [];
  drawLine($("chart-throughput"),
    [{ values: hist.map((p) => p.rx_bps) }, { values: hist.map((p) => p.tx_bps) }],
    ["#38bdf8", "#a78bfa"]);
  const t = d.metrics.throughput;
  $("ov-rate").textContent =
    `↓ ${fmtBits(t.rx_bps)}   ↑ ${fmtBits(t.tx_bps)}   (${t.rx_pps.toFixed(0)}/${t.tx_pps.toFixed(0)} pps)`;
  if (d.identity.interface) state.ifaces.add(d.identity.interface);
}

function renderEvents(container, events) {
  container.innerHTML = events.length ? events.map((e) => `
    <div class="ev">
      <span class="t">${fmtTime(e.timestamp)}</span>
      <span class="k">${esc(e.kind)}</span>
      <span class="s sev-${e.severity}">${e.severity}</span>
      <span class="conf conf-${e.confidence}" title="confidence">${e.confidence}</span>
      <span>${esc(e.summary)}</span>
    </div>`).join("")
    : `<p class="note">No events match the current filters.</p>`;
}

async function refreshSecurity() {
  const d = await api("security");
  const fw = $("sec-fw");
  fw.textContent = d.firewall.applied ? "active" :
    (d.firewall.available ? "inactive" : "unavailable");
  fw.className = "big " + (d.firewall.applied ? "ok" : "warn");
  $("sec-fw-profile").textContent = d.firewall.profile;
  const drops = Object.values(d.firewall.counters || {})
    .reduce((a, c) => a + (c.packets || 0), 0);
  $("sec-fw-drops").textContent = drops;
  const c = d.counts_24h;
  $("sec-counts").innerHTML = `
    <div class="kv"><span>ARP events</span><b>${c.arp}</b></div>
    <div class="kv"><span>DHCP events</span><b>${c.dhcp}</b></div>
    <div class="kv"><span>DNS events</span><b>${c.dns}</b></div>
    <div class="kv"><span>Wi-Fi events</span><b>${c.wifi}</b></div>`;
  $("sec-threats").innerHTML = d.threats.length
    ? d.threats.map((t) => `<div class="kv"><span>${esc(t.mac)}<br>
        <small>${esc(t.techniques.join(", "))}</small></span>
        <b class="sev-${t.threat_level === "HOSTILE" || t.threat_level === "CRITICAL" ? "critical" : "warning"}">
        ${t.threat_level} (${t.total_attacks})</b></div>`).join("")
    : "No known hostile profiles.";

  const qs = new URLSearchParams();
  const sev = $("f-severity").value, kind = $("f-kind").value,
        iface = $("f-iface").value, search = $("f-search").value.trim();
  if (sev) qs.set("severity", sev);
  if (kind) qs.set("kind", kind);
  if (iface) qs.set("iface", iface);
  qs.set("limit", "150");
  const evd = await api("events?" + qs.toString());
  let events = evd.events;
  if (search) {
    const s = search.toLowerCase();
    events = events.filter((e) =>
      e.summary.toLowerCase().includes(s) || e.kind.toLowerCase().includes(s));
  }
  // iface filter options (from events seen so far)
  events.forEach((e) => e.interface && state.ifaces.add(e.interface));
  const sel = $("f-iface");
  [...state.ifaces].forEach((i) => {
    if (![...sel.options].some((o) => o.value === i)) {
      const o = document.createElement("option");
      o.value = i; o.textContent = i; sel.appendChild(o);
    }
  });
  renderEvents($("sec-events"), events);
}

async function refreshAttacks() {
  const d = await api("attack_protection");
  const arp = $("at-arp");
  arp.textContent = d.arp.integrity === "ok"
    ? (d.arp_events.length ? `${d.arp_events.length} recent ARP alerts` : "nominal")
    : "gateway unresolved";
  arp.className = "big " + (d.arp_events.length ? "warn" : "ok");
  $("at-pin").textContent = d.arp.gateway_pinned ? "pinned (static)" : "not pinned";

  const dhcpEv = d.dhcp.events || [];
  const dhcp = $("at-dhcp");
  dhcp.textContent = dhcpEv.length ? dhcpEv.length + " alerts" : "nominal";
  dhcp.className = "big " + (dhcpEv.length ? "warn" : "ok");
  $("at-dhcp-srv").textContent = (d.dhcp.baseline.baseline_servers || []).join(", ") || "learning…";

  const dnsEv = d.dns.events || [];
  const dns = $("at-dns");
  dns.textContent = dnsEv.length ? dnsEv.length + " alerts" : "nominal";
  dns.className = "big " + (dnsEv.length ? "warn" : "ok");
  $("at-dns-srv").textContent = (d.dns.resolvers || []).join(", ") || "—";

  const wifiEv = d.wifi_disruption.events || [];
  const wifi = $("at-wifi");
  wifi.textContent = wifiEv.length ? wifiEv.length + " alerts" : "nominal";
  wifi.className = "big " + (wifiEv.length ? "warn" : "ok");
  $("at-mon").textContent = d.wifi_disruption.monitor_mode ? "available" : "unavailable";

  const defs = d.protections_active;
  $("at-defenses").innerHTML = Object.entries(defs).map(([k, v]) =>
    `<span class="chip" style="${v ? "" : "opacity:.35;text-decoration:line-through"}">
     ${k.replace(/_/g, " ")}${v ? "" : " (off)"}</span>`).join("");
  $("at-unavailable").innerHTML = (d.unavailable_protections || [])
    .map((u) => `<span class="chip">${esc(u)}</span>`).join("")
    || `<span class="chip">none — all supported protections active</span>`;

  const all = [...(d.arp_events || []), ...dhcpEv, ...dnsEv, ...wifiEv]
    .sort((a, b) => b.timestamp - a.timestamp).slice(0, 40);
  renderEvents($("at-events"), all);
}

async function refreshTopology() {
  const d = await api("topology");
  const box = $("topo");
  const nodes = d.nodes.map((n) => `
    <div class="node ${n.type}">
      <h4>${esc(n.label)}</h4>
      <div class="ip">${esc(n.ip || "—")}</div>
      <div class="mac">${esc(n.mac || "")}</div>
      ${n.observation ? `<div class="obs">${esc(n.observation)}</div>` : ""}
      ${n.authorized != null ? `<div class="obs">${n.authorized ? "authorized (bookkeeping)" : "unauthorized label"}</div>` : ""}
    </div>`);
  const edges = d.edges.map(() => `<div class="link">→</div>`);
  // self → gateway first, then others
  const self = nodes[0] || "";
  const gw = d.nodes.find((n) => n.type === "gateway");
  const others = d.nodes.filter((n) => n.type === "host").map((n, i) => nodes[d.nodes.indexOf(n)]);
  box.innerHTML =
    `<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center">
      ${self} ${gw ? edges[0] || "" : ""} ${gw ? nodes[d.nodes.indexOf(gw)] : ""}
     </div>
     <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:10px">${others.join("")}</div>
     <p class="note">${esc(d.note)}</p>`;
}

async function refreshPerformance() {
  const d = await api("performance");
  $("pf-cpu").textContent = d.metrics.engine.cpu_pct + " %";
  $("pf-mem").textContent = d.metrics.engine.mem_mb.toFixed(1) + " MB";
  $("pf-rtt").textContent =
    d.metrics.latency.rtt_ms != null ? d.metrics.latency.rtt_ms + " ms"
    : (d.metrics.latency.gw_ok === false ? "gateway unreachable" : "measuring…");
  $("pf-loss").textContent = d.metrics.latency.loss_pct + " %";
  const dnsEl = $("pf-dns");
  const ok = d.dns.last_probe && d.dns.last_probe.ok;
  dnsEl.textContent = d.dns.last_probe ? (ok ? "ok" : "failing") : "—";
  dnsEl.className = "big " + (d.dns.last_probe ? (ok ? "ok" : "crit") : "");
  $("pf-dns-t").textContent = d.dns.last_probe
    ? d.dns.last_probe.elapsed_s + " s" : "—";
  $("pf-explain").textContent = d.health.explanation;
  const w = d.wifi.current || {};
  $("pf-wifi").innerHTML = `
    <div class="kv"><span>SSID</span><b>${esc(w.ssid || "—")}</b></div>
    <div class="kv"><span>Signal</span><b>${w.rssi != null ? w.rssi + " dBm" : "—"}</b></div>
    <div class="kv"><span>TX bitrate</span><b>${w.tx_bitrate != null ? w.tx_bitrate + " MBit/s" : "—"}</b></div>
    <div class="kv"><span>State</span><b>${esc(w.assoc_state || "—")}</b></div>
    <div class="kv"><span>Monitor mode</span><b>${d.wifi.monitor_mode_capable ? "available" : "unavailable (802.11w recommended on AP)"}</b></div>`;
  const hist = d.metrics.history || [];
  drawLine($("chart-pps"),
    [{ values: hist.map((p) => p.rx_pps) }, { values: hist.map((p) => p.tx_pps) }],
    ["#38bdf8", "#a78bfa"]);
}

/* ---------------- main loop ---------------- */
const REFRESHERS = {
  overview: refreshOverview,
  security: refreshSecurity,
  attacks: refreshAttacks,
  topology: refreshTopology,
  performance: refreshPerformance,
};
let activePanel = "overview";

async function tick() {
  try {
    await REFRESHERS[activePanel]();
    $("conn-badge").textContent = "live";
    $("conn-badge").className = "badge online";
  } catch (e) {
    $("conn-badge").textContent = "engine unreachable";
    $("conn-badge").className = "badge offline";
  }
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    activePanel = btn.dataset.panel;
    $("panel-" + activePanel).classList.add("active");
    tick();
  });
});
["f-severity", "f-kind", "f-iface"].forEach((id) =>
  $(id).addEventListener("change", () => activePanel === "security" && tick()));
$("f-search").addEventListener("input",
  () => activePanel === "security" && tick());

tick();
setInterval(tick, 2000);
