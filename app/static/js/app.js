/* Security Dashboard front-end controller */
(() => {
  "use strict";
  const $ = (s, p = document) => p.querySelector(s);
  const $$ = (s, p = document) => Array.from(p.querySelectorAll(s));
  let netChart = null;
  let currentView = "overview";
  let pollTimer = null;
  const VIEW_TITLES = {overview:"Overview",connections:"Connections",firewall:"Firewall",
    ids:"IDS / fail2ban",alerts:"Alerts",scanner:"Offensive Scanner"};

  // ---- helpers ----
  async function api(path, opts) {
    try {
      const res = await fetch(path, opts);
      if (res.status === 401) { window.location.href = "/login"; return null; }
      return await res.json();
    } catch (e) { setStatus(false); return null; }
  }
  function setStatus(ok) {
    const dot = $("#conn-status");
    dot.classList.toggle("ok", ok); dot.classList.toggle("bad", !ok);
  }
  function fmtBytes(b) {
    if (b === 0 || b == null) return "0 B";
    const u = ["B","KB","MB","GB","TB"]; const i = Math.floor(Math.log(b)/Math.log(1024));
    return (b/Math.pow(1024,i)).toFixed(1)+" "+u[i];
  }
  function fmtRate(bps){ return fmtBytes(bps)+"/s"; }
  function fmtUptime(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
    return (d?d+"d ":"")+h+"h "+m+"m";}
  function esc(s){const d=document.createElement("div");d.textContent=s==null?"":String(s);return d.innerHTML;}
  function timeAgo(iso){const t=new Date(iso).getTime();const s=Math.floor((Date.now()-t)/1000);
    if(s<60)return s+"s ago";if(s<3600)return Math.floor(s/60)+"m ago";
    if(s<86400)return Math.floor(s/3600)+"h ago";return Math.floor(s/86400)+"d ago";}

  // ---- navigation ----
  function switchView(view) {
    currentView = view;
    $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === view));
    $$(".view").forEach(v => v.classList.add("hidden"));
    const el = $("#view-" + view); if (el) el.classList.remove("hidden");
    $("#view-title").textContent = VIEW_TITLES[view] || view;
    refresh();
  }
  $$(".nav-item").forEach(n => n.addEventListener("click", () => switchView(n.dataset.view)));
  $("#refresh-btn").addEventListener("click", refresh);

  // ---- OVERVIEW ----
  async function loadOverview() {
    const d = await api("/api/overview");
    if (!d || !d.ok) return; setStatus(true);
    $("#s-conns").textContent = d.network.established_count;
    $("#s-listen").textContent = d.network.listening_count;
    $("#s-blocked").textContent = d.blocked_count;
    $("#s-banned").textContent = d.ids.total_banned || 0;
    $("#s-alerts").textContent = d.alerts.unacknowledged || 0;

    const sys = d.system;
    $("#sys-status").innerHTML = [
      ["Hostname", sys.hostname],
      ["CPU", sys.cpu_percent + "% (" + sys.cpu_count + " cores)"],
      ["Load avg", `${sys.load_avg["1m"]} / ${sys.load_avg["5m"]} / ${sys.load_avg["15m"]}`],
      ["Memory", `${sys.memory.percent}% of ${fmtBytes(sys.memory.total)}`],
      ["Disk /", `${sys.disk.percent}% of ${fmtBytes(sys.disk.total)}`],
      ["Uptime", fmtUptime(sys.uptime_seconds)],
    ].map(([k,v]) => `<div class="kv-row"><span class="k">${k}</span><span>${esc(v)}</span></div>`).join("");

    $("#svc-health").innerHTML = Object.entries(sys.services).map(([k,v]) => {
      const up = v === "active";
      return `<div class="kv-row"><span class="k">${esc(k)}</span>
        <span class="badge ${up?'badge-up':'badge-down'}">${esc(v)}</span></div>`;
    }).join("") + `<div class="kv-row"><span class="k">firewall (${esc(d.firewall.backend)})</span>
      <span class="badge ${d.firewall.backend_active?'badge-up':'badge-down'}">${d.firewall.backend_active?'active':'inactive'}</span></div>`
      + (d.firewall.enforce?"":`<div class="kv-row"><span class="k">enforcement</span><span class="badge badge-dry">DRY-RUN</span></div>`);

    const tb = $("#talkers-tbl tbody");
    tb.innerHTML = (d.network.top_talkers||[]).map(t =>
      `<tr><td>${esc(t.ip)}</td><td>${t.count}</td>
       <td><button class="btn btn-danger btn-xs" data-block="${esc(t.ip)}">Block</button></td></tr>`).join("")
      || `<tr><td colspan="3" class="muted">No active remote connections</td></tr>`;
    $$("[data-block]", tb).forEach(b => b.addEventListener("click", () => blockIp(b.dataset.block, "high traffic")));
    updateNetChart(d.network.current_rate);
  }

  function updateNetChart(rate) {
    const ctx = $("#net-chart");
    if (!netChart) {
      netChart = new Chart(ctx, {
        type: "line",
        data: {labels: [], datasets: [
          {label:"Recv", data:[], borderColor:"#3fb950", backgroundColor:"#3fb95022", tension:.3, fill:true},
          {label:"Sent", data:[], borderColor:"#2f81f7", backgroundColor:"#2f81f722", tension:.3, fill:true},
        ]},
        options: {responsive:true, animation:false, plugins:{legend:{labels:{color:"#8b949e"}}},
          scales:{x:{ticks:{color:"#8b949e"},grid:{color:"#283040"}},
            y:{ticks:{color:"#8b949e",callback:v=>fmtBytes(v)+"/s"},grid:{color:"#283040"}}}}
      });
    }
    const now = new Date().toLocaleTimeString();
    const ds = netChart.data;
    ds.labels.push(now); ds.datasets[0].data.push(rate.recv_bps||0); ds.datasets[1].data.push(rate.sent_bps||0);
    if (ds.labels.length > 30){ds.labels.shift();ds.datasets[0].data.shift();ds.datasets[1].data.shift();}
    netChart.update();
  }

  // ---- CONNECTIONS ----
  async function loadConnections() {
    const d = await api("/api/connections");
    if (!d || !d.ok) return; setStatus(true);
    const filter = ($("#conn-filter").value || "").toLowerCase();
    const rows = d.connections.filter(c => !filter ||
      (c.laddr+c.raddr+c.process+c.status).toLowerCase().includes(filter));
    $("#conn-tbl tbody").innerHTML = rows.map(c => {
      const rip = c.raddr ? c.raddr.split(":")[0] : "";
      return `<tr><td>${esc(c.proto)}</td><td>${esc(c.laddr)}</td><td>${esc(c.raddr)}</td>
        <td>${esc(c.status)}</td><td>${esc(c.pid||"")}</td><td>${esc(c.process||"")}</td>
        <td>${rip&&c.status==="ESTABLISHED"?`<button class="btn btn-danger btn-xs" data-block="${esc(rip)}">Block</button>`:""}</td></tr>`;
    }).join("") || `<tr><td colspan="7" class="muted">No connections</td></tr>`;
    $$("[data-block]", $("#conn-tbl")).forEach(b => b.addEventListener("click", () => blockIp(b.dataset.block, "manual from connections")));
  }
  $("#conn-filter").addEventListener("input", loadConnections);

  // ---- FIREWALL ----
  async function loadFirewall() {
    const d = await api("/api/firewall/status");
    if (!d || !d.ok) return; setStatus(true);
    $("#fw-mode-note").innerHTML = d.status.enforce
      ? `Backend: <code>${esc(d.status.backend)}</code> — <b>enforcing</b> rules on the system.`
      : `Backend: <code>${esc(d.status.backend)}</code> — <b>DRY-RUN</b> mode (blocks are recorded & logged but not applied). Enable <code>firewall.enforce</code> in config to enforce.`;
    $("#blocked-tbl tbody").innerHTML = d.blocked.map(b =>
      `<tr><td>${esc(b.ip)}</td><td>${esc(b.reason)}</td><td>${timeAgo(b.ts)}</td><td>${esc(b.actor)}</td>
       <td>${b.enforced?'<span class="badge badge-up">yes</span>':'<span class="badge badge-dry">dry</span>'}</td>
       <td><button class="btn btn-ghost btn-xs" data-unblock="${esc(b.ip)}">Unblock</button></td></tr>`).join("")
      || `<tr><td colspan="6" class="muted">No blocked IPs</td></tr>`;
    $$("[data-unblock]").forEach(b => b.addEventListener("click", async () => {
      await api("/api/firewall/unblock",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({ip:b.dataset.unblock})}); loadFirewall();
    }));
    $("#fw-rules").textContent = d.status.rules_preview || "(no rules / insufficient privilege)";
  }
  async function blockIp(ip, reason) {
    const r = await api("/api/firewall/block",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ip, reason})});
    if (r && r.ok) { if(currentView==="firewall")loadFirewall(); else refresh(); }
    else alert((r && r.error) || "block failed");
  }
  $("#block-btn").addEventListener("click", () => {
    const ip = $("#block-ip").value.trim();
    if (ip) { blockIp(ip, $("#block-reason").value.trim()); $("#block-ip").value=""; $("#block-reason").value=""; }
  });

  // ---- IDS ----
  async function loadIDS() {
    const d = await api("/api/ids/status");
    if (!d || !d.ok) return; setStatus(true);
    $("#ids-unavailable").style.display = d.available ? "none" : "block";
    const cont = $("#jails-container");
    if (!d.available || !d.jails || !d.jails.length) {
      cont.innerHTML = d.available ? `<div class="card"><p class="muted">No fail2ban jails configured.</p></div>` : "";
      return;
    }
    cont.innerHTML = d.jails.map(j => `
      <div class="card">
        <div class="card-head"><h3>Jail: ${esc(j.jail)}</h3>
          <span class="muted small">currently banned: <b>${j.currently_banned}</b> · total: ${j.total_banned}</span></div>
        <div class="kv-list" style="flex-direction:row;gap:24px;flex-wrap:wrap">
          <span class="muted">Currently failed: <b>${j.currently_failed}</b></span>
          <span class="muted">Total failed: <b>${j.total_failed}</b></span>
        </div>
        <table class="tbl" style="margin-top:10px"><thead><tr><th>Banned IP</th><th></th></tr></thead>
          <tbody>${(j.banned_ips||[]).map(ip=>`<tr><td>${esc(ip)}</td>
            <td><button class="btn btn-ghost btn-xs" data-unban="${esc(ip)}" data-jail="${esc(j.jail)}">Unban</button></td></tr>`).join("")
            || `<tr><td colspan="2" class="muted">No banned IPs</td></tr>`}</tbody></table>
      </div>`).join("");
    $$("[data-unban]").forEach(b => b.addEventListener("click", async () => {
      await api("/api/ids/unban",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({ip:b.dataset.unban,jail:b.dataset.jail})}); loadIDS();
    }));
  }

  // ---- ALERTS ----
  async function loadAlerts() {
    const sev = $("#alert-sev-filter").value;
    const d = await api("/api/alerts?limit=200" + (sev?"&min_severity="+sev:""));
    if (!d || !d.ok) return; setStatus(true);
    $("#alerts-list").innerHTML = d.alerts.map(a => `
      <div class="alert-item sev-${esc(a.severity)}">
        <span class="sev-badge">${esc(a.severity)}</span>
        <div class="alert-body"><div>${esc(a.message)}</div>
          <div class="alert-meta">${esc(a.source)} · ${timeAgo(a.ts)} ${a.acknowledged?'· ✓ ack':''}</div></div>
        ${a.acknowledged?'':`<button class="btn btn-ghost btn-xs" data-ack="${a.id}">Ack</button>`}
      </div>`).join("") || `<p class="muted">No alerts.</p>`;
    $$("[data-ack]").forEach(b => b.addEventListener("click", async () => {
      await api("/api/alerts/ack",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({id:parseInt(b.dataset.ack)})}); loadAlerts();
    }));
  }
  $("#alert-sev-filter") && $("#alert-sev-filter").addEventListener("change", loadAlerts);

  // ---- SCANNER ----
  let profilesCache = [];
  async function initScanner() {
    if (!$("#scan-profile")) return;
    const d = await api("/api/scan/profiles");
    if (!d || !d.ok) return;
    profilesCache = d.profiles;
    $("#scan-profile").innerHTML = d.profiles.map(p => `<option value="${esc(p.key)}">${esc(p.label)}</option>`).join("");
    updateProfileDesc();
    $("#allowlist-note").innerHTML = (d.allowlist && d.allowlist.length)
      ? `Allow-list active. Permitted targets: <code>${d.allowlist.map(esc).join("</code>, <code>")}</code>`
      : `⚠️ No target allow-list configured — add CIDRs to <code>offensive.target_allowlist</code> in config to restrict scanning.`;
  }
  function updateProfileDesc(){
    const p = profilesCache.find(x => x.key === $("#scan-profile").value);
    $("#profile-desc").textContent = p ? p.desc : "";
  }
  $("#scan-profile") && $("#scan-profile").addEventListener("change", updateProfileDesc);
  $("#scan-btn") && $("#scan-btn").addEventListener("click", async () => {
    const msg = $("#scan-msg");
    const body = {target:$("#scan-target").value.trim(), profile:$("#scan-profile").value,
      ports:$("#scan-ports").value.trim(), authorized:$("#scan-auth").checked};
    msg.textContent = "starting…";
    const r = await api("/api/scan/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    if (r && r.ok){ msg.textContent="Scan started ("+r.scan_id+")"; loadScans(); }
    else { msg.textContent = (r && r.error) || "failed"; }
  });
  async function loadScans() {
    if (!$("#scans-tbl")) return;
    const d = await api("/api/scan/list");
    if (!d || !d.ok) return; setStatus(true);
    $("#scans-tbl tbody").innerHTML = d.scans.map(s => {
      const open = s.summary && s.summary.total_open_ports != null ? s.summary.total_open_ports : "—";
      const stColor = s.status==="completed"?"badge-up":(s.status==="failed"?"badge-down":"badge-dry");
      return `<tr><td>${esc(s.target)}</td><td>${esc(s.profile_label)}</td>
        <td><span class="badge ${stColor}">${esc(s.status)}</span></td>
        <td>${timeAgo(s.started)}</td><td>${open}</td>
        <td><button class="btn btn-ghost btn-xs" data-scan="${esc(s.id)}">View</button></td></tr>`;
    }).join("") || `<tr><td colspan="6" class="muted">No scans yet</td></tr>`;
    $$("[data-scan]").forEach(b => b.addEventListener("click", () => showScan(b.dataset.scan)));
  }
  async function showScan(id) {
    const d = await api("/api/scan/" + id);
    if (!d || !d.ok) return;
    const s = d.scan;
    $("#scan-detail-card").classList.remove("hidden");
    $("#scan-detail-target").textContent = s.target + " — " + s.profile_label;
    let html = "";
    if (s.status === "running") html = `<p class="muted">Scan in progress… reopen in a moment.</p>`;
    else if (s.status === "failed") html = `<p class="error-msg">${esc(s.error||"failed")}</p>`;
    if (s.hosts && s.hosts.length) {
      html += s.hosts.map(h => `
        <div class="card" style="background:var(--panel-2)">
          <h3>${esc(h.address)} ${h.hostname?'('+esc(h.hostname)+')':''}
            <span class="badge ${h.state==='up'?'badge-up':'badge-down'}">${esc(h.state)}</span></h3>
          ${h.os?`<p class="muted small">OS guess: ${esc(h.os)}</p>`:""}
          <div>${(h.ports||[]).map(p=>`<span class="port-tag"><b>${p.port}/${esc(p.protocol)}</b>
            ${esc(p.service)} ${esc(p.product)} ${esc(p.version)}</span>`).join("") || '<span class="muted">no open ports</span>'}</div>
          ${(h.scripts&&h.scripts.length)?`<h4 style="margin-top:10px">NSE findings</h4>
            <pre class="code-block">${h.scripts.map(sc=>esc(sc.id+": "+sc.output)).join("\n\n")}</pre>`:""}
        </div>`).join("");
    } else if (s.status === "completed") html += `<p class="muted">No hosts up / no open ports found.</p>`;
    $("#scan-detail-body").innerHTML = html;
  }
  $("#scan-detail-close") && $("#scan-detail-close").addEventListener("click", () =>
    $("#scan-detail-card").classList.add("hidden"));

  // ---- refresh dispatcher ----
  function refresh() {
    $("#last-update").textContent = "updated " + new Date().toLocaleTimeString();
    switch (currentView) {
      case "overview": loadOverview(); break;
      case "connections": loadConnections(); break;
      case "firewall": loadFirewall(); break;
      case "ids": loadIDS(); break;
      case "alerts": loadAlerts(); break;
      case "scanner": loadScans(); break;
    }
  }

  // ---- password modal ----
  function checkPwModal() {
    // Show only if URL hash indicates must_change (set after login redirect not used here);
    // we conservatively offer it via a localStorage flag-less heuristic: skip by default.
  }
  $("#pw-save") && $("#pw-save").addEventListener("click", async () => {
    const pw = $("#new-pw").value;
    const r = await api("/api/change_password",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({new_password:pw})});
    if (r && r.ok) $("#pw-modal").classList.add("hidden");
    else $("#pw-error").textContent = (r && r.error) || "failed";
  });
  $("#pw-skip") && $("#pw-skip").addEventListener("click", () => $("#pw-modal").classList.add("hidden"));

  // ---- boot ----
  initScanner();
  switchView("overview");
  pollTimer = setInterval(refresh, 5000);
})();
