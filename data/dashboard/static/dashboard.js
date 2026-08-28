/* ============================================================
   RESIDENTIAL IoT DEFENSE SYSTEM — Dashboard JavaScript
   Renders all state from the real backend. Zero fake data.
   ============================================================ */

'use strict';

// ── Helpers ──────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const safe = (val, fallback = 'N/A') =>
  (val === null || val === undefined || val === '') ? fallback : val;
const safeNum = (val, digits = 2) =>
  (val === null || val === undefined) ? 'N/A' : Number(val).toFixed(digits);
const safeMs = val =>
  (val === null || val === undefined) ? 'N/A' : `${Number(val).toFixed(1)} ms`;
const escHtml = s => String(s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function fmtTimestamp(ts) {
  if (!ts) return 'N/A';
  try {
    const d = typeof ts === 'number'
      ? new Date(ts * 1000)
      : new Date(ts);
    return d.toLocaleTimeString('en-GB', { hour12: false });
  } catch { return String(ts); }
}

function fmtIso(ts) {
  if (!ts) return 'N/A';
  try {
    const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
    return d.toLocaleTimeString('en-GB', { hour12: false, fractionalSecondDigits: 0 });
  } catch { return String(ts); }
}

// ── Notification ─────────────────────────────────────────────
let _alertTimer = null;
function showAlert(msg, type = 'info') {
  const el = $('alert-banner');
  if (!el) return;
  el.textContent = msg;
  el.className = `alert-banner show ${type}`;
  clearTimeout(_alertTimer);
  _alertTimer = setTimeout(() => { el.className = 'alert-banner'; }, 4000);
}

// ── Clock ────────────────────────────────────────────────────
function startClock() {
  function tick() {
    const el = $('header-clock');
    if (el) el.textContent = new Date().toLocaleString('en-GB', {
      hour12: false, year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).replace(',', ' ·');
  }
  tick();
  setInterval(tick, 1000);
}

// ── Phase → badge class ───────────────────────────────────────
const PHASE_CLASS = {
  IDLE: '', STARTING_NETWORK: 'active', BASELINE: 'active',
  OBSERVING: 'active', THREAT_DETECTED: 'threat', DECIDING: 'threat',
  RESPONDING: 'threat', DECOY_ACTIVE: 'decoy', ISOLATED: 'threat',
  RESTORING: 'active', RESTORED: 'restored', COMPLETE: 'restored',
  ERROR: 'threat', CLEANUP: '',
};

// ── Pipeline phases ───────────────────────────────────────────
const PIPE_STEPS = [
  { id: 'pipe-network',  done: ['BASELINE','OBSERVING','THREAT_DETECTED','DECIDING','RESPONDING','DECOY_ACTIVE','ISOLATED','RESTORING','RESTORED','COMPLETE'] },
  { id: 'pipe-observe',  done: ['THREAT_DETECTED','DECIDING','RESPONDING','DECOY_ACTIVE','ISOLATED','RESTORING','RESTORED','COMPLETE'] },
  { id: 'pipe-detect',   done: ['DECIDING','RESPONDING','DECOY_ACTIVE','ISOLATED','RESTORING','RESTORED','COMPLETE'] },
  { id: 'pipe-context',  done: ['RESPONDING','DECOY_ACTIVE','ISOLATED','RESTORING','RESTORED','COMPLETE'] },
  { id: 'pipe-decision', done: ['DECOY_ACTIVE','ISOLATED','RESTORING','RESTORED','COMPLETE'] },
  { id: 'pipe-response', done: ['RESTORING','RESTORED','COMPLETE'] },
  { id: 'pipe-recovery', done: ['COMPLETE'] },
];

const PIPE_ACTIVE = {
  'STARTING_NETWORK': 'pipe-network',
  'BASELINE': 'pipe-network',
  'OBSERVING': 'pipe-observe',
  'THREAT_DETECTED': 'pipe-detect',
  'DECIDING': 'pipe-context',
  'RESPONDING': 'pipe-decision',
  'DECOY_ACTIVE': 'pipe-response',
  'ISOLATED': 'pipe-response',
  'RESTORING': 'pipe-recovery',
  'RESTORED': 'pipe-recovery',
  'COMPLETE': 'pipe-recovery',
};

function updatePipeline(phase) {
  const activeId = PIPE_ACTIVE[phase] || null;
  PIPE_STEPS.forEach(({ id, done }) => {
    const el = $(id);
    if (!el) return;
    el.classList.remove('active', 'done');
    if (done.includes(phase)) el.classList.add('done');
    else if (id === activeId) el.classList.add('active');
  });
}

// ── Header ────────────────────────────────────────────────────
function renderHeader(state) {
  const phase = safe(state.phase, 'IDLE');
  const badge = $('phase-badge');
  if (badge) {
    badge.textContent = phase;
    badge.className = 'phase-badge ' + (PHASE_CLASS[phase] || '');
  }
  updatePipeline(phase);
}

// ── Topology ─────────────────────────────────────────────────
const NODE_SVG_MAP = {
  sensor:     { bg: 'bg-sensor',   status: 'status-sensor',   link: 'link-sensor' },
  camera:     { bg: 'bg-camera',   status: 'status-camera',   link: 'link-camera' },
  smart_plug: { bg: 'bg-plug',     status: 'status-plug',     link: 'link-plug' },
  attacker:   { bg: 'bg-attacker', status: 'status-attacker', link: 'link-attacker' },
  decoy:      { bg: 'bg-decoy',    status: 'status-decoy',    link: 'link-decoy' },
};

const STATUS_CSS = {
  'ONLINE':       'online',
  'OBSERVING':    'online',
  'ATTACKED':     'attacked',
  'ISOLATED':     'isolated',
  'DECOY ACTIVE': 'decoy',
  'RESTORED':     'restored',
  'OFFLINE':      '',
};

const STATUS_LINK = {
  'ONLINE':       'active',
  'OBSERVING':    'active',
  'ATTACKED':     'attacked',
  'ISOLATED':     'isolated',
  'DECOY ACTIVE': 'decoy',
  'RESTORED':     'restored',
  'OFFLINE':      '',
};

function renderTopology(state) {
  const nodes = state.nodes || {};
  Object.entries(NODE_SVG_MAP).forEach(([name, ids]) => {
    const node = nodes[name] || {};
    const status = String(node.status || 'OFFLINE').toUpperCase();
    const cssClass = STATUS_CSS[status] || '';
    const linkCss  = STATUS_LINK[status] || '';

    const bg = $(ids.bg);
    if (bg) {
      bg.className.baseVal = 'topo-node-bg ' + cssClass;
    }
    const st = $(ids.status);
    if (st) st.textContent = status;

    const lk = $(ids.link);
    if (lk) {
      lk.className.baseVal = 'topo-link ' + linkCss;
    }
  });
}

// ── Live Traffic ─────────────────────────────────────────────
const PROTO_CLASS = { TCP: 'proto-tcp', UDP: 'proto-udp', ICMP: 'proto-icmp', ARP: 'proto-arp' };

function renderTraffic(state) {
  const traffic = state.traffic || [];
  const tbody = $('traffic-tbody');
  const badge = $('traffic-count-badge');
  if (!tbody) return;
  if (badge) badge.textContent = `${traffic.length} pkts`;

  if (!traffic.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Awaiting packets…</td></tr>';
    return;
  }

  const rows = [...traffic].reverse().slice(0, 20).map((pkt, idx) => {
    const proto = String(pkt.protocol || pkt.proto || 'UNKNOWN').toUpperCase();
    const cls = PROTO_CLASS[proto] || '';
    return `<tr class="${idx === 0 ? 'tl-entry-new' : ''}">
      <td>${escHtml(fmtTimestamp(pkt.timestamp))}</td>
      <td class="mono">${escHtml(safe(pkt.src_ip))}</td>
      <td class="mono">${escHtml(safe(pkt.dst_ip))}</td>
      <td class="${cls}">${escHtml(proto)}</td>
      <td>${safe(pkt.src_port)}</td>
      <td>${safe(pkt.dst_port)}</td>
      <td>${safe(pkt.packet_length)}</td>
    </tr>`;
  }).join('');
  tbody.innerHTML = rows;
}

// ── Threat Detection ──────────────────────────────────────────
const THREAT_CONF = {
  NORMAL:         { cls: 'normal',     icon: '✅', label: 'NORMAL',          badgeCls: 'background:rgba(34,197,94,0.1);color:var(--accent-green);border:1px solid rgba(34,197,94,0.3)' },
  SUSPICIOUS:     { cls: 'suspicious', icon: '⚠️', label: 'SUSPICIOUS',       badgeCls: 'background:rgba(245,158,11,0.1);color:var(--accent-amber);border:1px solid rgba(245,158,11,0.3)' },
  THREAT_DETECTED:{ cls: 'threat',     icon: '🚨', label: 'THREAT DETECTED',  badgeCls: 'background:rgba(239,68,68,0.1);color:var(--accent-red);border:1px solid rgba(239,68,68,0.3)' },
};

const FEATURE_DISPLAY = [
  ['packet_count',              'Packet Count'],
  ['packets_per_second',        'Pkts / sec'],
  ['bytes_total',               'Bytes Total'],
  ['average_packet_size',       'Avg Pkt Size'],
  ['unique_destination_ports',  'Unique Dst Ports'],
  ['unique_source_ports',       'Unique Src Ports'],
  ['tcp_syn_count',             'TCP SYN'],
  ['tcp_ack_count',             'TCP ACK'],
  ['udp_packet_count',          'UDP Packets'],
  ['icmp_packet_count',         'ICMP Packets'],
];

function renderThreat(state) {
  const threat_status = String(state.threat_status || 'NORMAL').toUpperCase();
  const conf = THREAT_CONF[threat_status] || THREAT_CONF.NORMAL;
  const te = state.threat_event;

  const bar = $('threat-status-bar');
  if (bar) bar.className = `threat-status-bar ${conf.cls}`;

  const icon = $('threat-icon');
  if (icon) icon.textContent = conf.icon;

  const lbl = $('threat-label');
  if (lbl) lbl.textContent = conf.label;

  const badge = $('threat-badge');
  if (badge) { badge.textContent = conf.label; badge.style.cssText = conf.badgeCls; }

  const scoreEl = $('threat-score-val');
  if (scoreEl) scoreEl.textContent = te ? safeNum(te.threat_score, 2) : '0.00';

  const meta = $('threat-meta');
  const detailWrap = $('threat-details-wrap');

  if (te) {
    if (meta) meta.textContent = safe(te.detection_reason, 'Detection reason unavailable');
    if (detailWrap) detailWrap.style.display = '';

    const atk = $('attack-type');
    if (atk) atk.textContent = safe(te.attack_type);

    const conf_el = $('confidence-val');
    if (conf_el) conf_el.textContent = te.confidence !== undefined ? safeNum(te.confidence, 3) : 'N/A';

    const det = $('detector-name');
    if (det) det.textContent = safe(te.detector_name);

    const reason = $('detection-reason');
    if (reason) reason.textContent = safe(te.detection_reason);

    const tsrc = $('threat-src');
    if (tsrc) tsrc.textContent = safe(te.source_ip);

    const tdst = $('threat-dst');
    if (tdst) tdst.textContent = safe(te.destination_ip);

    const fg = $('feature-grid');
    if (fg) {
      const features = te.features || {};
      const html = FEATURE_DISPLAY.map(([key, label]) => {
        const val = features[key];
        const display = val !== undefined && val !== null
          ? (typeof val === 'number' ? (Number.isInteger(val) ? val : val.toFixed(2)) : val)
          : 'N/A';
        return `<div class="feature-item">
          <div class="feature-name">${escHtml(label)}</div>
          <div class="feature-value">${escHtml(String(display))}</div>
        </div>`;
      }).join('');
      fg.innerHTML = html;
    }
  } else {
    if (meta) meta.textContent = 'No threats detected — system nominal';
    if (detailWrap) detailWrap.style.display = 'none';
  }
}

// ── Security Context (BDI) ────────────────────────────────────
function renderContext(state) {
  const body = $('bdi-body');
  if (!body) return;

  const ctx = state.security_context;
  if (!ctx) {
    body.innerHTML = '<div class="empty-state">Awaiting threat event…</div>';
    return;
  }

  const b = ctx.beliefs || {};
  const d = ctx.desires || {};
  const intention = ctx.intention || 'unknown';

  const beliefRows = [
    ['Threat Type',    b.threat_type],
    ['Threat Score',   b.threat_score !== undefined ? safeNum(b.threat_score, 3) : null],
    ['Confidence',     b.confidence  !== undefined ? safeNum(b.confidence, 3) : null],
    ['Source',         b.source_device],
    ['Destination',    b.destination_device],
    ['Criticality',    b.device_criticality],
    ['History',        b.previous_relevant_events ? `${b.previous_relevant_events.length} events` : null],
  ].map(([k, v]) => `<div class="bdi-row">
    <span class="bdi-key">${escHtml(k)}</span>
    <span class="bdi-val mono">${escHtml(safe(v))}</span>
  </div>`).join('');

  const desires = [
    ['protect_legitimate_iot_service',              'Protect IoT Services'],
    ['contain_malicious_activity',                  'Contain Threats'],
    ['minimize_unnecessary_disruption',             'Min. Disruption'],
    ['gather_attacker_intelligence_when_appropriate','Gather Intel'],
  ].map(([key, label]) => {
    const checked = d[key] === true || d[key] === undefined;
    return `<div class="bdi-desire">
      <span class="desire-check">${checked ? '✓' : '○'}</span>
      <span>${escHtml(label)}</span>
    </div>`;
  }).join('');

  body.innerHTML = `
    <div class="bdi-grid">
      <div class="bdi-section bdi-beliefs">
        <div class="bdi-section-title">Beliefs</div>
        ${beliefRows}
      </div>
      <div class="bdi-section bdi-desires">
        <div class="bdi-section-title">Desires</div>
        ${desires}
      </div>
      <div class="bdi-section bdi-intention">
        <div class="bdi-section-title">Intention</div>
        <div style="margin-top:0.5rem">
          <div class="intention-chip">${escHtml(intention.replace(/_/g,' '))}</div>
        </div>
      </div>
    </div>`;
}

// ── Policy Comparison ─────────────────────────────────────────
function actionChipHtml(action, large = false) {
  if (!action) return '<span class="na-val">N/A</span>';
  const size = large ? 'font-size:1rem;padding:0.4rem 1rem;' : '';
  return `<div class="policy-action-chip action-${escHtml(action)}" style="${size}">${escHtml(action)}</div>`;
}

function renderPolicies(state) {
  const grid = $('policy-grid');
  const selWrap = $('selected-action-wrap');
  if (!grid) return;

  const cmp = state.policy_comparison;
  if (!cmp) {
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1">Awaiting policy evaluation…</div>';
    if (selWrap) selWrap.style.display = 'none';
    return;
  }

  // ── Rule-Based card
  const rb = cmp.rule_based || {};
  const rbHtml = `
    <div class="policy-card pc-rule">
      <div class="policy-card-title">🔵 Rule-Based Policy</div>
      ${actionChipHtml(rb.action)}
      <div class="policy-detail">
        <div class="policy-detail-row">
          <span class="pd-key">Confidence</span>
          <span class="pd-val">${safeNum(rb.confidence, 3)}</span>
        </div>
        <div class="policy-detail-row">
          <span class="pd-key">Threat Score</span>
          <span class="pd-val">${safeNum(rb.threat_score, 3)}</span>
        </div>
        <div class="policy-detail-row">
          <span class="pd-key">Policy</span>
          <span class="pd-val">${escHtml(safe(rb.policy_name))}</span>
        </div>
      </div>
      ${rb.reason ? `<div class="separator"></div><div style="font-size:0.68rem;color:var(--text-muted);line-height:1.4">${escHtml(rb.reason)}</div>` : ''}
    </div>`;

  // ── Stackelberg card
  const sk = cmp.stackelberg || {};
  const sr = cmp.stackelberg_reasoning || {};
  const candidates = sr.candidates || [];
  const candRows = candidates.map(c => {
    const isSel = c.defender_action === sr.selected_action;
    return `<tr class="${isSel ? 'sel-row' : ''}">
      <td>${escHtml(safe(c.defender_action))}</td>
      <td>${escHtml(safe(c.predicted_attacker_strategy))}</td>
      <td>${safeNum(c.attacker_utility, 1)}</td>
      <td>${safeNum(c.defender_utility, 1)}</td>
    </tr>`;
  }).join('');

  const skHtml = `
    <div class="policy-card pc-stack">
      <div class="policy-card-title">🟡 Stackelberg Policy</div>
      ${actionChipHtml(sk.action)}
      <div class="policy-detail">
        <div class="policy-detail-row">
          <span class="pd-key">Attacker Response</span>
          <span class="pd-val">${escHtml(safe(sr.predicted_attacker_strategy))}</span>
        </div>
        <div class="policy-detail-row">
          <span class="pd-key">Attacker Utility</span>
          <span class="pd-val">${safeNum(sr.selected_attacker_utility, 1)}</span>
        </div>
        <div class="policy-detail-row">
          <span class="pd-key">Defender Utility</span>
          <span class="pd-val">${safeNum(sr.selected_defender_utility, 1)}</span>
        </div>
        <div class="policy-detail-row">
          <span class="pd-key">Observed Threat</span>
          <span class="pd-val">${escHtml(safe(sr.observed_threat))}</span>
        </div>
      </div>
      ${candRows ? `
      <div class="separator"></div>
      <div class="label" style="margin-bottom:0.3rem">Strategic Candidates</div>
      <table class="stackelberg-table">
        <thead><tr><th>Action</th><th>Attacker Response</th><th>Atk Util</th><th>Def Util</th></tr></thead>
        <tbody>${candRows}</tbody>
      </table>` : ''}
    </div>`;

  // ── PPO card
  const pp = cmp.ppo;
  const ppoFallback = cmp.ppo_fallback_used;
  const ppoAction = pp ? pp.action : null;
  const ppoAi = pp && pp.context ? pp.context.ppo_action_index : null;
  const ppoHtml = `
    <div class="policy-card pc-ppo">
      <div class="policy-card-title">🟣 PPO Adaptive Policy</div>
      ${actionChipHtml(ppoAction)}
      <div class="policy-detail">
        <div class="policy-detail-row">
          <span class="pd-key">Action Index</span>
          <span class="pd-val">${ppoAi !== null && ppoAi !== undefined ? ppoAi : 'N/A'}</span>
        </div>
        <div class="policy-detail-row">
          <span class="pd-key">Model Status</span>
          <span class="pd-val">${ppoFallback ? 'FALLBACK' : (pp ? 'LOADED' : 'N/A')}</span>
        </div>
        <div class="policy-detail-row">
          <span class="pd-key">Confidence</span>
          <span class="pd-val">${pp ? safeNum(pp.confidence, 3) : 'N/A'}</span>
        </div>
      </div>
      ${pp && pp.reason ? `<div class="separator"></div><div style="font-size:0.68rem;color:var(--text-muted);line-height:1.4">${escHtml(pp.reason.slice(0,180))}</div>` : ''}
    </div>`;

  grid.innerHTML = rbHtml + skHtml + ppoHtml;

  // Selected / Executed / Result summary banner
  const sel = state.selected_decision;
  if (sel && selWrap) {
    selWrap.style.display = '';
    const snEl = $('sel-policy-name');
    if (snEl) snEl.textContent = safe(sel.policy_name);
    const saEl = $('sel-action-chip');
    if (saEl) {
      saEl.textContent = safe(sel.action);
      saEl.className = `policy-action-chip action-${safe(sel.action, 'ALLOW')}`;
    }

    const rr = state.response_result;
    const eaEl = $('exec-action-chip');
    if (eaEl) {
      eaEl.textContent = rr ? safe(rr.action) : 'N/A';
      eaEl.className = rr ? `policy-action-chip action-${safe(rr.action, 'ALLOW')}` : 'sa-action';
    }
    const erEl = $('exec-result-chip');
    if (erEl) {
      const status = rr ? String(safe(rr.status)).toUpperCase() : 'N/A';
      erEl.textContent = status;
      erEl.className = 'sa-action ' + (
        status === 'SUCCESS' ? 'accent-green' :
        status === 'FAILED' ? 'accent-red' :
        status === 'N/A' ? '' : 'accent-amber'
      );
    }

    const srEl = $('sel-reason');
    if (srEl) srEl.textContent = safe(sel.reason);
  } else if (selWrap) {
    selWrap.style.display = 'none';
  }
}

// ── Response ──────────────────────────────────────────────────
function renderResponse(state) {
  const body = $('response-body');
  const badge = $('resp-badge');
  if (!body) return;

  const rr = state.response_result;
  if (!rr) {
    body.innerHTML = '<div class="empty-state">No response executed yet.</div>';
    if (badge) { badge.textContent = 'IDLE'; badge.style.cssText = 'background:rgba(34,197,94,0.1);color:var(--accent-green);border:1px solid rgba(34,197,94,0.3)'; }
    return;
  }

  const action  = safe(rr.action);
  const status  = safe(rr.status);
  const latency = rr.latency_ms !== undefined ? `${Number(rr.latency_ms).toFixed(1)} ms` : 'N/A';
  const details = rr.details || {};

  const statusCss = status === 'success' ? 'status-success' : status === 'failed' ? 'status-failed' : 'status-pending';
  const statusIcon = status === 'success' ? '✅' : status === 'failed' ? '❌' : '⏳';

  // Badge update
  if (badge) {
    badge.textContent = `${action} · ${status.toUpperCase()}`;
    if (status === 'success') badge.style.cssText = 'background:rgba(34,197,94,0.1);color:var(--accent-green);border:1px solid rgba(34,197,94,0.3)';
    else if (status === 'failed') badge.style.cssText = 'background:rgba(239,68,68,0.1);color:var(--accent-red);border:1px solid rgba(239,68,68,0.3)';
    else badge.style.cssText = 'background:rgba(245,158,11,0.1);color:var(--accent-amber);border:1px solid rgba(245,158,11,0.3)';
  }

  let detailHtml = '';

  // DECOY details
  if (action === 'DECOY' && details.operation === 'decoy') {
    const d = details;
    detailHtml = `
      <div class="response-detail-card" style="border-color:rgba(168,85,247,0.3)">
        <div class="rdc-title" style="color:var(--accent-purple)">🪤 Decoy Operation</div>
        <div class="rdc-row"><span class="rdc-key">Decoy Host</span><span class="rdc-val">${escHtml(safe(d.decoy_host))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Decoy IP</span><span class="rdc-val">${escHtml(safe(d.decoy_ip))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Ports</span><span class="rdc-val">${escHtml(safe(JSON.stringify(d.decoy_ports)))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Redirect Mode</span><span class="rdc-val">${escHtml(safe(d.redirect_mode))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Source Host</span><span class="rdc-val">${escHtml(safe(d.source_host))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Requested Target</span><span class="rdc-val">${escHtml(safe(d.requested_target_ip))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Interactions</span><span class="rdc-val">${safe(d.interaction_count, '0')}</span></div>
        <div class="rdc-row"><span class="rdc-key">Latest Interaction</span><span class="rdc-val" style="max-width:220px;white-space:normal">${escHtml(safe(d.interaction))}</span></div>
      </div>`;
  }

  // ISOLATE details
  if (action === 'ISOLATE' && details.operation === 'isolate') {
    detailHtml = `
      <div class="response-detail-card" style="border-color:rgba(245,158,11,0.3)">
        <div class="rdc-title" style="color:var(--accent-amber)">🔒 Isolation Operation</div>
        <div class="rdc-row"><span class="rdc-key">Host</span><span class="rdc-val">${escHtml(safe(details.host))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Interface</span><span class="rdc-val">${escHtml(safe(details.interface))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Interface State</span><span class="rdc-val">${escHtml(safe(details.state))}</span></div>
      </div>`;
  }

  // RESTORE details
  if (details.operation === 'restore') {
    detailHtml = `
      <div class="response-detail-card" style="border-color:rgba(6,182,212,0.3)">
        <div class="rdc-title" style="color:var(--accent-cyan)">♻️ Restoration</div>
        <div class="rdc-row"><span class="rdc-key">Host</span><span class="rdc-val">${escHtml(safe(details.host))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Interface</span><span class="rdc-val">${escHtml(safe(details.interface))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Status</span><span class="rdc-val">${escHtml(safe(details.state || details.status))}</span></div>
      </div>`;
  }

  body.innerHTML = `
    <div class="response-status">
      <div class="rs-icon">${statusIcon}</div>
      <div class="rs-text">
        <div class="rs-action action-${escHtml(action)}">${escHtml(action)}</div>
        <div class="rs-status ${statusCss}">${escHtml(status.toUpperCase())}</div>
      </div>
      <div class="rs-latency">${escHtml(latency)}</div>
    </div>
    <div class="response-grid">
      <div class="response-detail-card">
        <div class="rdc-title">Response Details</div>
        <div class="rdc-row"><span class="rdc-key">Action</span><span class="rdc-val">${escHtml(action)}</span></div>
        <div class="rdc-row"><span class="rdc-key">Target IP</span><span class="rdc-val">${escHtml(safe(rr.target_ip))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Source IP</span><span class="rdc-val">${escHtml(safe(rr.source_ip))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Started</span><span class="rdc-val">${escHtml(fmtIso(rr.started_at))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Completed</span><span class="rdc-val">${escHtml(fmtIso(rr.completed_at))}</span></div>
        <div class="rdc-row"><span class="rdc-key">Latency</span><span class="rdc-val">${escHtml(latency)}</span></div>
        <div class="rdc-row"><span class="rdc-key">Message</span><span class="rdc-val" style="max-width:180px;white-space:normal">${escHtml(safe(rr.message))}</span></div>
      </div>
      ${detailHtml}
    </div>`;
}

// ── Event Timeline ────────────────────────────────────────────
const SEEN_ENTRIES = new Set();

const PHASE_DOT_CLASS = {
  THREAT_DETECTED: 'phase-threat', DECIDING: 'phase-deciding',
  RESPONDING: 'phase-deciding', DECOY_ACTIVE: 'phase-decoy',
  ISOLATED: 'phase-isolated', RESTORING: 'phase-deciding',
  RESTORED: 'phase-restored', COMPLETE: 'phase-complete', ERROR: 'phase-error',
};

function renderTimeline(state) {
  const wrap = $('timeline-wrap');
  const countEl = $('timeline-count');
  if (!wrap) return;

  const events = state.timeline || [];
  if (!events.length) {
    wrap.innerHTML = '<div class="empty-state">No events yet.</div>';
    if (countEl) countEl.textContent = '0 events';
    return;
  }

  if (countEl) countEl.textContent = `${events.length} events`;

  const html = [...events].reverse().map((ev, idx) => {
    const ts = fmtIso(ev.timestamp);
    const phase = safe(ev.phase, '');
    const msg = safe(ev.message, phase);
    const dotCls = PHASE_DOT_CLASS[phase] || '';
    const isNew = idx === 0 ? 'tl-entry-new' : '';
    return `<div class="timeline-entry ${isNew}">
      <div class="tl-time">${escHtml(ts)}</div>
      <div class="tl-dot-col">
        <div class="tl-dot ${dotCls}"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-phase">${escHtml(phase)}</div>
        <div class="tl-message">${escHtml(msg)}</div>
      </div>
    </div>`;
  }).join('');

  wrap.innerHTML = html;
}

// ── Metrics ───────────────────────────────────────────────────
function renderMetrics(state) {
  const m = state.metrics || {};
  const set = (id, val, digits = 0) => {
    const el = $(id);
    if (!el) return;
    el.textContent = (val === null || val === undefined) ? '—' : (digits ? Number(val).toFixed(digits) : val);
  };
  set('m-packets',      m.packets_observed);
  set('m-flows',        m.flows_analyzed);
  set('m-threats',      m.threats_detected);
  set('m-decoy',        m.decoy_interactions);
  set('m-isolations',   m.isolations);
  set('m-restorations', m.restorations);
  set('m-detect-latency', m.detection_latency_ms !== undefined ? m.detection_latency_ms?.toFixed(1) : null);
  set('m-resp-latency',   m.response_latency_ms  !== undefined ? m.response_latency_ms?.toFixed(1) : null);
}

// ── Master render ─────────────────────────────────────────────
let _lastPhase = null;

function renderAll(state) {
  try { renderHeader(state); } catch(e) { console.error('header', e); }
  try { renderTopology(state); } catch(e) { console.error('topology', e); }
  try { renderTraffic(state); } catch(e) { console.error('traffic', e); }
  try { renderThreat(state); } catch(e) { console.error('threat', e); }
  try { renderContext(state); } catch(e) { console.error('context', e); }
  try { renderPolicies(state); } catch(e) { console.error('policies', e); }
  try { renderResponse(state); } catch(e) { console.error('response', e); }
  try { renderTimeline(state); } catch(e) { console.error('timeline', e); }
  try { renderMetrics(state); } catch(e) { console.error('metrics', e); }

  // Phase change notifications
  const phase = state.phase;
  if (phase !== _lastPhase) {
    if (phase === 'THREAT_DETECTED') showAlert('⚠️ Threat detected — evaluating policies', 'threat');
    else if (phase === 'DECOY_ACTIVE') showAlert('🪤 Decoy deployed — attacker redirected', 'info');
    else if (phase === 'ISOLATED') showAlert('🔒 Target isolated from network', 'info');
    else if (phase === 'RESTORED') showAlert('✅ Network restored', 'info');
    else if (phase === 'ERROR') showAlert('❌ Demo error — check console', 'threat');
    _lastPhase = phase;
  }
}

// ── SSE Connection ────────────────────────────────────────────
let _es = null;
let _reconnectTimer = null;
let _connected = false;

function setConnected(ok) {
  _connected = ok;
  const ind = $('conn-indicator');
  const lbl = $('conn-label');
  if (!ind || !lbl) return;
  if (ok) {
    ind.className = 'conn-indicator live';
    lbl.textContent = 'LIVE';
  } else {
    ind.className = 'conn-indicator disconnected';
    lbl.textContent = 'DISCONNECTED';
  }
}

function connectSSE() {
  if (_es) { try { _es.close(); } catch(e){} _es = null; }
  clearTimeout(_reconnectTimer);

  try {
    _es = new EventSource('/stream');

    _es.onopen = () => {
      setConnected(true);
    };

    _es.onmessage = (evt) => {
      if (!evt.data || evt.data.trim() === '') return;
      try {
        const state = JSON.parse(evt.data);
        renderAll(state);
      } catch (e) {
        console.warn('[SSE] bad JSON:', e, evt.data.slice(0, 120));
      }
    };

    _es.onerror = () => {
      setConnected(false);
      _es.close();
      _es = null;
      _reconnectTimer = setTimeout(connectSSE, 3000);
    };
  } catch (e) {
    setConnected(false);
    _reconnectTimer = setTimeout(connectSSE, 5000);
  }
}

// ── Initial state load ────────────────────────────────────────
async function loadInitialState() {
  try {
    const resp = await fetch('/state');
    if (!resp.ok) return;
    const state = await resp.json();
    renderAll(state);
  } catch (e) {
    console.warn('[init] /state fetch failed:', e);
  }
}

// ── Boot ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  loadInitialState();
  connectSSE();
});
