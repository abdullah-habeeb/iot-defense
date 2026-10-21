/* ============================================================
   LIVE PHYSICAL DEMO — dashboard script
   Loaded after dashboard.js, whose renderers (traffic, threat, context,
   policies, arbiter, briefing, timeline, header) it reuses. Everything here is
   specific to the live defender: its own state stream (/live/stream), device
   cards, firewall rules, setup steps and defender status.
   ============================================================ */

'use strict';

const LIVE_STALE_MS = 5000;        // the defender rewrites its state every second
const LIVE_WARMUP_MS = 120000;     // ...except while it loads the policies at start-up
let _liveLastUpdate = 0;           // when (browser clock) a live state last arrived
let _liveConnected = false;
let _liveState = {};

// ── Defender status ──────────────────────────────────────────
function defenderStatus(state) {
  const fresh = Date.now() - _liveLastUpdate < LIVE_STALE_MS;
  if (!state.live) return 'waiting';                       // no live session has ever run
  // Loading the policies blocks the defender for a while (it cannot heartbeat); that is expected.
  if (state.live.warming && state.phase !== 'IDLE' && Date.now() - _liveLastUpdate < LIVE_WARMUP_MS) return 'starting';
  if (state.phase === 'IDLE' || !fresh) return 'stopped';  // it exited, or went silent
  return 'running';
}

function renderDefenderBadge(state) {
  const status = defenderStatus(state);
  const badge = $('defender-badge');
  if (badge) {
    badge.textContent = { running: 'DEFENDER: RUNNING', starting: 'DEFENDER: STARTING', stopped: 'DEFENDER: STOPPED', waiting: 'DEFENDER: NOT STARTED' }[status];
    badge.className = `phase-badge defender-badge ${status === 'starting' ? 'waiting' : status}`;
  }
  const conn = $('conn-indicator'), label = $('conn-label');
  if (conn && label) {
    conn.className = 'conn-indicator ' + (_liveConnected ? 'live' : 'disconnected');
    label.textContent = _liveConnected ? 'LIVE' : 'DISCONNECTED';
  }
  return status;
}

// ── Devices ──────────────────────────────────────────────────
const DEVICE_CLASS = {
  ONLINE: 'ok', RESTORED: 'ok', MONITORED: 'ok',
  ATTACKED: 'bad', 'SOURCE BLOCKED': 'warn', THROTTLED: 'warn', OFFLINE: '',
};

function setDevice(id, { ip, status, facts }) {
  const el = $(`dev-${id}`);
  if (!el) return;
  $(`dev-${id}-ip`).textContent = ip || '—';
  const st = $(`dev-${id}-status`);
  st.textContent = status;
  st.className = 'dev-status ' + (DEVICE_CLASS[status] || '');
  $(`dev-${id}-facts`).textContent = facts;
  el.className = el.className.replace(/\s*state-\w+/g, '') + ' state-' + (DEVICE_CLASS[status] || 'idle');
}

function renderDevices(state, status) {
  const live = state.live;
  const nodes = state.nodes || {};
  const running = status === 'running';
  const starting = status === 'starting';
  const blocks = (live && live.blocks) || [];
  const attackerIp = (nodes.attacker || {}).ip;
  const attackerBlock = blocks.find(b => b.source_ip === attackerIp);
  const trusted = (live && live.trusted) || [];
  const served = Number((live && live.served_recent) || 0);

  $('devices-note').textContent = live ? `${live.iface} · ${live.dry_run ? 'DRY RUN' : 'real firewall'}` : '';

  setDevice('box', {
    ip: live ? live.box_ip : '',
    status: running ? ((nodes.sensor || {}).status || 'ONLINE') : 'OFFLINE',
    facts: running
      ? `Watching ${live.iface}. ${Number(live.packets_seen || 0).toLocaleString()} packets seen. Page at :${live.service_port || 8080}.`
      : (starting ? 'Starting: loading the policies. Ready in a few seconds.' : live
          ? (state.phase === 'IDLE'
              ? 'Defender stopped cleanly. The firewall rules it added were removed.'
              : 'No updates from the defender. If it crashed, run the restore command (last step below) to remove its firewall rules.')
          : 'Not running. Start the defender (see below).'),
  });
  setDevice('phone', {
    ip: trusted[0] || '',
    status: running && trusted.length ? 'ONLINE' : 'OFFLINE',
    facts: running
      ? (trusted.length ? `Trusted. ${served} replies in the last 10 s${served === 0 ? ': NOT being served' : ''}.` : 'Open the box\'s page on the phone to register it.')
      : 'Open the box\'s page on the phone.',
  });
  const attackerStatus = attackerIp && attackerIp !== '—' ? ((nodes.attacker || {}).status || 'ATTACKED') : 'OFFLINE';
  setDevice('attacker', {
    ip: attackerIp && attackerIp !== '—' ? attackerIp : '',
    status: attackerBlock ? 'SOURCE BLOCKED' : attackerStatus,
    facts: attackerBlock
      ? `Blocked. ${Number(attackerBlock.packets_dropped || 0).toLocaleString()} of its packets dropped; unblocks in ${Number(attackerBlock.expires_in_s || 0).toFixed(0)} s.`
      : (attackerStatus === 'OFFLINE' ? 'Runs the scan. Not seen until it sends traffic.' : 'Sending traffic to the box.'),
  });

  const link = (id, cls) => { const l = $(id); if (l) l.className = 'dev-link ' + cls; };
  link('link-attacker', attackerBlock ? 'blocked' : (attackerStatus === 'ATTACKED' ? 'attack' : ''));
  link('link-phone', running && trusted.length && served > 0 ? 'ok' : '');
}

// ── Network guard (firewall) ─────────────────────────────────
function renderGuard(state, status) {
  const live = state.live;
  if (!live) {
    $('guard-flags').textContent = '';
    $('guard-box').textContent = '—';
    $('guard-allow').textContent = 'The defender has not been started yet.';
    $('live-blocks').innerHTML = '<div class="live-sub">None.</div>';
    return;
  }
  const flags = [];
  if (live.dry_run) flags.push('DRY RUN: no real firewall changes');
  flags.push(live.kernel_expiry ? 'rules also expire in the kernel' : 'rules expire by timer only');
  flags.push(`blocks last ${Number(live.ttl_s || 0).toFixed(0)} s`);
  $('guard-flags').textContent = flags.join(' · ');
  $('guard-box').textContent = `${safe(live.box_ip)} on ${safe(live.iface)}`;
  const allow = live.static_allow || [];
  $('guard-allow').textContent =
    `Never blocked: this box${allow.length ? ', ' + allow.join(', ') : ''}, and any device that completes real requests to the page. ` +
    `Responses available here: ${(live.supported_actions || []).join(', ')}.`;

  const rr = state.response_result;
  $('guard-response').innerHTML = rr
    ? `${actionChipHtml(rr.action)}<div class="live-sub">${escHtml(safe(rr.message))}</div>`
      + `<div class="live-sub">Status <b class="${rr.status === 'success' ? 'accent-green' : 'accent-red'}">${escHtml(String(rr.status).toUpperCase())}</b>`
      + ` · applied in ${Number(rr.latency_ms || 0).toFixed(1)} ms</div>`
    : 'None yet. The box is watching.';

  const blocks = live.blocks || [];
  $('live-blocks').innerHTML = blocks.length
    ? `<table class="live-rules"><thead><tr><th>Source</th><th>Rule</th><th>Dropped</th><th>Expires</th></tr></thead><tbody>${
        blocks.map(b => `<tr><td>${escHtml(b.source_ip)}</td><td>${escHtml(String(b.operation).toUpperCase())}</td>`
          + `<td class="drop">${Number(b.packets_dropped || 0).toLocaleString()} pkts</td><td>${Number(b.expires_in_s || 0).toFixed(0)} s</td></tr>`).join('')
      }</tbody></table>`
    : '<div class="live-sub">None. The box is watching.</div>';
}

function renderLiveMetrics(state) {
  const m = state.metrics || {}, live = state.live || {};
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  set('lm-packets', Number(live.packets_seen || 0).toLocaleString());
  set('lm-threats', m.threats_detected || 0);
  set('lm-blocks', m.blocks || 0);
  set('lm-throttles', m.throttles || 0);
  set('lm-detect', m.detection_latency_ms == null ? '—' : Math.round(m.detection_latency_ms));
  set('lm-resp', m.response_latency_ms == null ? '—' : Math.round(m.response_latency_ms));
  set('lm-served', live.served_recent || 0);
}

// ── Setup steps with copy buttons ────────────────────────────
function setupSteps(state) {
  const live = state.live || {};
  const iface = live.iface || '<interface>';
  const box = live.box_ip || '<box-ip>';
  const port = live.service_port || 8080;
  const cd = 'cd ~/iot-defense && ';
  return [
    { title: 'Prove it works first (no extra devices)', where: 'on the box (VM)', cmd: `${cd}sudo bash scripts/live_selftest.sh`,
      note: 'Builds a virtual attacker and phone inside the box. Must end with SELF-TEST PASSED.' },
    { title: 'Check normal traffic raises no alarm', where: 'on the box (VM)', cmd: `${cd}sudo .venv/bin/python3 -m iot_defense.live.defender calibrate --iface ${iface} --seconds 120`,
      note: `While it records, use the phone normally against http://${box}:${port}. Must print "no false alarms".` },
    { title: 'Start the defender', where: 'on the box (VM)', cmd: `${cd}sudo .venv/bin/python3 -m iot_defense.live.defender run --iface ${iface}`,
      note: 'Leave it running. This page turns to RUNNING within a few seconds.' },
    { title: 'Open the page on the phone', where: 'on the phone', cmd: `http://${box}:${port}`,
      note: 'It shows ONLINE and refreshes by itself. After two replies the box trusts it as a normal user.' },
    { title: 'Launch the attack', where: 'on the attacker laptop', cmd: `nmap -sT -p 1-1000 ${box}`,
      note: 'Watch this page: detection, the three advisors, the arbiter, then a real firewall rule. The phone stays ONLINE.' },
    { title: 'Stop and clean up', where: 'on the box (VM)', cmd: `Ctrl+C   (or)   ${cd}sudo .venv/bin/python3 -m iot_defense.live.defender restore --iface ${iface}`,
      note: 'Removes every firewall rule the defender added.' },
  ];
}

let _setupSignature = '';
let _setupStatus = null;
let _setupUserChose = false;     // once the viewer toggles the panel, stop auto-collapsing it

function setSetupCollapsed(collapsed) {
  const card = $('section-setup'), btn = $('setup-toggle');
  if (!card || !btn) return;
  card.classList.toggle('collapsed', collapsed);
  btn.textContent = collapsed ? 'Show' : 'Hide';
  btn.setAttribute('aria-expanded', String(!collapsed));
}

function renderSetup(state, status) {
  const body = $('setup-body');
  if (!body) return;
  // Steps are the point until the defender is up; once it runs, the demo itself is.
  if (status !== _setupStatus) {
    _setupStatus = status;
    if (!_setupUserChose) setSetupCollapsed(status === 'running');
  }
  const note = $('setup-note');
  if (note) note.textContent = { running: 'defender is running: ready for the attack', starting: 'starting: loading the policies', stopped: 'defender stopped', waiting: 'start the defender to begin' }[status];

  const steps = setupSteps(state);
  const signature = JSON.stringify(steps);
  if (signature === _setupSignature) return;      // do not rebuild (and lose a text selection) every second
  _setupSignature = signature;
  body.innerHTML = `<ol class="setup-steps">${steps.map((s, i) => `
    <li>
      <div class="step-head"><span class="step-title">${escHtml(s.title)}</span><span class="step-where">${escHtml(s.where)}</span></div>
      <div class="step-cmd"><code>${escHtml(s.cmd)}</code><button type="button" class="copy-btn" data-copy="${i}" aria-label="Copy command for step ${i + 1}">Copy</button></div>
      <div class="step-note">${escHtml(s.note)}</div>
    </li>`).join('')}</ol>
    <p class="setup-foot">Only use your own devices on a network you control. Full guide: <code>docs/LIVE_DEMO.md</code>.</p>`;
  body.querySelectorAll('.copy-btn').forEach(btn => btn.addEventListener('click', async () => {
    const text = steps[Number(btn.dataset.copy)].cmd;
    try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; }
    catch { btn.textContent = 'Select text'; }
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  }));
}

// ── Master render ────────────────────────────────────────────
let _livePhase = null;
function renderLiveAll(state) {
  _liveState = state;
  const status = renderDefenderBadge(state);
  const steps = [
    () => renderHeader(state),
    () => renderDevices(state, status),
    () => renderGuard(state, status),
    () => renderLiveMetrics(state),
    () => renderSetup(state, status),
    () => renderTraffic(state),
    () => renderThreat(state),
    () => renderContext(state),
    () => renderPolicies(state),
    () => renderArbiter(state),
    () => renderBriefing(state),
    () => renderTimeline(state),
  ];
  steps.forEach(fn => { try { fn(); } catch (e) { console.error('live render', e); } });

  if (state.phase !== _livePhase) {
    if (state.phase === 'THREAT_DETECTED') showAlert('Threat detected on the real network', 'threat');
    else if (state.phase === 'BLOCKED_SOURCE') showAlert('Attacker blocked by a real firewall rule', 'info');
    else if (state.phase === 'THROTTLED') showAlert('Attacker rate-limited by a real firewall rule', 'info');
    else if (state.phase === 'RESTORED') showAlert('Block expired: traffic from that source is allowed again', 'info');
    else if (state.phase === 'ERROR') showAlert('A response could not be applied: see the timeline', 'threat');
    _livePhase = state.phase;
  }
}

// ── Data: initial fetch, SSE stream, staleness watchdog ──────
function refreshLiveStatus() {
  if (!_liveState || !Object.keys(_liveState).length) return;
  const status = renderDefenderBadge(_liveState);
  renderDevices(_liveState, status);
  renderSetup(_liveState, status);
}

async function loadLiveInitial() {
  try {
    const resp = await fetch('/live/state');
    if (resp.ok) { _liveLastUpdate = 0; renderLiveAll(await resp.json()); }
  } catch (e) { console.warn('[live] initial state failed', e); }
}

function connectLive() {
  const es = new EventSource('/live/stream');
  es.onopen = () => { _liveConnected = true; renderDefenderBadge(_liveState); };
  es.onmessage = (ev) => {
    try {
      const state = JSON.parse(ev.data);
      if (!state || !state.phase) return;
      _liveLastUpdate = Date.now();
      renderLiveAll(state);
    } catch (e) { console.error('[live] bad state', e); }
  };
  es.onerror = () => { _liveConnected = false; renderDefenderBadge(_liveState); };   // EventSource reconnects by itself
}

async function loadLiveBriefings() {
  try {
    const resp = await fetch('/attacks');
    if (!resp.ok) throw new Error(`status ${resp.status}`);
    (await resp.json()).forEach(a => { ATTACK_BRIEFINGS[a.key] = a; });
    renderBriefing(_liveState);
  } catch (e) { console.warn('[live] /attacks failed', e); }
}

function initSetupToggle() {
  const btn = $('setup-toggle'), card = $('section-setup');
  if (!btn || !card) return;
  btn.addEventListener('click', () => {
    _setupUserChose = true;
    setSetupCollapsed(!card.classList.contains('collapsed'));
  });
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.body.dataset.page !== 'live') return;
  startClock();
  initBriefingToggle();
  initSetupToggle();
  loadLiveInitial();
  loadLiveBriefings();
  connectLive();
  // The defender rewrites its state every second; silence for LIVE_STALE_MS means it is not running.
  setInterval(refreshLiveStatus, 2000);
});
