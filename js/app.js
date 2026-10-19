'use strict';
/* PhishGuard frontend demo. Sections: 1 helpers, 2 storage, 3 detector, 4 state, 5 rendering, 6 features, 7 init. */

/* ===== 1. Helpers (all user text goes through textContent, never innerHTML) ===== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function el(tag, props = {}, kids = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) k === 'class' ? (n.className = v) : n.setAttribute(k, v);
  [].concat(kids).forEach(c => n.append(c));
  return n;
}
const fmtDate = iso => new Date(iso).toLocaleString();
const LABELS = { low: 'Low risk signals detected', suspicious: 'Suspicious URL', high: 'High-risk URL' };
const badge = level => el('span', { class: 'badge ' + level }, LABELS[level]);
function toast(msg, type = '') {
  const t = el('div', { class: 'toast ' + type }, msg);
  $('#toasts').append(t); setTimeout(() => t.remove(), 3500);
}
function confirmDialog(message, okText = 'Confirm') {
  return new Promise(res => {
    const d = $('#dlg');
    $('#dlgBody').replaceChildren(el('p', {}, message));
    const cancel = el('button', { class: 'btn' }, 'Cancel'), ok = el('button', { class: 'btn danger' }, okText);
    $('#dlgBtns').replaceChildren(cancel, ok);
    const done = v => { d.close(); res(v); };
    cancel.onclick = () => done(false); ok.onclick = () => done(true);
    d.showModal();
  });
}

/* ===== 2. Storage (localStorage wrapper; fails gracefully) ===== */
const Store = {
  get(key, fallback) { try { const v = localStorage.getItem('pg_' + key); return v ? JSON.parse(v) : fallback; } catch { return fallback; } },
  set(key, val) { try { localStorage.setItem('pg_' + key, JSON.stringify(val)); } catch { toast('Could not save: browser storage is unavailable.', 'error'); } },
  clearAll() { try { Object.keys(localStorage).filter(k => k.startsWith('pg_')).forEach(k => localStorage.removeItem(k)); } catch { /* ignore */ } }
};

/* ===== 3. Detection (kept separate from the UI) =====
   detectUrl() is the ONE integration point. To use a real ML service later, replace its body with:
     const r = await fetch('/api/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})});
     return r.json();   // must return the same shape as ruleBasedDetector()
   Never place secret API keys here; call your own backend instead. */
const KEYWORDS = ['login', 'verify', 'account', 'password', 'confirm', 'secure', 'update', 'otp', 'pin'];

function parseUrl(raw) {
  let s = (raw || '').trim();
  if (!s || /\s/.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s; // no scheme typed: assume https so we don't add a false HTTP flag
  try {
    const u = new URL(s);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    if (!u.hostname.includes('.') && !u.hostname.includes(':')) return null;
    return u;
  } catch { return null; }
}

/* Rule-based demo detector. NOT a trained AI model. Every rule adds visible points. */
function ruleBasedDetector(u) {
  const hits = [], add = (pts, text) => hits.push({ pts, text });
  const host = u.hostname, full = u.href, labels = host.split('.');
  if (u.protocol === 'http:') add(20, 'Uses HTTP instead of HTTPS (traffic is not encrypted).');
  if (full.length > 75) add(10, `Unusually long URL (${full.length} characters).`);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) add(30, 'Hostname is an IP address, not a domain name.');
  const found = KEYWORDS.filter(k => (host + u.pathname + u.search).toLowerCase().includes(k));
  if (found.length) add(Math.min(found.length * 8, 24), `Suspicious terms in URL: ${found.join(', ')}.`);
  if (labels.length > 4) add(15, `Excessive subdomain levels (${labels.length - 2} subdomains).`);
  if (host.split('.').some(l => l.startsWith('xn--'))) add(25, 'Punycode hostname (can disguise look-alike characters).');
  if (/@/.test(full.replace(/^https?:\/\//, '').split('/')[0])) add(25, 'Contains "@" before the host, which can hide the real destination.');
  if (u.port && !['80', '443'].includes(u.port)) add(15, `Unusual port number (${u.port}).`);
  if (/%[0-9a-f]{2}/i.test(full)) add(10, 'Contains percent-encoded characters that may hide content.');
  if ((host.match(/-/g) || []).length >= 3) add(8, 'Many hyphens in the hostname.');
  if (/mtn/i.test(host) && !/(^|\.)mtn(online)?\.(com|ng)$/i.test(host)) add(20, 'Mentions "MTN" in a domain that does not look like an official MTN domain (heuristic only).');
  const score = Math.min(100, hits.reduce((n, h) => n + h.pts, 0));
  const level = score >= 55 ? 'high' : score >= 25 ? 'suspicious' : 'low';
  const explain = {
    low: 'Few or no warning signs were found by these basic rules. This does not prove the site is safe.',
    suspicious: 'Several warning signs were found. The link may be a phishing attempt and deserves caution.',
    high: 'Many strong warning signs were found. This link has traits common in phishing URLs.'
  };
  const advise = {
    low: 'Still confirm the sender and type official addresses yourself before entering any personal details.',
    suspicious: 'Do not enter passwords, PINs or OTPs. Verify the sender through an official channel first.',
    high: 'Do not open this link. Delete the message and report it through official channels.'
  };
  return { url: u.href, score, level, indicators: hits.map(h => h.text), explanation: explain[level], recommendation: advise[level], date: new Date().toISOString(), engine: 'rule-based-demo' };
}
async function detectUrl(u) { return ruleBasedDetector(u); }

/* ===== 4. State ===== */
const state = {
  scans: Store.get('scans', []), reports: Store.get('reports', []), alerts: Store.get('alerts', []),
  settings: Store.get('settings', { dark: false, notify: true })
};
const save = k => Store.set(k, state[k]);

/* ===== 5. Rendering ===== */
function tableRows(body, rows, cols, emptyText) {
  body.replaceChildren();
  if (!rows.length) { body.append(el('tr', {}, el('td', { colspan: cols, class: 'empty' }, emptyText))); return; }
  rows.forEach(r => body.append(r));
}
const td = (content, cls = '') => el('td', cls ? { class: cls } : {}, content);

function renderResult(box, s) {
  const list = s.indicators.length ? el('ul', { class: 'plain' }, s.indicators.map(t => el('li', {}, t))) : el('p', {}, 'No warning indicators were triggered.');
  box.replaceChildren(
    el('div', { class: 'res-head' }, [el('div', { class: 'gauge ' + s.level, 'aria-label': 'Risk score' }, String(s.score)), el('div', {}, [badge(s.level), el('p', {}, 'Risk score: ' + s.score + ' / 100')])]),
    el('p', {}, el('b', {}, 'Submitted URL')), el('p', { class: 'res-url' }, s.url),
    el('h2', { class: 'mt' }, 'Warning indicators'), list,
    el('h2', { class: 'mt' }, 'Explanation'), el('p', {}, s.explanation),
    el('h2', { class: 'mt' }, 'Recommendation'), el('p', {}, s.recommendation),
    el('p', { class: 'note' }, 'Scanned ' + fmtDate(s.date) + '. Demo rules only: no live threat intelligence, and the link was not opened.')
  );
}

function renderStats() {
  const c = lvl => state.scans.filter(s => s.level === lvl).length;
  const data = [['Total URLs scanned', state.scans.length, ''], ['Suspicious URLs detected', c('suspicious'), 'orange'], ['High-risk URLs detected', c('high'), 'red'], ['Reports submitted', state.reports.length, 'green']];
  $('#stats').replaceChildren(...data.map(([l, n, cls]) => el('div', { class: 'stat ' + cls }, [el('b', {}, String(n)), el('span', {}, l)])));
  const total = state.scans.length || 1;
  $('#riskSummary').replaceChildren(...[['low', 'Low risk signals', 'var(--green)'], ['suspicious', 'Suspicious', 'var(--orange)'], ['high', 'High-risk', 'var(--red)']].map(([k, l, col]) => {
    const i = el('i'); i.style.width = (c(k) / total * 100) + '%'; i.style.background = col;
    return el('div', {}, [el('span', {}, `${l}: ${c(k)}`), el('div', { class: 'bar' }, i)]);
  }));
  tableRows($('#recentBody'), state.scans.slice(0, 5).map(s => el('tr', {}, [td(s.url, 'url'), td(String(s.score)), td(badge(s.level))])), 3, 'No scans yet. Try the URL Scanner.');
  $('#bellDot').hidden = !state.alerts.some(a => !a.read);
}

function renderHistory() {
  const q = $('#histSearch').value.trim().toLowerCase(), f = $('#histFilter').value, asc = $('#histSort').value === 'old';
  const rows = state.scans.filter(s => (f === 'all' || s.level === f) && s.url.toLowerCase().includes(q))
    .sort((a, b) => asc ? a.date.localeCompare(b.date) : b.date.localeCompare(a.date));
  tableRows($('#histBody'), rows.map(s => {
    const b = el('button', { class: 'btn sm' }, 'View details'); b.onclick = () => showDetails(s);
    return el('tr', {}, [td(s.url, 'url'), td(fmtDate(s.date)), td(String(s.score)), td(badge(s.level)), td(String(s.indicators.length)), td(b)]);
  }), 6, state.scans.length ? 'No scans match your search.' : 'No scans yet.');
}
function showDetails(s) {
  const body = el('div'); renderResult(body, s);
  const close = el('button', { class: 'btn primary' }, 'Close'); close.onclick = () => $('#dlg').close();
  $('#dlgBody').replaceChildren(body); $('#dlgBtns').replaceChildren(close); $('#dlg').showModal();
}

function renderReports() {
  const q = $('#repSearch').value.trim().toLowerCase();
  const rows = state.reports.filter(r => (r.url + r.reason + r.notes).toLowerCase().includes(q));
  tableRows($('#repBody'), rows.map(r => el('tr', {}, [td(r.url, 'url'), td(r.reason), td(fmtDate(r.date)), td(r.status)])), 4, 'No reports found.');
}

function renderAlerts() {
  const f = $('#alertFilter').value, box = $('#alertList');
  const list = state.alerts.filter(a => f === 'all' || a.level === f);
  box.replaceChildren();
  if (!list.length) return box.append(el('p', { class: 'empty' }, 'No alerts. Scan a URL to generate simulated alerts.'));
  list.forEach(a => {
    const btn = el('button', { class: 'btn sm' }, a.read ? 'Read' : 'Mark as read'); btn.disabled = a.read;
    btn.onclick = () => { a.read = true; save('alerts'); renderAll(); };
    box.append(el('div', { class: 'alert ' + a.level + (a.read ? ' read' : '') }, [el('div', {}, [el('b', {}, a.title + (a.read ? '' : ' (unread)')), el('p', {}, a.url), badge(a.level), el('p', {}, a.explanation), el('small', {}, fmtDate(a.date) + ' · Simulated alert')]), btn]));
  });
}

const SAFETY = [
  ['How phishing attacks work', 'Attackers pretend to be a trusted brand to trick you into sharing secrets or installing malware. They rely on urgency, fear or tempting offers so you act before thinking.'],
  ['Identifying suspicious URLs', 'Read the domain right before the first single slash. Watch for extra hyphens, misspellings, IP addresses, "@" symbols and brand names placed in unrelated domains.'],
  ['Fake login pages', 'A copied page can look identical to the real one. Open the service by typing its address or using its official app, never through a link in a message.'],
  ['SMS phishing and fraudulent messages', 'Messages that threaten SIM blocking, promise prizes, or ask you to "verify" details through a link are common scams. Do not tap links from unknown numbers.'],
  ['Impersonation of telecom companies', 'Scammers copy network names, logos and short codes. A real provider will not ask you to share your PIN or OTP in a message or on a call.'],
  ['Protecting passwords, PINs and OTPs', 'Never share OTPs with anyone, even someone claiming to be staff. Use unique passwords and enable two-step verification where offered.'],
  ['Verifying official MTN communications', 'Use contact details from the official MTN website, the official app, or a service centre. Do not rely on numbers or links inside an unexpected message.'],
  ['Reporting suspected phishing', 'Do not reply or click. Take a screenshot, report the link through the official provider channels, then delete the message. You can also log it in Threat Reports here.']
];

function renderAll() { renderStats(); renderHistory(); renderReports(); renderAlerts(); }

/* ===== 6. Features ===== */
async function handleScan(e) {
  e.preventDefault();
  const err = $('#scanErr'), u = parseUrl($('#scanUrl').value);
  if (!u) { err.textContent = 'Enter a valid web address, for example https://example.com/page'; $('#scanUrl').focus(); return; }
  err.textContent = '';
  let result;
  try { result = await detectUrl(u); } catch { err.textContent = 'The detector failed. Please try again.'; return; }
  state.scans.unshift(result); save('scans');
  if (result.level !== 'low') {
    state.alerts.unshift({ id: Date.now(), title: result.level === 'high' ? 'High-risk URL detected' : 'Suspicious URL detected', url: result.url, level: result.level, date: result.date, explanation: result.explanation, read: false });
    save('alerts');
    if (state.settings.notify) toast(LABELS[result.level] + ': see Security Alerts.', 'error');
  }
  const box = $('#scanResult'); renderResult(box, result); box.hidden = false; box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  renderAll();
}

function handleReport(e) {
  e.preventDefault();
  const u = parseUrl($('#repUrl').value), reason = $('#repReason').value, err = $('#repErr');
  if (!u) return void (err.textContent = 'Enter a valid URL to report.');
  if (!reason) return void (err.textContent = 'Choose a reason for reporting.');
  err.textContent = '';
  state.reports.unshift({ id: Date.now(), url: u.href, reason, notes: $('#repNotes').value.trim(), date: new Date().toISOString(), status: 'Saved locally (not sent)' });
  save('reports'); e.target.reset(); renderAll(); toast('Report saved in this browser. It has not been sent to anyone.');
}

/* Routing: #/app/<view> shows the dashboard; anything else shows the landing page */
const TITLES = { overview: 'Overview', scanner: 'URL Scanner', history: 'Scan History', reports: 'Threat Reports', alerts: 'Security Alerts', safety: 'Safety Center', settings: 'Settings' };
function route() {
  const m = location.hash.match(/^#\/app\/(\w+)/), isApp = !!m;
  $('#landing').hidden = isApp; $('#app').hidden = !isApp;
  $('#app').classList.remove('open');
  if (!isApp) return;
  const view = TITLES[m[1]] ? m[1] : 'overview';
  $$('[data-panel]').forEach(p => p.hidden = p.dataset.panel !== view);
  $$('#sideNav a').forEach(a => a.classList.toggle('active', a.dataset.view === view));
  $('#pageTitle').textContent = TITLES[view]; document.title = TITLES[view] + ' | PhishGuard'; window.scrollTo(0, 0);
}

function applyTheme() { document.documentElement.dataset.theme = state.settings.dark ? 'dark' : 'light'; }

/* ===== 7. Init ===== */
function init() {
  applyTheme();
  $('#safetyList').replaceChildren(...SAFETY.map(([t, p], i) => { const d = el('details', {}, [el('summary', {}, t), el('p', {}, p)]); if (!i) d.open = true; return d; }));
  // Landing nav: mobile toggle + shadow on scroll + scroll reveal
  const nav = $('#navLinks'), tog = $('#navToggle');
  tog.onclick = () => { const o = nav.classList.toggle('open'); tog.setAttribute('aria-expanded', o); };
  nav.addEventListener('click', e => { if (e.target.tagName === 'A') { nav.classList.remove('open'); tog.setAttribute('aria-expanded', false); } });
  addEventListener('scroll', () => $('#siteNav').classList.toggle('scrolled', scrollY > 10), { passive: true });
  const io = new IntersectionObserver(es => es.forEach(x => { if (x.isIntersecting) { x.target.classList.add('in'); io.unobserve(x.target); } }), { threshold: .15 });
  $$('.reveal').forEach(n => io.observe(n));
  // Dashboard sidebar
  $('#sideToggle').onclick = () => $('#app').classList.toggle('open');
  $('#scrim').onclick = () => $('#app').classList.remove('open');
  $('#collapseBtn').onclick = () => $('#app').classList.toggle('collapsed');
  // Forms and filters
  $('#scanForm').addEventListener('submit', handleScan);
  $('#reportForm').addEventListener('submit', handleReport);
  ['#histSearch', '#histFilter', '#histSort'].forEach(s => $(s).addEventListener('input', renderHistory));
  $('#repSearch').addEventListener('input', renderReports);
  $('#alertFilter').addEventListener('change', renderAlerts);
  $('#readAll').onclick = () => { state.alerts.forEach(a => a.read = true); save('alerts'); renderAll(); };
  $('#clearHist').onclick = async () => { if (await confirmDialog('Delete all scan history on this device? This cannot be undone.', 'Clear history')) { state.scans = []; save('scans'); renderAll(); toast('Scan history cleared.'); } };
  // Settings
  $('#setDark').checked = state.settings.dark; $('#setNotify').checked = state.settings.notify;
  $('#setDark').onchange = e => { state.settings.dark = e.target.checked; save('settings'); applyTheme(); };
  $('#setNotify').onchange = e => { state.settings.notify = e.target.checked; save('settings'); };
  $('#clearAll').onclick = async () => {
    if (!(await confirmDialog('Delete all scans, reports, alerts and preferences stored by this demo?', 'Clear all data'))) return;
    Store.clearAll(); Object.assign(state, { scans: [], reports: [], alerts: [], settings: { dark: false, notify: true } });
    $('#setDark').checked = false; $('#setNotify').checked = true; applyTheme(); $('#scanResult').hidden = true; renderAll(); toast('Local demonstration data cleared.');
  };
  addEventListener('hashchange', route); route(); renderAll();
}
document.addEventListener('DOMContentLoaded', init);
