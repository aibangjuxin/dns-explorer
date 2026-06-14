// DNS Explorer - frontend
// Calls /api/dns (Pages Function), renders IP classification results.

const $ = (id) => document.getElementById(id);

const els = {
  domain: $('domain'),
  type: $('type'),
  server: $('server'),
  queryBtn: $('query-btn'),
  status: $('status'),
  result: $('result'),
};

let inflight = null;

async function query() {
  const domain = els.domain.value.trim();
  const type = els.type.value;
  const server = els.server.value;

  if (!domain) {
    showStatus('Please enter a domain', 'error');
    return;
  }

  // basic sanity check
  if (!/^[a-z0-9._-]+$/i.test(domain)) {
    showStatus('Invalid domain format', 'error');
    return;
  }

  // cancel previous request
  if (inflight) inflight.abort();
  const ctrl = new AbortController();
  inflight = ctrl;

  els.queryBtn.disabled = true;
  showStatus('Resolving...', 'loading');
  els.result.classList.add('hidden');

  const t0 = performance.now();
  try {
    const url = `/api/dns?domain=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}&server=${encodeURIComponent(server)}`;
    const resp = await fetch(url, { signal: ctrl.signal });
    const elapsed = Math.round(performance.now() - t0);

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }

    const data = await resp.json();
    render(data, elapsed);
    hideStatus();
  } catch (err) {
    if (err.name === 'AbortError') return;
    showStatus(`Query failed: ${err.message}`, 'error');
  } finally {
    els.queryBtn.disabled = false;
    inflight = null;
  }
}

function showStatus(msg, kind = '') {
  els.status.className = `status ${kind}`;
  els.status.textContent = msg;
  els.status.classList.remove('hidden');
}

function hideStatus() {
  els.status.classList.add('hidden');
}

function render(d, elapsed) {
  const verdictClass = (d.verdict || 'unknown').toLowerCase();
  const ips = d.ips || [];
  const aliases = d.aliases || [];
  const mx = d.mx || [];
  const texts = d.texts || [];
  const other = d.other || [];

  const hasAny = ips.length || aliases.length || mx.length || texts.length || other.length;
  if (!hasAny) {
    els.result.innerHTML = `
      <div class="result-header">
        <h2>${escapeHtml(d.domain)}</h2>
        <span class="verdict ${verdictClass}">${escapeHtml(d.verdict || 'UNKNOWN')}</span>
      </div>
      <div class="meta-row">
        <span>📡 <strong>${escapeHtml(d.dnsServer)}</strong></span>
        <span>📋 <strong>${escapeHtml(d.recordType)}</strong></span>
        <span class="verdict ${rcodeClass(d.rcode)}">${rcodeLabel(d.rcode)}</span>
        <span>⏱️ <strong>${elapsed}ms</strong></span>
        <span>🌍 edge: <strong>${escapeHtml(d.edge || 'unknown')}</strong></span>
      </div>
      <p class="no-records">No records returned</p>
    `;
    els.result.classList.remove('hidden');
    return;
  }

  const sections = [];

  if (ips.length) {
    sections.push(`
      <h3>Addresses (${ips.length})</h3>
      <ul class="ip-list">
        ${ips.map(i => `
          <li class="ip-item">
            <span>${escapeHtml(i.data)}</span>
            <span class="ip-class ${i.ipClass || 'public'}">${i.type} · ${i.ipClass || 'public'} · TTL ${i.ttl}s</span>
          </li>`).join('')}
      </ul>
    `);
  }

  if (aliases.length) {
    sections.push(`
      <h3>${aliases[0].type} Records (${aliases.length})</h3>
      <ul class="ip-list">
        ${aliases.map(a => `
          <li class="ip-item alias">
            <span>${escapeHtml(a.data)}</span>
            <span class="ip-class public">${a.type} · TTL ${a.ttl}s</span>
          </li>`).join('')}
      </ul>
    `);
  }

  if (mx.length) {
    sections.push(`
      <h3>MX Records (${mx.length})</h3>
      <ul class="ip-list">
        ${mx.map(m => {
          // MX data format: "priority target" — split on first space
          const space = m.data.indexOf(' ');
          const pri = space > 0 ? m.data.slice(0, space) : '?';
          const tgt = space > 0 ? m.data.slice(space + 1) : m.data;
          return `
            <li class="ip-item alias">
              <span>${escapeHtml(tgt)}</span>
              <span class="ip-class private">pri ${escapeHtml(pri)} · TTL ${m.ttl}s</span>
            </li>`;
        }).join('')}
      </ul>
    `);
  }

  if (texts.length) {
    sections.push(`
      <h3>TXT Records (${texts.length})</h3>
      <ul class="ip-list">
        ${texts.map(t => `
          <li class="ip-item text">
            <span class="txt-data">${escapeHtml(t.data)}</span>
            <span class="ip-class public">TXT · TTL ${t.ttl}s</span>
          </li>`).join('')}
      </ul>
    `);
  }

  if (other.length) {
    sections.push(`
      <h3>Other Records (${other.length})</h3>
      <ul class="ip-list">
        ${other.map(o => `
          <li class="ip-item">
            <span>${escapeHtml(o.data)}</span>
            <span class="ip-class private">${o.type} · TTL ${o.ttl}s</span>
          </li>`).join('')}
      </ul>
    `);
  }

  els.result.innerHTML = `
    <div class="result-header">
      <h2>${escapeHtml(d.domain)}</h2>
      <span class="verdict ${verdictClass}">${escapeHtml(d.verdict || 'UNKNOWN')}</span>
    </div>
    <div class="meta-row">
      <span>📡 <strong>${escapeHtml(d.dnsServer)}</strong></span>
      <span>📋 <strong>${escapeHtml(d.recordType)}</strong></span>
      <span class="verdict ${rcodeClass(d.rcode)}">${rcodeLabel(d.rcode)}</span>
      <span>⏱️ <strong>${elapsed}ms</strong></span>
      <span>🌍 edge: <strong>${escapeHtml(d.edge || 'unknown')}</strong></span>
    </div>
    ${sections.join('')}
    <details>
      <summary>View raw DoH response</summary>
      <pre>${escapeHtml(JSON.stringify(d.raw, null, 2))}</pre>
    </details>
  `;
  els.result.classList.remove('hidden');
}

function rcodeClass(code) {
  if (code === 0) return 'public';
  if (code === 3) return 'nxdomain';
  return 'private';
}

function rcodeLabel(code) {
  const map = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED',
  };
  return map[code] ?? `RCODE ${code}`;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// --- Wire up events ---
els.queryBtn.addEventListener('click', query);
els.domain.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') query();
});

document.querySelectorAll('.presets button').forEach((btn) => {
  btn.addEventListener('click', () => {
    els.domain.value = btn.dataset.d;
    els.type.value = btn.dataset.t || 'A';
    query();
  });
});

// Auto-run on load for instant feedback
window.addEventListener('DOMContentLoaded', () => {
  query();
});
