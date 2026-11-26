/* global acquireVsCodeApi */
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');

  let state = {
    name: '',
    summary: null,
    pageSize: 100,
    page: 0,
    total: 0,
    rows: [],
    selected: null,
    tab: 'rules',
    revealEnv: false,
    req: 0,
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function post(msg) {
    state.req += 1;
    vscode.postMessage({ ...msg, req: state.req });
  }

  function fmtSize(n) {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function renderShell() {
    const s = state.summary;
    const errChip = s.errorCount > 0 ? `<span class="chip bad"><b>Errors:</b> ${s.errorCount}</span>` : '<span class="chip"><b>Safety:</b> OK</span>';
    const warnChip = s.warningCount > 0 ? `<span class="chip warn"><b>Warnings:</b> ${s.warningCount}</span>` : '';

    app.innerHTML = `
      <div class="top">
        <div class="title">
          <span class="name">${esc(state.name)}</span>
          <span class="kind">Claude Settings JSON · ${fmtSize(s.fileSize)} · 100% offline</span>
        </div>
        <div class="summary">
          <span class="chip"><b>Allow:</b> ${s.allowCount}</span>
          <span class="chip"><b>Deny:</b> ${s.denyCount}</span>
          <span class="chip"><b>Hooks:</b> ${s.hookCount}</span>
          <span class="chip"><b>Env:</b> ${s.envCount}</span>
          ${errChip}${warnChip}
        </div>
        <div class="toolbar">
          <input id="q" type="search" placeholder="Filter by tool, pattern or decision..." />
          <select id="decisionFilter">
            <option value="">All decisions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="ask">Ask</option>
          </select>
          <select id="statusFilter">
            <option value="">All statuses</option>
            <option value="error">Has errors</option>
            <option value="warning">Has warnings</option>
            <option value="ok">Clean</option>
          </select>
          <button id="filterBtn" type="button">Filter</button>
          <button id="revealBtn" type="button">Reveal Env Values</button>
          <span class="sep"></span>
          <div id="protools"></div>
        </div>
        <div class="tabs">
          <button class="tab on" data-tab="rules" type="button">Permissions (${s.ruleCount})</button>
          <button class="tab" data-tab="hooks" type="button">Hooks (${s.hookCount})</button>
          <button class="tab" data-tab="env" type="button">Env Vars (${s.envCount})</button>
          <button class="tab" data-tab="findings" type="button">Safety Checks (${s.errorCount + s.warningCount})</button>
        </div>
        <div id="hint" class="hint"></div>
      </div>
      <div class="main">
        <div id="leftPane" class="tablewrap"></div>
        <div id="detail" class="detail"><p class="muted">Select a permission rule to inspect details and raw settings JSON.</p></div>
      </div>
      <div class="pager">
        <button id="prev" type="button">Prev</button>
        <span id="pageInfo"></span>
        <button id="next" type="button">Next</button>
      </div>
    `;

    const q = document.getElementById('q');
    const decSel = document.getElementById('decisionFilter');
    const stSel = document.getElementById('statusFilter');
    const runFilter = () => {
      state.page = 0;
      post({ type: 'filter', filter: { text: q.value, decision: decSel.value, status: stSel.value } });
    };
    document.getElementById('filterBtn').addEventListener('click', runFilter);
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') runFilter(); });
    decSel.addEventListener('change', runFilter);
    stSel.addEventListener('change', runFilter);

    const revealBtn = document.getElementById('revealBtn');
    revealBtn.addEventListener('click', () => {
      state.revealEnv = !state.revealEnv;
      revealBtn.textContent = state.revealEnv ? 'Mask Env Values' : 'Reveal Env Values';
      if (state.tab === 'env') renderPane();
    });

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state.tab = btn.dataset.tab;
        renderPane();
      });
    });

    document.getElementById('prev').addEventListener('click', () => {
      if (state.page > 0) { state.page -= 1; loadPage(); }
    });
    document.getElementById('next').addEventListener('click', () => {
      if ((state.page + 1) * state.pageSize < state.total) { state.page += 1; loadPage(); }
    });
  }

  function loadPage() {
    post({ type: 'page', from: state.page * state.pageSize, n: state.pageSize });
  }

  function renderPane() {
    const left = document.getElementById('leftPane');
    const pager = document.querySelector('.pager');
    const s = state.summary;

    if (state.tab === 'hooks') {
      pager.style.display = 'none';
      const rows = (s.hooks || []).map((h) => `<tr>
        <td class="num">${h.index}</td>
        <td><strong>${esc(h.event)}</strong></td>
        <td><code>${esc(h.matcher)}</code></td>
        <td>${esc(h.type)}</td>
        <td><code>${esc(h.command)}</code></td>
        <td class="${h.status === 'error' ? 'bad' : (h.status === 'ok' ? 'ok' : '')}">${esc(h.status.toUpperCase())}</td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th class="num">#</th><th>Event</th><th>Matcher</th><th>Type</th><th>Shell Command / Prompt</th><th>Status</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="muted">No hooks configured in this settings file.</td></tr>'}</tbody>
      </table>`;
      return;
    }

    if (state.tab === 'env') {
      pager.style.display = 'none';
      const rows = (s.envVars || []).map((e) => `<tr>
        <td><strong>${esc(e.key)}</strong></td>
        <td><code>${esc(state.revealEnv ? e.value : e.masked)}</code></td>
        <td>${e.isSecret ? '<span class="badge-mismatch">SECRET</span>' : '<span class="badge-muted">CONFIG</span>'}</td>
        <td class="${e.status === 'error' ? 'bad' : 'ok'}">${esc(e.status.toUpperCase())}</td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th>Key</th><th>Value (${state.revealEnv ? 'Revealed Locally' : 'Masked'})</th><th>Type</th><th>Status</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4" class="muted">No environment variables configured.</td></tr>'}</tbody>
      </table>`;
      return;
    }

    if (state.tab === 'findings') {
      pager.style.display = 'none';
      const fRows = (s.findings || []).map((f) => `<tr>
        <td class="${f.severity === 'error' ? 'bad' : ''}">${esc(f.severity.toUpperCase())}</td>
        <td>${esc(f.category)}</td>
        <td><code>${esc(f.target)}</code></td>
        <td>${esc(f.finding)}</td>
      </tr>`).join('');
      left.innerHTML = fRows
        ? `<table id="grid"><thead><tr><th>Severity</th><th>Category</th><th>Target</th><th>Finding</th></tr></thead><tbody>${fRows}</tbody></table>`
        : '<p class="muted" style="padding:12px;">All static Claude settings safety checks passed.</p>';
      return;
    }

    pager.style.display = 'flex';
    const body = state.rows.map((r) => {
      const sel = state.selected === r.index ? ' class="sel"' : '';
      const eBadge = r.errorCount ? `<span class="badge-mismatch">ERR (${r.errorCount})</span>` : '';
      const wBadge = r.warningCount ? `<span class="badge-muted">WARN (${r.warningCount})</span>` : '';
      const statusCls = r.status === 'error' ? 'bad' : (r.status === 'ok' ? 'ok' : '');
      return `<tr data-idx="${r.index}"${sel}>
        <td class="num">${r.index}</td>
        <td><strong>${esc(r.decision.toUpperCase())}</strong></td>
        <td>${esc(r.tool)}</td>
        <td><code>${esc(r.pattern)}</code>${eBadge}${wBadge}</td>
        <td class="${statusCls}">${esc(r.status.toUpperCase())}</td>
      </tr>`;
    }).join('');
    left.innerHTML = `<table id="grid">
      <thead><tr><th class="num">#</th><th>Decision</th><th>Tool</th><th>Pattern</th><th>Status</th></tr></thead>
      <tbody>${body || '<tr><td colspan="5" class="muted">No matching permission rules.</td></tr>'}</tbody>
    </table>`;

    left.querySelectorAll('tbody tr[data-idx]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const idx = Number(tr.dataset.idx);
        state.selected = idx;
        left.querySelectorAll('tbody tr').forEach((row) => row.classList.toggle('sel', Number(row.dataset.idx) === idx));
        post({ type: 'detail', index: idx });
      });
    });

    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    document.getElementById('pageInfo').textContent = `Page ${state.page + 1} of ${pages} (${state.total} rules)`;
    document.getElementById('prev').disabled = state.page <= 0;
    document.getElementById('next').disabled = (state.page + 1) * state.pageSize >= state.total;
  }

  function renderDetail(d) {
    const el = document.getElementById('detail');
    if (!d) {
      el.innerHTML = '<p class="muted">No permission rule selected.</p>';
      return;
    }
    const pairs = [
      ['Decision', d.decision.toUpperCase()],
      ['Tool', d.tool],
      ['Pattern', d.pattern],
      ['Raw Rule', d.raw],
      ['Default Mode', d.defaultMode],
      ['Status', d.status.toUpperCase()],
    ];
    const rows = pairs.map(([k, v]) => `<tr><td><strong>${esc(k)}</strong></td><td><code>${esc(v)}</code></td></tr>`).join('');
    const fItems = (d.findings || []).map((f) => `<li class="${f.severity === 'error' ? 'bad' : ''}"><strong>[${esc(f.severity.toUpperCase())}] ${esc(f.category)}:</strong> ${esc(f.finding)}</li>`).join('');
    el.innerHTML = `
      <div class="dhead"><strong>${esc(d.decision.toUpperCase())}: ${esc(d.tool)}</strong><span class="muted">#${d.index}</span></div>
      <table class="splits"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>
      ${fItems ? `<div class="attr-head"><strong>Findings (${d.findings.length})</strong></div><ul class="findings-list">${fItems}</ul>` : ''}
      <div class="attr-head"><strong>Settings JSON</strong></div>
      <pre class="attr-json">${esc(d.rawJson || '')}</pre>
    `;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (!m || typeof m !== 'object') return;
    switch (m.type) {
      case 'init':
        if (m.error) {
          app.innerHTML = `<div class="error"><strong>Could not open ${esc(m.name)}</strong><p>${esc(m.error)}</p></div>`;
          return;
        }
        state.name = m.name;
        state.summary = m.summary;
        state.pageSize = m.pageSize || 100;
        state.page = 0;
        renderShell();
        loadPage();
        return;
      case 'pageResult':
        state.total = m.total;
        state.rows = m.rows || [];
        renderPane();
        if (state.rows.length && state.selected == null) {
          state.selected = state.rows[0].index;
          post({ type: 'detail', index: state.selected });
        }
        return;
      case 'filterResult':
        state.total = m.count;
        document.getElementById('hint').textContent = m.count < m.total ? `Showing ${m.count} of ${m.total} rules.` : '';
        loadPage();
        return;
      case 'detailResult':
        renderDetail(m.detail);
        return;
      case 'zovoAlso': {
        const anchor = m.anchor && document.getElementById(m.anchor);
        if (anchor && m.html) {
          const old = document.querySelector('.zovo-also');
          if (old) old.remove();
          anchor.insertAdjacentHTML('afterend', m.html);
        }
        return;
      }
      case 'hint':
        if (document.getElementById('hint')) document.getElementById('hint').textContent = m.text || '';
        return;
      default:
    }
  });

  post({ type: 'ready' });
})();
