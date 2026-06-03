// State
const API = '/api';
const STAGES = ['surfaces', 'analysis', 'vuln_tasks', 'vulnerabilities', 'vuln_review'];
const STAGE_LABELS = {
  surfaces: '暴露面',
  analysis: '攻击面分析',
  vuln_tasks: '漏洞分析任务',
  vulnerabilities: '漏洞分析结论',
  vuln_review: '二次审查结论',
};
const STAGE_COLORS = {
  surfaces: '#4caf50',
  analysis: '#2196f3',
  vuln_tasks: '#ff9800',
  vulnerabilities: '#f44336',
  vuln_review: '#9c27b0',
};

// ── Helpers ──

async function api(path, opts = {}) {
  const res = await fetch(API + path, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!res.ok) {
    let msg;
    try { msg = (await res.json()).error || res.statusText; } catch { msg = res.statusText; }
    throw new Error(msg);
  }
  return res.json();
}

function navigate(hash) { location.hash = hash; }

function qs(sel, ctx) { return (ctx || document).querySelector(sel); }

function esc(html) {
  const d = document.createElement('div');
  d.textContent = html;
  return d.innerHTML;
}

// ── Router ──

function route() {
  const hash = location.hash.slice(1) || '/projects';
  const parts = hash.split('/').filter(Boolean);

  if (hash === '/projects') renderProjectList();
  else if (parts.length >= 2 && parts[0] === 'projects') {
    const name = parts[1];
    const stage = parts[2];
    const fileId = parts[3] ? parseInt(parts[3]) : null;
    renderDashboard(name, stage, fileId);
  }
}

window.addEventListener('hashchange', route);
window.addEventListener('load', route);

// ── View: Project List ──

async function renderProjectList() {
  const projects = await api('/projects');

  document.getElementById('app').innerHTML = `
    <div class="page-full">
      <div class="content">
        <div class="create-section">
          <h3>创建项目</h3>
          <form id="create-form">
            <div class="form-row">
              <div class="form-group"><label>项目名</label><input name="name" required></div>
              <div class="form-group"><label>目标目录</label><input name="target_dir" required></div>
            </div>
            <div class="form-actions"><button type="submit" class="btn btn-primary">创建</button></div>
          </form>
        </div>
        <h2>项目列表</h2>
        <div class="proj-grid">
          ${projects.length === 0 ? '<p style="color:#999;grid-column:1/-1">暂无项目</p>' : projects.map(p => `
            <div class="proj-card" onclick="navigate('/projects/${p.name}')">
              <div class="proj-name">
                ${esc(p.name)}
                <span class="status ${p.status}">${p.status}</span>
              </div>
              <div class="proj-meta">目标: ${esc(p.target_dir)}</div>
              <div class="proj-meta">创建: ${p.created_at || '-'}</div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;

  const form = document.getElementById('create-form');
  if (form) form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    try {
      await api('/projects', { method: 'POST', body: JSON.stringify(data) });
      navigate('/projects');
    } catch (err) { alert('创建失败: ' + err.message); }
  });
}

// ── View: Dashboard ──

let _dashState = {
  project: null,
  stageFiles: {},
  active: null,    // file selected in LEFT sidebar (determines trace panel)
  viewing: null,   // file shown in MIDDLE panel
  trace: null,     // trace data for active
  expanded: {},
};

async function renderDashboard(name, activeStage, activeFileId) {
  const [proj, ...stageFileLists] = await Promise.all([
    api(`/projects/${name}`),
    ...STAGES.map(s => api(`/projects/${name}/files/${s}`).then(d => d.files).catch(() => [])),
  ]);

  const stageFiles = {};
  STAGES.forEach((s, i) => { stageFiles[s] = stageFileLists[i]; });

  _dashState = {
    project: proj,
    stageFiles,
    active: null,
    viewing: null,
    trace: null,
    expanded: Object.fromEntries(STAGES.map(s => [s, true])),
  };

  // Load active file if specified by URL
  if (activeStage && activeFileId && STAGES.includes(activeStage)) {
    await selectFile(activeStage, activeFileId);
  }

  renderDashLayout();

  // Bind header buttons
  const btnRun = qs('#dash-run-btn');
  if (btnRun) btnRun.onclick = () => showRunDialog(name);
  const btnDel = qs('#dash-del-btn');
  if (btnDel) btnDel.onclick = async () => {
    if (!confirm('确定删除项目 ' + name + '？将同时删除 _output 产物')) return;
    await api(`/projects/${name}`, { method: 'DELETE' });
    navigate('/projects');
  };
}

function renderDashLayout() {
  const p = _dashState.project;
  document.getElementById('app').innerHTML = `
    <div class="dashboard">
      <div class="dash-header">
        <span class="back" onclick="navigate('/projects')">← 项目列表</span>
        <span class="title">${esc(p.name)}</span>
        <span class="status ${p.status}">${p.status}</span>
        <span style="font-size:12px;color:#888">${esc(p.target_dir)}</span>
        <span class="spacer"></span>
        ${p.status === 'pending' || p.status === 'done' ? `<button id="dash-run-btn" class="header-btn">运行</button>` : ''}
        <button id="dash-del-btn" class="header-btn danger">删除</button>
      </div>
      <div class="dash-body">
        <div class="dash-sidebar" id="dash-sidebar"></div>
        <div class="dash-main" id="dash-main"></div>
      </div>
    </div>
  `;
  renderSidebar();
  renderMiddle();
}

function renderSidebar() {
  const el = document.getElementById('dash-sidebar');
  if (!el) return;
  const active = _dashState.active;

  let html = STAGES.map(s => {
    const files = _dashState.stageFiles[s] || [];
    const expanded = _dashState.expanded[s] !== false;
    const actKey = active ? `${active.stage}|${active.id}` : null;
    return `
      <div class="stage-group">
        <div class="stage-header" onclick="toggleStage('${s}')">
          <span class="arrow ${expanded ? 'open' : ''}">▶</span>
          <span style="color:${STAGE_COLORS[s]}">●</span>
          ${STAGE_LABELS[s] || s}
          <span class="count">${files.length}</span>
        </div>
        <ul class="stage-files ${expanded ? '' : 'collapsed'}">
          ${files.map(f => {
            const key = `${s}|${f.id}`;
            const isActive = key === actKey;
            return `<li class="stage-file ${isActive ? 'active' : ''}" onclick="onSelectFile('${s}',${f.id})">${esc(f.filename)}</li>`;
          }).join('')}
        </ul>
      </div>
    `;
  }).join('');

  // Trace section after surfaces
  const trace = _dashState.trace;
  if (trace) {
    html += `
      <div class="trace-section">
        <div class="trace-label">● 关联文件</div>
        <div class="trace-scroll">
          ${STAGES.map(s => {
            const files = trace.related[s] || [];
            const a = _dashState.active;
            if (files.length === 0) return '';
            return `
              <div style="margin-bottom:6px">
                <div style="font-size:10px;font-weight:600;color:${STAGE_COLORS[s]};margin-bottom:1px">${STAGE_LABELS[s] || s} (${files.length})</div>
                ${files.map(f => {
                  const isSource = a && a.stage === s && a.filename === f.filename;
                  return `<div class="trace-file ${isSource ? 'active-source' : ''}" ${isSource ? '' : `onclick="onTraceClick('${s}',${f.id})"`}>${esc(f.filename)}</div>`;
                }).join('')}
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }

  el.innerHTML = html;
}

function renderMiddle() {
  const el = document.getElementById('dash-main');
  if (!el) return;
  const viewing = _dashState.viewing;
  const active = _dashState.active;

  if (!viewing) {
    el.innerHTML = `
      <div class="detail-panel">
        <div class="detail-placeholder">
          <div style="text-align:center">
            <div style="font-size:48px;margin-bottom:12px;opacity:.3">📋</div>
            <div>从左侧选择文件查看详情</div>
            <div style="font-size:12px;color:#bbb;margin-top:6px">各阶段文件数: ${STAGES.map(s => `${STAGE_LABELS[s]}: ${(_dashState.stageFiles[s]||[]).length}`).join(' · ')}</div>
          </div>
        </div>
      </div>
    `;
    return;
  }

  const html = marked.parse(viewing.content);
  el.innerHTML = `
    <div class="detail-panel">
      <div class="detail-header">
        <span class="file-name">${esc(viewing.filename)}</span>
        <span class="file-stage" style="background:${STAGE_COLORS[viewing.stage]}22;color:${STAGE_COLORS[viewing.stage]}">${STAGE_LABELS[viewing.stage] || viewing.stage}</span>
        ${active && (active.stage !== viewing.stage || active.id !== viewing.id)
          ? `<span style="font-size:11px;color:#888">(关联自: ${STAGE_LABELS[active.stage] || active.stage} / ${esc(active.filename)})</span>`
          : ''}
      </div>
      <div class="detail-content">${html}</div>
    </div>
  `;
  document.querySelectorAll('.detail-content pre code').forEach(b => hljs.highlightElement(b));
}

// ── Actions ──

// Called when clicking a file in the LEFT sidebar
async function onSelectFile(stage, fileId) {
  try {
    const [file, trace] = await Promise.all([
      api(`/projects/${_dashState.project.name}/files/${stage}/${fileId}`),
      api(`/projects/${_dashState.project.name}/files/${stage}/${fileId}/trace`).catch(() => null),
    ]);
    _dashState.active = { ...file, stage, id: fileId };
    _dashState.viewing = { ...file, stage, id: fileId };
    _dashState.trace = trace;
  } catch (err) {
    _dashState.active = null;
    _dashState.viewing = null;
    _dashState.trace = null;
  }
  renderSidebar();
  renderMiddle();
}

// Called when clicking a file in the RIGHT trace panel
// Updates only the middle panel, left sidebar and trace stay untouched
async function onTraceClick(stage, fileId) {
  try {
    const file = await api(`/projects/${_dashState.project.name}/files/${stage}/${fileId}`);
    _dashState.viewing = { ...file, stage, id: fileId };
  } catch (err) {
    return;
  }
  renderMiddle();
}

// Called when clicking a file in the LEFT sidebar
async function selectFile(stage, fileId) {
  try {
    const [file, trace] = await Promise.all([
      api(`/projects/${_dashState.project.name}/files/${stage}/${fileId}`),
      api(`/projects/${_dashState.project.name}/files/${stage}/${fileId}/trace`).catch(() => null),
    ]);
    _dashState.active = { ...file, stage, id: fileId };
    _dashState.viewing = { ...file, stage, id: fileId };
    _dashState.trace = trace;
  } catch (err) {
    _dashState.active = null;
    _dashState.viewing = null;
    _dashState.trace = null;
  }
}

// ── Run Dialog ──

function showRunDialog(projectName) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-box">
      <h3>启动分析 — ${esc(projectName)}</h3>
      <div class="form-group"><label>Collect Prompt</label><input id="run-collect-prompt" placeholder="可选"></div>
      <div class="form-group"><label>Analyze Prompt</label><input id="run-analyze-prompt" placeholder="可选"></div>
      <div class="form-group"><label>Vuln Prompt</label><input id="run-vuln-prompt" placeholder="可选"></div>
      <div class="form-group"><label>Model</label><input id="run-model" placeholder="可选"></div>
      <div class="form-group"><label>Agent</label><input id="run-agent" placeholder="可选"></div>
      <div class="form-group"><label>Force Surface</label><input id="run-force-surface" placeholder="可选, 逗号分隔"></div>
      <div class="modal-actions">
        <button class="btn" onclick="this.closest('.modal-overlay').remove()">取消</button>
        <button class="btn btn-primary" onclick="startRun('${projectName}', this)">启动</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

async function startRun(projectName, btn) {
  btn.disabled = true;
  btn.textContent = '启动中...';
  const data = {
    collect_prompt: document.getElementById('run-collect-prompt')?.value || '',
    analyze_prompt: document.getElementById('run-analyze-prompt')?.value || '',
    vuln_prompt: document.getElementById('run-vuln-prompt')?.value || '',
    model: document.getElementById('run-model')?.value || '',
    agent: document.getElementById('run-agent')?.value || '',
    force_surface: document.getElementById('run-force-surface')?.value || '',
  };
  try {
    await api(`/projects/${projectName}/run`, { method: 'POST', body: JSON.stringify(data) });
    navigate(`/projects/${projectName}`);
  } catch (err) { alert('启动失败: ' + err.message); btn.disabled = false; btn.textContent = '启动'; }
}

function toggleStage(stage) {
  _dashState.expanded[stage] = !_dashState.expanded[stage];
  renderSidebar();
}
