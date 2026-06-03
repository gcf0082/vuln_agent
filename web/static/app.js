const { createApp, ref, reactive, computed, watch, nextTick, defineComponent, provide, inject } = Vue;

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

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!res.ok) {
    let msg;
    try { msg = (await res.json()).error || res.statusText; } catch { msg = res.statusText; }
    throw new Error(msg);
  }
  return res.json();
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

// ── Root App ──

const app = createApp({
  setup() {
    const route = ref('projects');
    const routeParams = reactive({ name: '', stage: null, fileId: null });
    const toast = reactive({ show: false, msg: '' });
    const runDialog = reactive({ show: false, projectName: '' });

    let toastTimer = null;
    function showToast(msg) {
      toast.msg = msg;
      toast.show = true;
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { toast.show = false; }, 2500);
    }

    function onRunStarted() {
      runDialog.show = false;
      showToast('任务已启动');
    }

    function parseRoute() {
      const hash = location.hash.slice(1) || '/projects';
      const parts = hash.split('/').filter(Boolean);
      if (hash === '/projects') {
        route.value = 'projects';
      } else if (parts[0] === 'projects' && parts[1]) {
        route.value = 'dashboard';
        routeParams.name = parts[1];
        routeParams.stage = STAGES.includes(parts[2]) ? parts[2] : null;
        routeParams.fileId = parts[3] ? parseInt(parts[3]) : null;
      }
    }

    parseRoute();
    window.addEventListener('hashchange', parseRoute);

    function navigate(hash) { location.hash = hash; }

    function openRunDialog(name) {
      runDialog.projectName = name;
      runDialog.show = true;
    }

    provide('showToast', showToast);
    provide('navigate', navigate);
    provide('openRunDialog', openRunDialog);

    return { route, routeParams, toast, runDialog, showToast, navigate, onRunStarted };
  },
});

// ── ProjectList Component ──

app.component('ProjectList', {
  template: `
    <div class="page-full">
      <div class="content">
        <div class="create-section">
          <h3>创建项目</h3>
          <form @submit.prevent="createProject">
            <div class="form-row">
              <div class="form-group"><label>项目名</label><input v-model="form.name" required></div>
              <div class="form-group"><label>目标目录</label><input v-model="form.targetDir" required></div>
            </div>
            <div class="form-actions"><button type="submit" class="btn btn-primary">创建</button></div>
          </form>
        </div>
        <h2>项目列表</h2>
        <div v-if="loading" style="color:#999;padding:20px 0">加载中...</div>
        <div v-else class="proj-grid">
          <p v-if="projects.length===0" style="color:#999;grid-column:1/-1">暂无项目</p>
          <div v-for="p in projects" :key="p.name" class="proj-card" @click="navigate('/projects/'+p.name)">
            <div class="proj-name">
              {{ p.name }}
              <span class="status" :class="p.status">{{ p.status }}</span>
            </div>
            <div class="proj-meta">目标: {{ p.target_dir }}</div>
            <div class="proj-meta">创建: {{ p.created_at || '-' }}</div>
          </div>
        </div>
      </div>
    </div>
  `,
  setup() {
    const projects = ref([]);
    const loading = ref(true);
    const form = reactive({ name: '', targetDir: '' });
    const showToast = inject('showToast');
    const navigate = inject('navigate');

    async function loadProjects() {
      loading.value = true;
      try { projects.value = await api('/projects'); } catch {}
      loading.value = false;
    }

    async function createProject() {
      try {
        await api('/projects', {
          method: 'POST',
          body: JSON.stringify({ name: form.name, target_dir: form.targetDir }),
        });
        form.name = '';
        form.targetDir = '';
        showToast('项目创建成功');
        await loadProjects();
      } catch (err) { alert('创建失败: ' + err.message); }
    }

    loadProjects();
    return { projects, loading, form, navigate, createProject };
  },
});

// ── Dashboard Component ──

app.component('Dashboard', {
  props: {
    projectName: String,
    activeStage: String,
    activeFileId: Number,
  },
  template: `
    <div class="dashboard">
      <div class="dash-header">
        <span class="back" @click="navigate('/projects')">← 项目列表</span>
        <span class="title">{{ project.name }}</span>
        <span class="status" :class="project.status">{{ project.status }}</span>
        <span style="font-size:12px;color:#888">{{ project.target_dir }}</span>
        <span class="spacer"></span>
        <button v-if="['pending','done','error'].includes(project.status)" class="header-btn" @click="showRunDialog">启动</button>
        <button class="header-btn danger" @click="deleteProject">删除</button>
      </div>
      <div class="dash-body">
        <div class="dash-sidebar">
          <div v-for="s in stages" :key="s" class="stage-group">
            <div class="stage-header" @click="toggleStage(s)">
              <span class="arrow" :class="expanded[s]?'open':''">▶</span>
              <span :style="{color: stageColors[s]}">●</span>
              {{ stageLabels[s] || s }}
              <span class="count">{{ (stageFiles[s]||[]).length }}</span>
            </div>
            <ul class="stage-files" :class="expanded[s]?'':'collapsed'">
              <li v-for="f in (stageFiles[s]||[])" :key="f.id"
                class="stage-file"
                :class="{active: active && active.stage===s && active.id===f.id}"
                @click="selectFile(s,f.id)">
                {{ f.filename }}
              </li>
            </ul>
          </div>
          <div v-if="trace" class="trace-section">
            <div class="trace-label">● 关联文件</div>
            <div class="trace-scroll">
              <div v-for="s in stages" :key="'t'+s" v-if="trace.related[s] && trace.related[s].length">
                <div style="margin-bottom:6px">
                  <div style="font-size:10px;font-weight:600;margin-bottom:1px" :style="{color:stageColors[s]}">{{ stageLabels[s] || s }} ({{ trace.related[s].length }})</div>
                  <div v-for="f in trace.related[s]" :key="f.id"
                    class="trace-file"
                    :class="{'active-source': active && active.stage===s && active.filename===f.filename}"
                    @click="traceClick(s,f.id)">
                    {{ f.filename }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="dash-main">
          <div v-if="!viewing" class="detail-panel">
            <div class="detail-placeholder">
              <div style="text-align:center">
                <div style="font-size:48px;margin-bottom:12px;opacity:.3">📋</div>
                <div>从左侧选择文件查看详情</div>
                <div style="font-size:12px;color:#bbb;margin-top:6px">
                  各阶段文件数:
                  {{ stages.map(s => stageLabels[s]+': '+(stageFiles[s]||[]).length).join(' · ') }}
                </div>
              </div>
            </div>
          </div>
          <div v-else class="detail-panel">
            <div class="detail-header">
              <span class="file-name">{{ viewing.filename }}</span>
              <span class="file-stage" :style="{background: stageColors[viewing.stage]+'22', color: stageColors[viewing.stage]}">{{ stageLabels[viewing.stage] || viewing.stage }}</span>
              <span v-if="active && (active.stage!==viewing.stage || active.id!==viewing.id)" style="font-size:11px;color:#888">
                (关联自: {{ stageLabels[active.stage] || active.stage }} / {{ active.filename }})
              </span>
            </div>
            <div class="detail-content" v-html="renderedContent"></div>
          </div>
        </div>
      </div>
    </div>
  `,
  setup(props) {
    const project = reactive({ name: '', target_dir: '', status: '' });
    const stageFiles = reactive({});
    const active = ref(null);
    const viewing = ref(null);
    const trace = ref(null);
    const expanded = reactive(Object.fromEntries(STAGES.map(s => [s, true])));
    const renderedContent = ref('');

    function navigate(hash) { location.hash = hash; }

    async function load() {
      try {
        const [proj, ...fileLists] = await Promise.all([
          api(`/projects/${props.projectName}`),
          ...STAGES.map(s =>
            api(`/projects/${props.projectName}/files/${s}`).then(d => d.files).catch(() => [])
          ),
        ]);
        Object.assign(project, proj);
        STAGES.forEach((s, i) => { stageFiles[s] = fileLists[i]; });

        if (props.activeStage && props.activeFileId && STAGES.includes(props.activeStage)) {
          await selectFile(props.activeStage, props.activeFileId);
        }
      } catch {}
    }

    async function selectFile(stage, fileId) {
      try {
        const [file, traceData] = await Promise.all([
          api(`/projects/${props.projectName}/files/${stage}/${fileId}`),
          api(`/projects/${props.projectName}/files/${stage}/${fileId}/trace`).catch(() => null),
        ]);
        active.value = { ...file, stage, id: fileId };
        viewing.value = { ...file, stage, id: fileId };
        trace.value = traceData;
      } catch {
        active.value = null;
        viewing.value = null;
        trace.value = null;
      }
    }

    function traceClick(stage, fileId) {
      api(`/projects/${props.projectName}/files/${stage}/${fileId}`)
        .then(file => { viewing.value = { ...file, stage, id: fileId }; })
        .catch(() => {});
    }

    function toggleStage(s) { expanded[s] = !expanded[s]; }

    const openRunDialog = inject('openRunDialog');
    function showRunDialog() { openRunDialog(props.projectName); }

    async function deleteProject() {
      if (!confirm('确定删除项目 ' + props.projectName + '？将同时删除 _output 产物')) return;
      await api(`/projects/${props.projectName}`, { method: 'DELETE' });
      navigate('/projects');
    }

    watch(viewing, (v) => {
      if (v && v.content) {
        nextTick(() => {
          renderedContent.value = marked.parse(v.content);
          nextTick(() => {
            document.querySelectorAll('.detail-content pre code').forEach(b => hljs.highlightElement(b));
          });
        });
      } else {
        renderedContent.value = '';
      }
    }, { immediate: true });

    load();

    return {
      stages: STAGES,
      stageLabels: STAGE_LABELS,
      stageColors: STAGE_COLORS,
      project, stageFiles, active, viewing, trace, expanded, renderedContent,
      navigate, selectFile, traceClick, toggleStage, showRunDialog, deleteProject,
    };
  },
});

// ── RunDialog Component ──

app.component('RunDialog', {
  props: { projectName: String },
  emits: ['close', 'started'],
  template: `
    <div class="modal-overlay" @click.self="$emit('close')">
      <div class="modal-box">
        <h3>启动分析 — {{ projectName }}</h3>
        <div class="form-group"><label>Collect Prompt</label><input v-model="form.collect_prompt" placeholder="可选"></div>
        <div class="form-group"><label>Analyze Prompt</label><input v-model="form.analyze_prompt" placeholder="可选"></div>
        <div class="form-group"><label>Vuln Prompt</label><input v-model="form.vuln_prompt" placeholder="可选"></div>
        <div class="form-group"><label>Model</label><input v-model="form.model" placeholder="可选"></div>
        <div class="form-group"><label>Agent</label><input v-model="form.agent" placeholder="可选"></div>
        <div class="form-group"><label>Force Surface</label><input v-model="form.force_surface" placeholder="可选, 逗号分隔"></div>
        <div class="modal-actions">
          <button class="btn" @click="$emit('close')">取消</button>
          <button class="btn btn-primary" :disabled="starting" @click="startRun">{{ starting ? '启动中...' : '启动' }}</button>
        </div>
      </div>
    </div>
  `,
  setup(props, { emit }) {
    const form = reactive({
      collect_prompt: '', analyze_prompt: '', vuln_prompt: '',
      model: '', agent: '', force_surface: '',
    });
    const starting = ref(false);

    async function startRun() {
      starting.value = true;
      try {
        await api(`/projects/${props.projectName}/run`, {
          method: 'POST',
          body: JSON.stringify({ ...form }),
        });
        emit('started');
      } catch (err) { alert('启动失败: ' + err.message); starting.value = false; }
    }

    return { form, starting, startRun };
  },
});

app.mount('#app');
