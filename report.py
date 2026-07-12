#!/usr/bin/env python3
"""Generate a consolidated HTML audit report from vuln_agent output products."""

import argparse
import html
import json
import re
import shutil
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional


OUTPUT_PARENT = ".vuln_agent_output"


@dataclass
class FindingMeta:
    title: str = ""
    vuln_type: str = ""
    cvss: str = ""
    severity: str = ""
    location: str = ""


@dataclass
class FindingEntry:
    surface_stem: str
    prefix: str
    n: str
    filename: str
    relative_path: str
    review_prefix: Optional[str]
    review_filename: Optional[str]
    review_relative_path: Optional[str]
    meta: FindingMeta
    content: str = ""
    review_content: str = ""


@dataclass
class SurfaceEntry:
    stem: str
    filename: str
    relative_path: str
    surface_type: str
    category: str
    description: str
    source: str
    analyzed_relative_path: Optional[str]
    content: str = ""
    analyzed_content: str = ""
    findings: Optional[list[FindingEntry]] = None


def parse_surface_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    result = {"type": "", "category": "", "description": "", "source": ""}
    for line in text.splitlines():
        m = re.search(r'^\s*-\s*\*+类型\*+\s*[:：]\s*(.+)', line)
        if m:
            result["type"] = m.group(1).strip()
        m = re.search(r'^\s*-\s*\*+分类\*+\s*[:：]\s*(.+)', line)
        if m:
            result["category"] = m.group(1).strip()
        m = re.search(r'^\s*-\s*\*+描述\*+\s*[:：]\s*(.+)', line)
        if m:
            result["description"] = m.group(1).strip()
        m = re.search(r'^\s*-\s*\*+来源\*+\s*[:：]\s*(.+)', line)
        if m:
            result["source"] = m.group(1).strip()
    if not result["type"]:
        result["type"] = "iface" if "iface" in path.name else "noniface"
    return result


def parse_finding_filename(name: str) -> Optional[tuple[str, str, str]]:
    m = re.match(r'^(VULN|NOVULN|SUSPECTED)-(.+)-(\d+)\.md$', name)
    if m:
        return m.group(1), m.group(2), m.group(3)
    return None


def extract_finding_meta(content: str) -> FindingMeta:
    meta = FindingMeta()
    m = re.search(r'^# (.+)', content, re.MULTILINE)
    if m:
        meta.title = m.group(1).strip()
    m = re.search(r'\*\*类型\*\*\s*[：:]\s*(.+)', content)
    if m:
        meta.vuln_type = m.group(1).strip()
    m = re.search(r'\*\*CVSS 评分\*\*\s*[：:]\s*([\d.]+)', content)
    if m:
        meta.cvss = m.group(1).strip()
    m = re.search(r'\*\*严重性\*\*\s*[：:]\s*(.+)', content)
    if m:
        meta.severity = m.group(1).strip()
    m = re.search(r'\*\*位置\*\*\s*[：:]\s*(.+)', content)
    if m:
        meta.location = m.group(1).strip()
    return meta


def scan_output(target_dir: Path) -> tuple[list[SurfaceEntry], dict[str, str]]:
    output_dir = target_dir / OUTPUT_PARENT
    if not output_dir.exists():
        print(f"Error: {output_dir} not found. Run the pipeline first.")
        return [], {}

    surfaces_dir = output_dir / "discovered_surfaces"
    analyzed_dir = output_dir / "analyzed_surfaces"
    findings_dir = output_dir / "vuln_findings"
    reviews_dir = output_dir / "vuln_reviews"

    surface_map: dict[str, SurfaceEntry] = {}
    file_contents: dict[str, str] = {}

    if surfaces_dir.exists():
        for f in sorted(surfaces_dir.glob("*.md")):
            stem = f.stem
            parsed = parse_surface_file(f)
            content = f.read_text(encoding="utf-8")
            file_contents[f"./discovered_surfaces/{f.name}"] = content

            analyzed_path = analyzed_dir / f.name
            analyzed_content = ""
            analyzed_rel = None
            if analyzed_path.exists():
                analyzed_content = analyzed_path.read_text(encoding="utf-8")
                analyzed_rel = f"./analyzed_surfaces/{f.name}"
                file_contents[analyzed_rel] = analyzed_content

            surface_map[stem] = SurfaceEntry(
                stem=stem,
                filename=f.name,
                relative_path=f"./discovered_surfaces/{f.name}",
                surface_type=parsed["type"],
                category=parsed["category"],
                description=parsed["description"],
                source=parsed["source"],
                analyzed_relative_path=analyzed_rel,
                content=content,
                analyzed_content=analyzed_content,
                findings=[],
            )

    if findings_dir.exists():
        for f in sorted(findings_dir.glob("*.md")):
            parsed = parse_finding_filename(f.name)
            if not parsed:
                continue
            prefix, surface_stem, n = parsed
            finding_stem = f.stem
            content = f.read_text(encoding="utf-8")
            file_contents[f"./vuln_findings/{f.name}"] = content

            review_prefix = None
            review_filename = None
            review_relative_path = None
            review_content = ""

            if reviews_dir.exists():
                for rp in ("VULN", "NOVULN", "SUSPECTED"):
                    rf_name = f"{rp}-{finding_stem}.md"
                    rf_path = reviews_dir / rf_name
                    if rf_path.exists():
                        review_prefix = rp
                        review_filename = rf_name
                        review_relative_path = f"./vuln_reviews/{rf_name}"
                        review_content = rf_path.read_text(encoding="utf-8")
                        file_contents[review_relative_path] = review_content
                        break

            meta = extract_finding_meta(content)
            fe = FindingEntry(
                surface_stem=surface_stem,
                prefix=prefix,
                n=n,
                filename=f.name,
                relative_path=f"./vuln_findings/{f.name}",
                review_prefix=review_prefix,
                review_filename=review_filename,
                review_relative_path=review_relative_path,
                meta=meta,
                content=content,
                review_content=review_content,
            )

            if surface_stem in surface_map:
                surface_map[surface_stem].findings.append(fe)
            else:
                surface_map[surface_stem] = SurfaceEntry(
                    stem=surface_stem,
                    filename=f"{surface_stem}.md",
                    relative_path="",
                    surface_type="",
                    category="",
                    description="",
                    source="",
                    analyzed_relative_path=None,
                    findings=[fe],
                )

    return list(surface_map.values()), file_contents


def copy_assets(target_dir: Path) -> Path:
    src = Path(__file__).resolve().parent / "assets"
    dst = target_dir / OUTPUT_PARENT / "assets"
    dst.mkdir(parents=True, exist_ok=True)
    if src.exists():
        for f in src.iterdir():
            if f.is_file():
                shutil.copy2(f, dst / f.name)
    return dst


CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f6fa; color: #2c3e50; line-height: 1.6; }
.page { min-height: 100vh; }
header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #fff; padding: 32px 48px; }
header h1 { font-size: 24px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
header h1 span { font-size: 28px; }
header .meta { font-size: 14px; color: #a0aec0; margin-top: 8px; }
header .meta a { color: #63b3ed; text-decoration: none; }
.main { padding: 24px 48px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #fff; border-radius: 10px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }
.card .num { font-size: 32px; font-weight: 700; margin-bottom: 4px; }
.card .label { font-size: 13px; color: #718096; }
.card.highlight-green .num { color: #38a169; }
.card.highlight-red .num { color: #e53e3e; }
.card.highlight-yellow .num { color: #d69e2e; }
.card.highlight-blue .num { color: #3182ce; }
.card.highlight-gray .num { color: #718096; }
.filters { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
.filters label { font-size: 13px; font-weight: 600; color: #4a5568; }
.filters select { padding: 6px 12px; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 14px; background: #fff; color: #2d3748; cursor: pointer; }
.tabs { display: flex; gap: 0; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; }
.tab-btn { padding: 10px 24px; border: none; background: none; font-size: 14px; font-weight: 600; color: #718096; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all 0.2s; }
.tab-btn:hover { color: #2d3748; }
.tab-btn.active { color: #3182ce; border-bottom-color: #3182ce; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
thead { background: #f7fafc; }
th { text-align: left; padding: 12px 16px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: #4a5568; letter-spacing: 0.05em; border-bottom: 2px solid #e2e8f0; }
td { padding: 10px 16px; font-size: 14px; border-bottom: 1px solid #f7fafc; }
tr:hover { background: #f7fafc; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.badge-vuln { background: #fed7d7; color: #c53030; }
.badge-novuln { background: #c6f6d5; color: #276749; }
.badge-suspected { background: #fefcbf; color: #975a16; }
.badge-empty { background: #e2e8f0; color: #4a5568; }
.links { white-space: nowrap; }
.links a { display: inline-block; margin: 0 2px; padding: 4px 8px; border-radius: 4px; font-size: 12px; text-decoration: none; background: #edf2f7; color: #4a5568; transition: background 0.2s; cursor: pointer; }
.links a:hover { background: #cbd5e0; }
.surface-card { background: #fff; border-radius: 10px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.surface-card h3 { font-size: 16px; margin-bottom: 8px; }
.surface-card h3 a { color: #2b6cb0; text-decoration: none; cursor: pointer; }
.surface-card h3 a:hover { text-decoration: underline; }
.surface-card .meta { font-size: 13px; color: #718096; margin-bottom: 12px; }
.surface-card .sub-table { margin: 0; }
.surface-card .sub-table th { font-size: 11px; padding: 8px 12px; }
.surface-card .sub-table td { font-size: 13px; padding: 6px 12px; }
.empty { text-align: center; padding: 60px 20px; color: #a0aec0; font-size: 16px; }
.footer { margin-top: 24px; padding: 16px 48px; text-align: center; font-size: 12px; color: #a0aec0; }

.drawer-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.45); z-index: 999; opacity: 0; visibility: hidden; transition: opacity 0.3s, visibility 0.3s; }
.drawer-overlay.active { opacity: 1; visibility: visible; }
.drawer { position: fixed; top: 0; right: 0; width: 55%; height: 100%; background: #fff; z-index: 1000; transform: translateX(100%); transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: -6px 0 24px rgba(0,0,0,0.2); display: flex; flex-direction: column; }
.drawer.active { transform: translateX(0); }
.drawer-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; border-bottom: 1px solid #e2e8f0; flex-shrink: 0; background: #fafbfc; }
.drawer-header h2 { font-size: 15px; font-weight: 600; color: #2d3748; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin: 0; }
.drawer-close { background: none; border: none; font-size: 22px; cursor: pointer; color: #718096; padding: 4px 8px; line-height: 1; border-radius: 4px; transition: background 0.15s; }
.drawer-close:hover { background: #edf2f7; color: #2d3748; }
.drawer-body { flex: 1; overflow-y: auto; padding: 24px; }
.drawer-body .markdown-body { padding: 0; max-width: none; }
.drawer-body .markdown-body pre { border-radius: 6px; }
.drawer-loading { text-align: center; padding: 60px 20px; color: #a0aec0; font-size: 14px; }

@media (max-width: 1024px) {
  .drawer { width: 75%; }
}
@media (max-width: 768px) {
  header { padding: 24px 20px; }
  .main { padding: 16px 20px; }
  .drawer { width: 100%; }
  .cards { grid-template-columns: repeat(2, 1fr); }
  .filters { flex-direction: column; align-items: stretch; }
}
"""


def generate_html(surfaces: list[SurfaceEntry], file_contents: dict[str, str], target_name: str) -> str:
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    data_list = []
    total_findings = 0
    for s in surfaces:
        s_dict = asdict(s)
        s_dict["findings_count"] = len(s.findings) if s.findings else 0
        total_findings += s_dict["findings_count"]
        data_list.append(s_dict)

    json_data = json.dumps(data_list, ensure_ascii=False)
    json_contents = json.dumps(file_contents, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全审计报告 - {html.escape(target_name)}</title>
<link rel="stylesheet" href="./assets/github-markdown.css">
<link rel="stylesheet" href="./assets/github-dark.min.css">
<style>{CSS}</style>
</head>
<body>
<div class="page">

  <header>
    <h1><span>🛡</span> 安全审计报告</h1>
    <div class="meta">
      目标: <strong>{html.escape(target_name)}</strong> &middot; {now}
      &middot; {len(surfaces)} 攻击面 &middot; {total_findings} 发现
    </div>
  </header>

  <div class="main">

    <div id="summary" class="cards"></div>

    <div class="filters">
      <label>复核结论</label>
      <select id="filter-review" onchange="applyFilters()">
        <option value="all">全部</option>
        <option value="VULN">✓ 复核确认 (VULN)</option>
        <option value="NOVULN">✗ 复核推翻 (NOVULN)</option>
        <option value="SUSPECTED">? 无法确定</option>
        <option value="none">— 未复核</option>
      </select>
      <label>攻击面</label>
      <select id="filter-surface" onchange="applyFilters()"><option value="all">全部</option></select>
      <label>严重性</label>
      <select id="filter-severity" onchange="applyFilters()">
        <option value="all">全部</option>
        <option value="严重">严重</option>
        <option value="高">高</option>
        <option value="中">中</option>
        <option value="低">低</option>
      </select>
      <span id="count-label" style="font-size:13px;color:#718096;margin-left:12px;"></span>
    </div>

    <div class="tabs">
      <button class="tab-btn active" onclick="switchView('findings', this)">📋 漏洞清单</button>
      <button class="tab-btn" onclick="switchView('surfaces', this)">📂 攻击面总览</button>
    </div>

    <div id="view-findings"></div>
    <div id="view-surfaces" style="display:none"></div>

    <div class="footer">Generated by vuln_agent report.py</div>

  </div>

</div>

<div class="drawer-overlay" id="drawerOverlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="drawer-header">
    <h2 id="drawerTitle">文件预览</h2>
    <button class="drawer-close" onclick="closeDrawer()">×</button>
  </div>
  <div class="drawer-body" id="drawerBody">
    <div class="drawer-loading">加载中...</div>
  </div>
</div>

<script src="./assets/marked.min.js"></script>
<script src="./assets/highlight.min.js"></script>
<script>
const DATA = {json_data};
const FILE_CONTENTS = {json_contents};

function escapeHtml(text) {{
  var d = document.createElement('div');
  d.appendChild(document.createTextNode(text));
  return d.innerHTML;
}}

function badge(prefix) {{
  if (prefix === 'VULN') return '<span class="badge badge-vuln">VULN</span>';
  if (prefix === 'NOVULN') return '<span class="badge badge-novuln">NOVULN</span>';
  if (prefix === 'SUSPECTED') return '<span class="badge badge-suspected">SUSPECTED</span>';
  return '<span class="badge badge-empty">-</span>';
}}

function reviewStatus(review_prefix) {{
  if (review_prefix === 'VULN') return '复核确认';
  if (review_prefix === 'NOVULN') return '复核推翻';
  if (review_prefix === 'SUSPECTED') return '无法确定';
  return '未复核';
}}

function getFileLabel(path) {{
  if (!path) return '';
  if (path.indexOf('discovered_surfaces/') !== -1) return '📄 攻击面';
  if (path.indexOf('analyzed_surfaces/') !== -1) return '🔍 业务流';
  if (path.indexOf('vuln_findings/') !== -1) return '📋 漏洞分析';
  if (path.indexOf('vuln_reviews/') !== -1) return '✅ 复核';
  return '📄 文件';
}}

function renderMarkdown(content) {{
  if (typeof marked !== 'undefined' && marked.parse) {{
    try {{
      var html = marked.parse(content, {{ breaks: true, gfm: true }});
      return '<div class="markdown-body">' + html + '</div>';
    }} catch(e) {{
      return '<pre style="white-space:pre-wrap;word-break:break-word;padding:16px;font-size:13px;">' + escapeHtml(content) + '</pre>';
    }}
  }}
  return '<pre style="white-space:pre-wrap;word-break:break-word;padding:16px;font-size:13px;">' + escapeHtml(content) + '</pre>';
}}

function openDrawer(path) {{
  if (!path || !FILE_CONTENTS[path]) {{
    document.getElementById('drawerBody').innerHTML = '<div class="empty">文件内容不可用。</div>';
    document.getElementById('drawerTitle').textContent = path ? path.split('/').pop() : '未知文件';
    document.getElementById('drawerOverlay').classList.add('active');
    document.getElementById('drawer').classList.add('active');
    document.body.style.overflow = 'hidden';
    return;
  }}
  var filename = path.split('/').pop();
  var label = getFileLabel(path);
  document.getElementById('drawerTitle').textContent = label + ': ' + filename;
  document.getElementById('drawerBody').innerHTML = renderMarkdown(FILE_CONTENTS[path]);
  document.getElementById('drawerOverlay').classList.add('active');
  document.getElementById('drawer').classList.add('active');
  document.body.style.overflow = 'hidden';
  if (typeof hljs !== 'undefined') {{
    setTimeout(function() {{
      document.querySelectorAll('#drawerBody pre code').forEach(function(block) {{
        hljs.highlightElement(block);
      }});
    }}, 50);
  }}
}}

function closeDrawer() {{
  document.getElementById('drawerOverlay').classList.remove('active');
  document.getElementById('drawer').classList.remove('active');
  document.body.style.overflow = '';
}}

document.addEventListener('keydown', function(e) {{
  if (e.key === 'Escape') closeDrawer();
}});

function renderSummary(data) {{
  var surfaces = data.length;
  var total = 0, vuln = 0, novuln = 0, suspected = 0;
  var rvuln = 0, rnovuln = 0, rsuspected = 0, rnone = 0;
  var severe = 0, high = 0, medium = 0, low = 0;
  for (var i = 0; i < data.length; i++) {{
    var s = data[i];
    if (!s.findings) continue;
    for (var j = 0; j < s.findings.length; j++) {{
      var f = s.findings[j];
      total++;
      if (f.prefix === 'VULN') vuln++;
      else if (f.prefix === 'NOVULN') novuln++;
      else suspected++;
      if (f.review_prefix === 'VULN') rvuln++;
      else if (f.review_prefix === 'NOVULN') rnovuln++;
      else if (f.review_prefix === 'SUSPECTED') rsuspected++;
      else rnone++;
      var sv = (f.meta.severity || '').trim();
      if (sv === '严重') severe++;
      else if (sv === '高') high++;
      else if (sv === '中') medium++;
      else if (sv === '低') low++;
    }}
  }}
  document.getElementById('summary').innerHTML =
    '<div class="card highlight-blue"><div class="num">' + surfaces + '</div><div class="label">攻击面</div></div>' +
    '<div class="card highlight-gray"><div class="num">' + total + '</div><div class="label">总发现</div></div>' +
    '<div class="card highlight-green"><div class="num">' + rvuln + '</div><div class="label">复核确认</div></div>' +
    '<div class="card highlight-red"><div class="num">' + rnovuln + '</div><div class="label">复核推翻</div></div>' +
    '<div class="card highlight-yellow"><div class="num">' + (rsuspected + rnone) + '</div><div class="label">待定 / 未复核</div></div>';
}}

function renderFindings(data) {{
  var html = '';
  if (data.length === 0) {{
    html = '<div class="empty">没有匹配的发现。</div>';
  }} else {{
    html = '<table><thead><tr><th>攻击面</th><th>漏洞名称</th><th>原始结论</th><th>复核结论</th><th>类型</th><th>CVSS</th><th>严重性</th><th>文件</th></tr></thead><tbody>';
    for (var i = 0; i < data.length; i++) {{
      var f = data[i];
      var cvss = f.meta.cvss || '-';
      var sev = f.meta.severity || '-';
      var type = f.meta.vuln_type || '-';
      var title = f.meta.title || f.filename;
      var safeTitle = escapeHtml(title.substring(0, 60));
      var surfIdx = -1;
      for (var k = 0; k < DATA.length; k++) {{
        if (DATA[k].stem === f.surface_stem) {{ surfIdx = k; break; }}
      }}
      var surf = surfIdx >= 0 ? DATA[surfIdx] : null;
      var links = [];
      if (surf && surf.relative_path) {{
        links.push('<a onclick="openDrawer(\\'' + surf.relative_path + '\\')" title="攻击面">📄</a>');
      }}
      if (surf && surf.analyzed_relative_path) {{
        links.push('<a onclick="openDrawer(\\'' + surf.analyzed_relative_path + '\\')" title="业务流">🔍</a>');
      }}
      links.push('<a onclick="openDrawer(\\'' + f.relative_path + '\\')" title="漏洞分析">📋</a>');
      if (f.review_relative_path) {{
        links.push('<a onclick="openDrawer(\\'' + f.review_relative_path + '\\')" title="复核">✅</a>');
      }}
      html += '<tr>' +
        '<td><strong>' + escapeHtml(f.surface_stem) + '</strong></td>' +
        '<td>' + safeTitle + '</td>' +
        '<td>' + badge(f.prefix) + '</td>' +
        '<td>' + badge(f.review_prefix) + ' ' + reviewStatus(f.review_prefix) + '</td>' +
        '<td>' + escapeHtml(type) + '</td>' +
        '<td>' + escapeHtml(cvss) + '</td>' +
        '<td>' + escapeHtml(sev) + '</td>' +
        '<td class="links">' + links.join('') + '</td>' +
      '</tr>';
    }}
    html += '</tbody></table>';
  }}
  document.getElementById('view-findings').innerHTML = html;
}}

function renderSurfaces(data) {{
  var html = '';
  if (data.length === 0) {{
    html = '<div class="empty">没有攻击面数据。</div>';
  }} else {{
    html = '';
    for (var i = 0; i < data.length; i++) {{
      var s = data[i];
      var surfLinks = [];
      if (s.relative_path) {{
        surfLinks.push('<a onclick="openDrawer(\\'' + s.relative_path + '\\')">📄 攻击面</a>');
      }}
      if (s.analyzed_relative_path) {{
        surfLinks.push('<a onclick="openDrawer(\\'' + s.analyzed_relative_path + '\\')">🔍 业务流</a>');
      }}
      var desc = '';
      if (s.surface_type) desc += '类型: ' + escapeHtml(s.surface_type);
      if (s.category) desc += (desc ? ' | ' : '') + '分类: ' + escapeHtml(s.category);
      if (s.description) desc += (desc ? ' | ' : '') + escapeHtml(s.description);
      html += '<div class="surface-card">' +
        '<h3><a onclick="openDrawer(\\'' + (s.relative_path || s.analyzed_relative_path || '') + '\\')">' + escapeHtml(s.stem) + '</a></h3>' +
        '<div class="meta">' + desc + '</div>' +
        '<div style="margin-bottom:8px;font-size:13px;color:#718096;">' + surfLinks.join(' &middot; ') + '</div>';
      if (s.findings && s.findings.length > 0) {{
        html += '<table class="sub-table"><thead><tr><th>文件</th><th>原始结论</th><th>复核结论</th><th>类型</th><th>CVSS</th><th>严重性</th></tr></thead><tbody>';
        for (var j = 0; j < s.findings.length; j++) {{
          var f = s.findings[j];
          var cvss = f.meta.cvss || '-';
          var sev = f.meta.severity || '-';
          var type = f.meta.vuln_type || '-';
          var title = f.meta.title || f.filename;
          var flinks = [];
          flinks.push('<a onclick="openDrawer(\\'' + f.relative_path + '\\')">📋</a>');
          if (f.review_relative_path) {{
            flinks.push('<a onclick="openDrawer(\\'' + f.review_relative_path + '\\')">✅</a>');
          }}
          html += '<tr>' +
            '<td>' + escapeHtml(title.substring(0, 50)) + ' ' + flinks.join('') + '</td>' +
            '<td>' + badge(f.prefix) + '</td>' +
            '<td>' + badge(f.review_prefix) + ' ' + reviewStatus(f.review_prefix) + '</td>' +
            '<td>' + escapeHtml(type) + '</td>' +
            '<td>' + escapeHtml(cvss) + '</td>' +
            '<td>' + escapeHtml(sev) + '</td>' +
          '</tr>';
        }}
        html += '</tbody></table>';
      }} else {{
        html += '<div style="font-size:13px;color:#a0aec0;">暂无发现</div>';
      }}
      html += '</div>';
    }}
  }}
  document.getElementById('view-surfaces').innerHTML = html;
}}

function applyFilters() {{
  var rv = document.getElementById('filter-review').value;
  var sv = document.getElementById('filter-surface').value;
  var sev = document.getElementById('filter-severity').value;
  var filtered = [];
  for (var i = 0; i < DATA.length; i++) {{
    var s = DATA[i];
    if (!s.findings) continue;
    for (var j = 0; j < s.findings.length; j++) {{
      var f = s.findings[j];
      if (rv !== 'all') {{
        var fRv = f.review_prefix || 'none';
        if (fRv !== rv) continue;
      }}
      if (sv !== 'all' && f.surface_stem !== sv) continue;
      if (sev !== 'all') {{
        var fSev = (f.meta.severity || '').trim();
        if (fSev !== sev) continue;
      }}
      filtered.push({{
        ...f,
        surface_stem: f.surface_stem,
        surface_type: s.surface_type,
        surface_category: s.category,
      }});
    }}
  }}
  document.getElementById('count-label').textContent = filtered.length + ' 条结果';
  renderFindings(filtered);
}}

function switchView(name, btn) {{
  document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  btn.classList.add('active');
  document.getElementById('view-findings').style.display = name === 'findings' ? '' : 'none';
  document.getElementById('view-surfaces').style.display = name === 'surfaces' ? '' : 'none';
}}

(function init() {{
  renderSummary(DATA);
  var sel = document.getElementById('filter-surface');
  var stems = [];
  for (var i = 0; i < DATA.length; i++) {{
    if (stems.indexOf(DATA[i].stem) === -1) stems.push(DATA[i].stem);
  }}
  for (var i = 0; i < stems.length; i++) {{
    var opt = document.createElement('option');
    opt.value = stems[i]; opt.textContent = stems[i];
    sel.appendChild(opt);
  }}
  applyFilters();
  renderSurfaces(DATA);
}})();
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Generate HTML audit report from vuln_agent output")
    parser.add_argument("target_dir", help="Target directory that was analyzed")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.exists():
        print(f"Error: target directory not found: {target_dir}")
        return

    surfaces, file_contents = scan_output(target_dir)
    if not surfaces:
        print("No data found. Run the pipeline first.")
        return

    copy_assets(target_dir)

    html = generate_html(surfaces, file_contents, target_dir.name)
    output_path = target_dir / OUTPUT_PARENT / "report.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"Report generated: {output_path}")


if __name__ == "__main__":
    main()
