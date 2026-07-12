#!/usr/bin/env python3
"""Generate a consolidated HTML audit report from vuln_agent output products."""

import argparse
import json
import re
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
    findings: list[FindingEntry]


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


def scan_output(target_dir: Path) -> list[SurfaceEntry]:
    output_dir = target_dir / OUTPUT_PARENT
    if not output_dir.exists():
        print(f"Error: {output_dir} not found. Run the pipeline first.")
        return []

    surfaces_dir = output_dir / "discovered_surfaces"
    analyzed_dir = output_dir / "analyzed_surfaces"
    findings_dir = output_dir / "vuln_findings"
    reviews_dir = output_dir / "vuln_reviews"

    surface_map: dict[str, SurfaceEntry] = {}

    if surfaces_dir.exists():
        for f in sorted(surfaces_dir.glob("*.md")):
            stem = f.stem
            parsed = parse_surface_file(f)
            analyzed_path = analyzed_dir / f.name
            surface_map[stem] = SurfaceEntry(
                stem=stem,
                filename=f.name,
                relative_path=f"./discovered_surfaces/{f.name}",
                surface_type=parsed["type"],
                category=parsed["category"],
                description=parsed["description"],
                source=parsed["source"],
                analyzed_relative_path=f"./analyzed_surfaces/{f.name}" if analyzed_path.exists() else None,
                findings=[],
            )

    if findings_dir.exists():
        for f in sorted(findings_dir.glob("*.md")):
            parsed = parse_finding_filename(f.name)
            if not parsed:
                continue
            prefix, surface_stem, n = parsed
            finding_stem = f.stem
            review_prefix = None
            review_filename = None
            review_relative_path = None

            if reviews_dir.exists():
                for rp in ("VULN", "NOVULN", "SUSPECTED"):
                    rf_name = f"{rp}-{finding_stem}.md"
                    if (reviews_dir / rf_name).exists():
                        review_prefix = rp
                        review_filename = rf_name
                        review_relative_path = f"./vuln_reviews/{rf_name}"
                        break

            meta = extract_finding_meta(f.read_text(encoding="utf-8"))
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

    return list(surface_map.values())


CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f6fa; color: #2c3e50; line-height: 1.6; }
.container { max-width: 1400px; margin: 0 auto; padding: 24px; }
header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #fff; padding: 32px 24px; border-radius: 12px; margin-bottom: 24px; }
header h1 { font-size: 24px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
header h1 span { font-size: 28px; }
header .meta { font-size: 14px; color: #a0aec0; margin-top: 8px; }
header .meta a { color: #63b3ed; text-decoration: none; }
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
.links a { display: inline-block; margin: 0 2px; padding: 4px 8px; border-radius: 4px; font-size: 12px; text-decoration: none; background: #edf2f7; color: #4a5568; transition: background 0.2s; }
.links a:hover { background: #cbd5e0; }
.surface-card { background: #fff; border-radius: 10px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.surface-card h3 { font-size: 16px; margin-bottom: 8px; }
.surface-card h3 a { color: #2b6cb0; text-decoration: none; }
.surface-card h3 a:hover { text-decoration: underline; }
.surface-card .meta { font-size: 13px; color: #718096; margin-bottom: 12px; }
.surface-card .sub-table { margin: 0; }
.surface-card .sub-table th { font-size: 11px; padding: 8px 12px; }
.surface-card .sub-table td { font-size: 13px; padding: 6px 12px; }
.empty { text-align: center; padding: 60px 20px; color: #a0aec0; font-size: 16px; }
.footer { margin-top: 24px; padding: 16px; text-align: center; font-size: 12px; color: #a0aec0; }
"""


def generate_html(surfaces: list[SurfaceEntry], target_name: str) -> str:
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    data_list = []
    total_findings = 0
    for s in surfaces:
        s_dict = asdict(s)
        s_dict["findings_count"] = len(s.findings)
        total_findings += len(s.findings)
        data_list.append(s_dict)

    json_data = json.dumps(data_list, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全审计报告 - {target_name}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>🛡</span> 安全审计报告</h1>
    <div class="meta">
      目标: <strong>{target_name}</strong> &middot; {now}
      &middot; {len(surfaces)} 攻击面 &middot; {total_findings} 发现
    </div>
  </header>

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

<script>
const DATA = {json_data};

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

function renderSummary(data) {{
  let surfaces = data.length;
  let total = 0, vuln = 0, novuln = 0, suspected = 0;
  let rvuln = 0, rnovuln = 0, rsuspected = 0, rnone = 0;
  let severe = 0, high = 0, medium = 0, low = 0;
  for (const s of data) {{
    for (const f of s.findings) {{
      total++;
      if (f.prefix === 'VULN') vuln++;
      else if (f.prefix === 'NOVULN') novuln++;
      else suspected++;
      if (f.review_prefix === 'VULN') rvuln++;
      else if (f.review_prefix === 'NOVULN') rnovuln++;
      else if (f.review_prefix === 'SUSPECTED') rsuspected++;
      else rnone++;
      const sv = (f.meta.severity || '').trim();
      if (sv === '严重') severe++;
      else if (sv === '高') high++;
      else if (sv === '中') medium++;
      else if (sv === '低') low++;
    }}
  }}
  document.getElementById('summary').innerHTML = `
    <div class="card highlight-blue"><div class="num">${{surfaces}}</div><div class="label">攻击面</div></div>
    <div class="card highlight-gray"><div class="num">${{total}}</div><div class="label">总发现</div></div>
    <div class="card highlight-green"><div class="num">${{rvuln}}</div><div class="label">复核确认</div></div>
    <div class="card highlight-red"><div class="num">${{rnovuln}}</div><div class="label">复核推翻</div></div>
    <div class="card highlight-yellow"><div class="num">${{rsuspected + rnone}}</div><div class="label">待定 / 未复核</div></div>
  `;
}}

function renderFindings(data) {{
  let html = '';
  if (data.length === 0) {{
    html = '<div class="empty">没有匹配的发现。</div>';
  }} else {{
    html = '<table><thead><tr><th>攻击面</th><th>漏洞名称</th><th>原始结论</th><th>复核结论</th><th>类型</th><th>CVSS</th><th>严重性</th><th>文件</th></tr></thead><tbody>';
    for (const f of data) {{
      const cvss = f.meta.cvss || '-';
      const sev = f.meta.severity || '-';
      const type = f.meta.vuln_type || '-';
      const title = f.meta.title || f.filename;
      const links = [];
      const surf = DATA.find(s => s.stem === f.surface_stem);
      if (surf && surf.relative_path) links.push(`<a href="${{surf.relative_path}}" target="_blank" title="攻击面">📄</a>`);
      if (surf && surf.analyzed_relative_path) links.push(`<a href="${{surf.analyzed_relative_path}}" target="_blank" title="业务流">🔍</a>`);
      links.push(`<a href="${{f.relative_path}}" target="_blank" title="漏洞分析">📋</a>`);
      if (f.review_relative_path) links.push(`<a href="${{f.review_relative_path}}" target="_blank" title="复核">✅</a>`);
      html += `<tr>
        <td><strong>${{f.surface_stem}}</strong></td>
        <td>${{title.substring(0, 60)}}</td>
        <td>${{badge(f.prefix)}}</td>
        <td>${{badge(f.review_prefix)}} ${{reviewStatus(f.review_prefix)}}</td>
        <td>${{type}}</td>
        <td>${{cvss}}</td>
        <td>${{sev}}</td>
        <td class="links">${{links.join('')}}</td>
      </tr>`;
    }}
    html += '</tbody></table>';
  }}
  document.getElementById('view-findings').innerHTML = html;
}}

function renderSurfaces(data) {{
  let html = '';
  if (data.length === 0) {{
    html = '<div class="empty">没有攻击面数据。</div>';
  }} else {{
    html = '';
    for (const s of data) {{
      const surfLinks = [];
      if (s.relative_path) surfLinks.push(`<a href="${{s.relative_path}}" target="_blank">📄 攻击面</a>`);
      if (s.analyzed_relative_path) surfLinks.push(`<a href="${{s.analyzed_relative_path}}" target="_blank">🔍 业务流</a>`);
      html += `<div class="surface-card">
        <h3><a href="${{s.relative_path || '#'}}" target="_blank">${{s.stem}}</a></h3>
        <div class="meta">${{s.surface_type ? '类型: ' + s.surface_type : ''}}${{s.category ? ' | 分类: ' + s.category : ''}}${{s.description ? ' | ' + s.description : ''}}</div>
        <div style="margin-bottom:8px;font-size:13px;color:#718096;">${{surfLinks.join(' &middot; ')}}</div>`;
      if (s.findings && s.findings.length > 0) {{
        html += '<table class="sub-table"><thead><tr><th>文件</th><th>原始结论</th><th>复核结论</th><th>类型</th><th>CVSS</th><th>严重性</th></tr></thead><tbody>';
        for (const f of s.findings) {{
          const cvss = f.meta.cvss || '-';
          const sev = f.meta.severity || '-';
          const type = f.meta.vuln_type || '-';
          const title = f.meta.title || f.filename;
          const flinks = [];
          flinks.push(`<a href="${{f.relative_path}}" target="_blank">📋</a>`);
          if (f.review_relative_path) flinks.push(`<a href="${{f.review_relative_path}}" target="_blank">✅</a>`);
          html += `<tr>
            <td>${{title.substring(0, 50)}} ${{flinks.join('')}}</td>
            <td>${{badge(f.prefix)}}</td>
            <td>${{badge(f.review_prefix)}} ${{reviewStatus(f.review_prefix)}}</td>
            <td>${{type}}</td>
            <td>${{cvss}}</td>
            <td>${{sev}}</td>
          </tr>`;
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
  const rv = document.getElementById('filter-review').value;
  const sv = document.getElementById('filter-surface').value;
  const sev = document.getElementById('filter-severity').value;
  let filtered = [];
  for (const s of DATA) {{
    for (const f of s.findings) {{
      if (rv !== 'all') {{
        const fRv = f.review_prefix || 'none';
        if (fRv !== rv) continue;
      }}
      if (sv !== 'all' && f.surface_stem !== sv) continue;
      if (sev !== 'all') {{
        const fSev = (f.meta.severity || '').trim();
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
  document.getElementById('count-label').textContent = `${{filtered.length}} 条结果`;
  renderFindings(filtered);
}}

function switchView(name, btn) {{
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('view-findings').style.display = name === 'findings' ? '' : 'none';
  document.getElementById('view-surfaces').style.display = name === 'surfaces' ? '' : 'none';
}}

(function init() {{
  renderSummary(DATA);
  const sel = document.getElementById('filter-surface');
  const stems = [...new Set(DATA.map(s => s.stem))];
  for (const stem of stems) {{
    const opt = document.createElement('option');
    opt.value = stem; opt.textContent = stem;
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

    surfaces = scan_output(target_dir)
    if not surfaces:
        print("No data found. Run the pipeline first.")
        return

    html = generate_html(surfaces, target_dir.name)
    output_path = target_dir / OUTPUT_PARENT / "report.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"Report generated: {output_path}")


if __name__ == "__main__":
    main()
