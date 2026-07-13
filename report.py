#!/usr/bin/env python3
"""Generate report-data.js + copy static report.html to target directory."""

import argparse
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


def generate_data_js(surfaces: list[SurfaceEntry], file_contents: dict[str, str], target_name: str) -> str:
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    data_list = []
    total_findings = 0
    for s in surfaces:
        s_dict = asdict(s)
        s_dict["findings_count"] = len(s.findings) if s.findings else 0
        total_findings += s_dict["findings_count"]
        data_list.append(s_dict)

    report_data = {
        "target_name": target_name,
        "visited_key": f"vuln_agent_visited_{target_name}",
        "generated_at": now,
        "surface_count": len(surfaces),
        "total_findings": total_findings,
        "surfaces": data_list,
        "file_contents": file_contents,
    }
    json_str = json.dumps(report_data, ensure_ascii=False, indent=2)
    return f"window.REPORT_DATA = {json_str};\n"


def copy_static_files(target_dir: Path) -> None:
    project_root = Path(__file__).resolve().parent
    output_dir = target_dir / OUTPUT_PARENT

    src_html = project_root / "reporting" / "report.html"
    if src_html.exists():
        shutil.copy2(src_html, output_dir / "report.html")

    src_assets = project_root / "reporting" / "assets"
    dst_assets = output_dir / "assets"
    dst_assets.mkdir(parents=True, exist_ok=True)
    if src_assets.exists():
        for f in src_assets.iterdir():
            if f.is_file():
                shutil.copy2(f, dst_assets / f.name)


def generate_report(target_dir: Path) -> tuple[bool, str]:
    """Generate report-data.js + copy static files for a target directory.
    
    Returns (success, message).
    """
    try:
        if not target_dir.exists():
            return False, f"Target directory not found: {target_dir}"
        surfaces, file_contents = scan_output(target_dir)
        if not surfaces:
            return False, "No data found. Run the pipeline first."
        js_content = generate_data_js(surfaces, file_contents, target_dir.name)
        data_path = target_dir / OUTPUT_PARENT / "report-data.js"
        data_path.write_text(js_content, encoding="utf-8")
        copy_static_files(target_dir)
        return True, f"Report generated: {data_path}"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="Generate audit report data for vuln_agent")
    parser.add_argument("target_dir", help="Target directory that was analyzed")
    args = parser.parse_args()

    ok, msg = generate_report(Path(args.target_dir).resolve())
    print(msg)


if __name__ == "__main__":
    main()
