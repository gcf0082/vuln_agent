#!/usr/bin/env python3
"""Collect one or more target outputs to output/reports/<name>/."""

import argparse
import glob as glob_module
import json
import re
import shutil
from pathlib import Path


TOOL_DIR = Path(__file__).resolve().parent
REPORTING_DIR = TOOL_DIR / "reporting"
OUTPUT_DIR = TOOL_DIR / "output" / "reports"


def target_id(target_dir: Path) -> str:
    return str(target_dir.resolve()).replace("\\", "/").replace("/", "_").replace(":", "")


def collect_target(target_dir: Path, dest_collected_dir: Path) -> dict:
    target_dir = target_dir.resolve()
    output_dir = target_dir / ".vuln_agent_output"

    if not output_dir.exists():
        raise FileNotFoundError(f"{output_dir} not found. Run the pipeline first.")

    data_js = output_dir / "report-data.js"
    if not data_js.exists():
        print(f"  generating report-data.js for {target_dir.name}...")
        from report import generate_report
        ok, msg = generate_report(target_dir)
        if not ok:
            raise RuntimeError(f"generate_report failed: {msg}")

    tid = target_id(target_dir)
    dest = dest_collected_dir / tid
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(output_dir, dest)

    return {
        "id": tid,
        "short_name": target_dir.name,
        "full_path": str(target_dir),
        "data_path": f"collected/{tid}/report-data.js",
    }


def copy_template_files(dest_dir: Path) -> None:
    for fname in ["dashboard.html", "report.html"]:
        src = REPORTING_DIR / fname
        if src.exists():
            shutil.copy2(src, dest_dir / fname)
    src_assets = REPORTING_DIR / "assets"
    dst_assets = dest_dir / "assets"
    dst_assets.mkdir(parents=True, exist_ok=True)
    if src_assets.exists():
        for f in src_assets.iterdir():
            if f.is_file():
                shutil.copy2(f, dst_assets / f.name)


def update_targets_js(new_entries: list[dict], dest_dir: Path) -> None:
    targets_js = dest_dir / "targets.js"
    existing = []
    if targets_js.exists():
        text = targets_js.read_text(encoding="utf-8")
        m = re.search(r"window\.TARGETS\s*=\s*(\[.*?\])\s*;", text, re.DOTALL)
        if m:
            try:
                existing = json.loads(m.group(1))
            except json.JSONDecodeError:
                existing = []

    by_id = {t["id"]: t for t in existing}
    for e in new_entries:
        by_id[e["id"]] = e

    all_targets = sorted(by_id.values(), key=lambda t: t["short_name"])
    js = f"window.TARGETS = {json.dumps(all_targets, ensure_ascii=False, indent=2)};\n"
    targets_js.write_text(js, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Collect target outputs to output/reports/<name>/"
    )
    parser.add_argument("--name", "-n", default="report",
                        help="Output directory name under output/reports/ (default: report)")
    parser.add_argument("target_dirs", nargs="+", help="Target directories to collect")
    args = parser.parse_args()

    dest_base = OUTPUT_DIR / args.name
    dest_collected = dest_base / "collected"
    dest_collected.mkdir(parents=True, exist_ok=True)

    copy_template_files(dest_base)

    paths = []
    for arg in args.target_dirs:
        expanded = glob_module.glob(arg, recursive=True)
        if expanded:
            paths.extend(Path(p).resolve() for p in expanded)
        else:
            paths.append(Path(arg).resolve())

    new_entries = []
    for d in paths:
        if not d.is_dir():
            print(f"  skipping {d}: not a directory")
            continue
        print(f"collecting {d}...")
        try:
            entry = collect_target(d, dest_collected)
            new_entries.append(entry)
            print(f"  -> {entry['id']} ({entry['short_name']})")
        except Exception as e:
            print(f"  FAILED: {e}")

    if new_entries:
        update_targets_js(new_entries, dest_base)
        out_file = dest_base / "targets.js"
        m = re.search(r"window\.TARGETS\s*=\s*(\[.*?\])\s*;",
                      out_file.read_text("utf-8"), re.DOTALL)
        total = len(json.loads(m.group(1))) if m else 0
        print(f"Done. Collected {len(new_entries)} target(s), {total} total in output/reports/{args.name}/.")
    else:
        print("Nothing collected.")


if __name__ == "__main__":
    main()
