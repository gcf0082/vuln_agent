#!/usr/bin/env python3
"""Collect one or more target analysis outputs to the tool's collection directory."""

import argparse
import json
import re
import shutil
from pathlib import Path


TOOL_DIR = Path(__file__).resolve().parent
COLLECTED_DIR = TOOL_DIR / "reporting" / "collected"
TARGETS_JS = TOOL_DIR / "reporting" / "targets.js"


def target_id(target_dir: Path) -> str:
    return str(target_dir.resolve()).replace("\\", "/").replace("/", "_")


def collect_target(target_dir: Path) -> dict:
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
    dest = COLLECTED_DIR / tid
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(output_dir, dest)

    return {
        "id": tid,
        "short_name": target_dir.name,
        "full_path": str(target_dir),
        "data_path": f"collected/{tid}/report-data.js",
    }


def update_targets_js(new_entries: list[dict]):
    existing = []
    if TARGETS_JS.exists():
        text = TARGETS_JS.read_text(encoding="utf-8")
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
    TARGETS_JS.write_text(js, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Collect target analysis outputs to tool's collection directory"
    )
    parser.add_argument("target_dirs", nargs="+", help="Target directories to collect")
    args = parser.parse_args()

    COLLECTED_DIR.mkdir(parents=True, exist_ok=True)

    new_entries = []
    for path_str in args.target_dirs:
        d = Path(path_str).resolve()
        if not d.is_dir():
            print(f"  skipping {d}: not a directory")
            continue
        print(f"collecting {d}...")
        try:
            entry = collect_target(d)
            new_entries.append(entry)
            print(f"  -> {entry['id']} ({entry['short_name']})")
        except Exception as e:
            print(f"  FAILED: {e}")

    if new_entries:
        update_targets_js(new_entries)
        count = len(new_entries)
        total = len(json.loads(re.search(
            r"window\.TARGETS\s*=\s*(\[.*?\])\s*;", TARGETS_JS.read_text("utf-8"), re.DOTALL
        ).group(1)))
        print(f"Done. Collected {count} target(s), {total} total in collection.")
    else:
        print("Nothing collected.")


if __name__ == "__main__":
    main()
