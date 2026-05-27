#!/usr/bin/env python3
"""Pipeline runner — executes all stages in sequence."""

import sys
from pathlib import Path

from . import collect, analyze, vuln, reanalyze
from .workspace import setup_logging, log, find_surface_files, find_vuln_files


def load_config() -> dict:
    """Load flat key-value config from analysis-config.yaml."""
    config_path = Path(__file__).parent.parent / "config" / "analysis-config.yaml"
    config: dict = {}
    if not config_path.exists():
        return config
    for line in config_path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if val.lower() == "true":
            val = True
        elif val.lower() == "false":
            val = False
        else:
            try:
                val = int(val)
            except ValueError:
                pass
        config[key] = val
    return config


def main():
    work_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    config = load_config()
    max_workers = config.get("max_workers", 3)
    setup_logging(Path.cwd())
    log(f"Work directory: {work_dir}")
    log(f"Max workers:    {max_workers}")
    log("=" * 50)

    collect.run(work_dir)
    analyze.run(work_dir, max_workers)
    vuln.run(work_dir, max_workers)
    reanalyze.run(work_dir, max_workers)

    log()
    log("=" * 50)
    log("Pipeline complete.")
    surfaces = find_surface_files(work_dir)
    vulns = find_vuln_files(work_dir)
    log(f"  Surface products: {len(surfaces)}")
    log(f"  Vuln products:    {len(vulns)}")


if __name__ == "__main__":
    main()
