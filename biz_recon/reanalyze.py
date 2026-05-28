"""Stage 6: Vulnerability re-analysis — one client per VULN, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .workspace import OUTPUT_PARENT, build_vars, read_prompt, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = ""):
    log(f"\n=== Stage 6: Vulnerability Re-Analysis ===")

    vuln_files = sorted((work_dir / OUTPUT_PARENT / "vulnerabilities").glob("VULN-*.md"))
    if not vuln_files:
        log("  No VULN files found.")
        return []

    log(f"  Re-analyzing {len(vuln_files)} VULN files in parallel (workers={max_workers})...")
    vars = build_vars(work_dir)

    def reanalyze_one(vf_path):
        local_vars = {**vars,
            "vuln_file": vf_path.name,
        }
        prompt = read_prompt("review-vulnerability.txt", local_vars)
        if extra_prompt:
            prompt += "\n\n" + extra_prompt

        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            msg = f"Re-analysis failed for {vf_path.name} (exit={result.exit_code})"
            log(f"    ERROR: {msg}")
            raise RuntimeError(msg)
        log(f"    OK: {vf_path.name}")
        return vf_path

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(reanalyze_one, vuln_files))

    return sorted((work_dir / OUTPUT_PARENT / "vuln_review").glob("*"))
