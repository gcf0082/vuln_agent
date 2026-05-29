"""Stage 6: Vulnerability re-analysis — one client per VULN, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .workspace import OUTPUT_PARENT, build_vars, read_prompt, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = ""):
    log(f"\n=== Stage 6: Vulnerability Re-Analysis ===")

    review_dir = work_dir / OUTPUT_PARENT / "vuln_review"
    if review_dir.exists() and any(review_dir.iterdir()):
        log("  SKIP: vuln_review already has output")
        return sorted(review_dir.glob("*"))

    vuln_files = sorted((work_dir / OUTPUT_PARENT / "vulnerabilities").glob("VULN-*.md"))
    if not vuln_files:
        log("  No VULN files found.")
        return []

    log(f"  Re-analyzing {len(vuln_files)} VULN files in parallel (workers={max_workers})...")
    vars = build_vars(work_dir)
    failures: list[str] = []

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
            return False
        log(f"    OK: {vf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for vf_path, ok in zip(vuln_files, pool.map(reanalyze_one, vuln_files)):
            if not ok:
                failures.append(vf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        log(msg)
        print(msg, flush=True)

    return sorted((work_dir / OUTPUT_PARENT / "vuln_review").glob("*"))
