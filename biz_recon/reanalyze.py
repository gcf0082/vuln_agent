"""Stage 6: Vulnerability re-analysis — one client per file, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = ""):
    log(f"\n=== Stage 6: Vulnerability Re-Analysis ===")

    review_dir = work_dir / OUTPUT_PARENT / "vuln_review"
    if review_dir.exists() and any(review_dir.iterdir()):
        log("  SKIP: vuln_review already has output")
        return sorted(review_dir.glob("*"))

    vuln_files = sorted((work_dir / OUTPUT_PARENT / "vulnerabilities").glob("*.md"))
    if not vuln_files:
        log("  No vulnerability files found.")
        return []

    log(f"  Re-analyzing {len(vuln_files)} files in parallel (workers={max_workers})...")
    vars = build_vars(work_dir)
    failures: list[str] = []

    def reanalyze_one(vf_path):
        log(f"  ▶ {vf_path.name}")
        local_vars = {**vars,
            "vuln_file": vf_path.name,
        }
        prompt = read_prompt("review-vulnerability.txt", local_vars)
        if extra_prompt:
            prompt += "\n\n" + extra_prompt

        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            log(f"  ✗ {vf_path.name}")
            return False
        log(f"  ✓ {vf_path.name}")
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
