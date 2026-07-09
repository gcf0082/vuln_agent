# -*- coding: utf-8 -*-
"""Stage 5: vuln_postprocess — user-custom post-processing after review.

Only runs when prompts-ext/postprocess-prompt.md exists.
Only processes VULN- and SUSPECTED- prefixed review files.
"""

import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, log


def run(work_dir: Path, extra_prompt: str = "",
        thinking: bool = False, prefix: str = ""):
    from .workspace import setup_stage_log
    pp_log = setup_stage_log("vuln_postprocess", prefix=prefix)

    ext_file = Path(__file__).parent.parent / "prompts-ext" / "postprocess-prompt.md"
    if not ext_file.exists():
        pp_log(f"{prefix} ⏭ 漏洞后置处理跳过（无 prompts-ext/postprocess-prompt.md）")
        return

    review_dir = work_dir / OUTPUT_PARENT / "vuln_reviews"
    if not review_dir.exists():
        pp_log(f"{prefix} No vuln_reviews directory found.")
        return

    review_files = sorted(review_dir.glob("*.md"))
    if not review_files:
        pp_log(f"{prefix} No review files found.")
        return

    relevant = [f for f in review_files
                if f.name.startswith("VULN-") or f.name.startswith("SUSPECTED-")]
    if not relevant:
        pp_log(f"{prefix} No VULN/SUSPECTED review files found.")
        return

    postprocess_dir = work_dir / OUTPUT_PARENT / "vuln_postprocess"
    postprocess_dir.mkdir(parents=True, exist_ok=True)

    vars = build_vars(work_dir)
    failures: list[str] = []

    def run_one(rf_path):
        rp_log = setup_stage_log("vuln_postprocess", rf_path.name, prefix=prefix)
        output_path = postprocess_dir / f"POST-{rf_path.stem}.md"
        if output_path.exists():
            rp_log(f"{prefix} ⏭ {rf_path.name}")
            return True

        rp_log(f"{prefix} → 漏洞后置处理 {rf_path.name}")

        review_stem = rf_path.stem
        vuln_stem = re.sub(r'^(?:VULN|SUSPECTED)-', '', review_stem)
        vuln_file = vuln_stem + ".md"

        analysis_stem = re.sub(r'^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-', '', vuln_stem)
        analysis_stem = re.sub(r'-\d+$', '', analysis_stem)
        analysis_file = analysis_stem + ".md"

        local_vars = {**vars,
            "review_file": rf_path.name,
            "review_stem": review_stem,
            "vuln_file": vuln_file,
            "analysis_file": analysis_file,
            "ext_prompt_path": str(ext_file),
        }
        prompt = read_prompt("postprocess-vulnerability.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt, verbose=thinking)
        if result.exit_code != 0:
            rp_log(f"{prefix} ✗ {rf_path.name}")
            return False
        rp_log(f"{prefix} ✓ 漏洞后置处理完成 {rf_path.name}")
        return True

    for rf_path in relevant:
        ok = run_one(rf_path)
        if not ok:
            failures.append(rf_path.name)

    if failures:
        msg = f"{prefix} FAILURES ({len(failures)}): {', '.join(failures)}"
        pp_log(msg)
        print(msg, flush=True)
