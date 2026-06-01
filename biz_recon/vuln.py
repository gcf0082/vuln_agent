"""Stage 3: Vulnerability analysis — one client per task, parallel."""

import concurrent.futures
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_vuln_files, log


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None):
    from .workspace import ensure_dirs
    log(f"\n=== Stage 3: Vulnerability Analysis ===")
    ensure_dirs(work_dir)

    tasks_dir = work_dir / OUTPUT_PARENT / "tasks"
    if not tasks_dir.exists():
        log("  No tasks directory found. Run task planning first.")
        return find_vuln_files(work_dir)

    task_files = sorted(tasks_dir.glob("*.md"))
    if not task_files:
        log("  No task files found. Run task planning first.")
        return find_vuln_files(work_dir)

    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        task_files = [f for f in task_files if any(s in f.name for s in stems)]
        if not task_files:
            log(f"  No matching tasks for force-list: {force_list}")
            return find_vuln_files(work_dir)
        log(f"  Force re-analyzing {len(task_files)} task(s): {[f.name for f in task_files]}")
    else:
        log(f"  Analyzing {len(task_files)} tasks in parallel (workers={max_workers})...")

    vars = build_vars(work_dir)
    failures: list[str] = []

    def analyze_one(task_path):
        log(f"  ▶ {task_path.name}")
        task_text = task_path.read_text()

        # Read the task file to find the source analysis file name
        # Format: **来源分析文件**：{filename}
        source_file = task_path.name  # fallback
        for line in task_text.splitlines():
            if "来源分析文件" in line and "：" in line:
                source_file = line.split("：", 1)[-1].strip()
                break

        local_vars = {**vars,
            "task_file": task_path.name,
            "task_content": task_text,
            "surface_file": source_file,
            "surface_stem": source_file.replace(".md", ""),
            "extra_prompt": f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else "",
        }
        prompt = read_prompt("analyze-vulnerability.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            log(f"  ✗ {task_path.name}")
            return False
        log(f"  ✓ {task_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for task_path, ok in zip(task_files, pool.map(analyze_one, task_files)):
            if not ok:
                failures.append(task_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        log(msg)
        print(msg, flush=True)

    return find_vuln_files(work_dir)
