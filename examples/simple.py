"""Example: multiple scenarios using opencode_wrapper."""

import json, os, sys, tempfile, shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from opencode_wrapper import OpenCodeClient, SkillsRepo, AgentsRepo, ProfileConfig, load_env

# ── Setup ──
BASE = Path(__file__).resolve().parent.parent
skills_repo = SkillsRepo(str(BASE / "skills"))
agents_repo = AgentsRepo(str(BASE / "agents"))
env = load_env()

print(f"Default model: {env.get('OPENCODE_DEFAULT_MODEL')}")
print(f"Available skills: {skills_repo.list()}")
print(f"Available agents: {agents_repo.list()}")
print("=" * 60)

client = OpenCodeClient(skills_repo=skills_repo, agents_repo=agents_repo)

# ── 0. Verify work_dir defaults to current dir ──
print("【0】Verify work_dir = current directory (not a temp profile dir)")
pf0 = Path(tempfile.mkdtemp(prefix="demo-verify-"))
env0 = client._build_env(pf0, ProfileConfig())
expected_wd = os.getcwd()
actual_wd = env0["OPENCODE_WORK_DIR"]
assert actual_wd == expected_wd, f"OPENCODE_WORK_DIR mismatch: {actual_wd} != {expected_wd}"
print(f"  OPENCODE_WORK_DIR={actual_wd} == cwd={expected_wd}  ✓")
shutil.rmtree(pf0)
print()

# ── 0b. Verify OPENCODE_WORK_DIR override works ──
print("【0b】Verify OPENCODE_WORK_DIR override")
pf0b = Path(tempfile.mkdtemp(prefix="demo-verify-"))
old_env = os.environ.get("OPENCODE_WORK_DIR")
os.environ["OPENCODE_WORK_DIR"] = "/custom/work/path"
env0b = client._build_env(pf0b, ProfileConfig())
assert env0b["OPENCODE_WORK_DIR"] == "/custom/work/path", (
    f"expected /custom/work/path, got {env0b['OPENCODE_WORK_DIR']}"
)
if old_env is None:
    del os.environ["OPENCODE_WORK_DIR"]
else:
    os.environ["OPENCODE_WORK_DIR"] = old_env
print(f"  OPENCODE_WORK_DIR=/custom/work/path  ✓")
shutil.rmtree(pf0b)
print()

# ── 1. Plain query (no skills, no agents) ──
print("【1】Basic query — no skills, no agents")
r = client.run("Say hello in one sentence.")
print(f"  exit={r.exit_code}  response: {r.text[:150]}\n")

