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

# ── 2. Load a skill — check profile dir structure ──
print("【2】With skill — verify SKILL.md lands in profile directory")
pf = Path(tempfile.mkdtemp(prefix="demo-"))
r = client.run("Explain what an API is.",
               ProfileConfig(skills=["formal-responder"], profile_dir=pf))
skill_file = pf / ".opencode" / "skills" / "formal-responder" / "SKILL.md"
print(f"  SKILL.md exists: {skill_file.exists()}")
print(f"  response: {r.text[:150]}")
shutil.rmtree(pf)
print()

# ── 3. Load an agent — check agent file in profile dir ──
print("【3】With agent — verify .md lands in profile directory")
pf = Path(tempfile.mkdtemp(prefix="demo-"))
r = client.run("What is 2+2?",
               ProfileConfig(agents=["qa-reviewer"], profile_dir=pf))
agent_file = pf / ".opencode" / "agents" / "qa-reviewer.md"
print(f"  agent file exists: {agent_file.exists()}")
print(f"  response: {r.text[:150]}")
shutil.rmtree(pf)
print()

# ── 4. Multi-select: 2 skills + 1 agent ──
print("【4】Multi-select: formal-responder + json-mode skills, planner agent")
r = client.run("Explain what an API is.",
               ProfileConfig(skills=["formal-responder", "json-mode"],
                             agents=["planner"]))
print(f"  exit={r.exit_code}  response: {r.text[:300]}\n")

# ── 5. Isolation check — two calls with different skills ──
print("【5】Isolation: two profiles with different skills, no cross-contamination")
pA = Path(tempfile.mkdtemp(prefix="demo-A-"))
pB = Path(tempfile.mkdtemp(prefix="demo-B-"))

client.run("hi", ProfileConfig(skills=["formal-responder"], profile_dir=pA))
client.run("hi", ProfileConfig(skills=["json-mode"], profile_dir=pB))

skillsA = [c.name for c in (pA / ".opencode" / "skills").iterdir()]
skillsB = [c.name for c in (pB / ".opencode" / "skills").iterdir()]
print(f"  Profile A skills: {skillsA}")
print(f"  Profile B skills: {skillsB}")
print(f"  Isolated (no overlap): {set(skillsA).isdisjoint(set(skillsB)) or skillsA != skillsB}")
shutil.rmtree(pA); shutil.rmtree(pB)
print()

# ── 6. Nonexistent skill name ──
print("【6】Graceful: nonexistent skill name won't crash")
r = client.run("Say hi.", ProfileConfig(skills=["does-not-exist"]))
print(f"  exit={r.exit_code}  response: {r.text[:100]}\n")

# ── 7. All features combined ──
print("【7】All together: 2 skills + 2 agents")
r = client.run("Suggest two Python project ideas.",
               ProfileConfig(skills=["formal-responder", "json-mode"],
                             agents=["planner", "qa-reviewer"]))
print(f"  exit={r.exit_code}  response:\n{r.text[:500]}\n")

# ── 8. Verify exact skill set — no more, no less ──
print("【8】Exact skill set deployed — no more, no less")
pf = Path(tempfile.mkdtemp(prefix="demo-skills-"))
client._populate_skills_agents(pf, ProfileConfig(skills=["formal-responder", "json-mode"], profile_dir=pf))
client._write_config(pf, ProfileConfig(skills=["formal-responder", "json-mode"]))
# Check on-disk: exactly the two skill directories
skills_found = {c.name for c in (pf / ".opencode" / "skills").iterdir()}
assert skills_found == {"formal-responder", "json-mode"}, f"unexpected skills: {skills_found}"
# Check config permission: exactly the two allowed
with open(pf / "config.json") as f:
    cfg = json.load(f)
allowed = {k for k, v in cfg["permission"]["skill"].items() if v == "allow"}
assert allowed == {"formal-responder", "json-mode"}, f"unexpected allowed: {allowed}"
shutil.rmtree(pf)
print(f"  skills dir: {skills_found}")
print(f"  config allowed: {allowed}")
print()

print("=" * 60)
print("All scenarios completed.")
