"""Example: multiple scenarios using opencode_wrapper."""

import json, tempfile, shutil
from pathlib import Path
from opencode_wrapper import OpenCodeClient, SkillsRepo, AgentsRepo, ProfileConfig, load_env

# ── Setup ──
skills_repo = SkillsRepo("./my_skills")
agents_repo = AgentsRepo("./my_agents")
env = load_env()

print(f"Default model: {env.get('OPENCODE_DEFAULT_MODEL')}")
print(f"Available skills: {skills_repo.list()}")
print(f"Available agents: {agents_repo.list()}")
print("=" * 60)

client = OpenCodeClient(skills_repo=skills_repo, agents_repo=agents_repo)

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

print("=" * 60)
print("All scenarios completed.")
