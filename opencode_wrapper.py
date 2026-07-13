# -*- coding: utf-8 -*-
"""Python wrapper for OpenCode CLI with isolated environment per invocation."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import sys
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _kill_proc(proc: subprocess.Popen):
    """Kill a subprocess and its children cross-platform.

    On Unix uses process-group kill (requires start_new_session=True).
    On Windows falls back to proc.kill().
    """
    if not sys.platform.startswith("win"):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except (ProcessLookupError, AttributeError, PermissionError):
            pass
    try:
        proc.kill()
    except OSError:
        pass

ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub('', text)


# ── .env loading ──

def load_env(env_path: str | Path = ".env") -> dict[str, str]:
    """Load .env file and return key-value pairs."""
    env_path = Path(env_path)
    if not env_path.exists():
        return {}
    result = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            result[key.strip()] = val.strip()
    return result


# ── Skills Repository ──

class SkillsRepo:
    """Manages a directory of skills (subdirectories each containing SKILL.md)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def list(self) -> list[str]:
        """List available skill names."""
        if not self.path.exists():
            return []
        return sorted(
            child.name for child in self.path.iterdir()
            if child.is_dir() and (child / "SKILL.md").exists()
        )

    def copy_to(self, dst: Path, names: list[str]):
        """Copy selected skills into dst/skills/<name>/."""
        if not names:
            return
        skills_dir = dst / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            src = self.path / name
            if (src / "SKILL.md").exists():
                shutil.copytree(src, skills_dir / name, dirs_exist_ok=True)


# ── Agents Repository ──

class AgentsRepo:
    """Manages a directory of agents (.md files or subdirectories)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def list(self) -> list[str]:
        """List available agent names."""
        if not self.path.exists():
            return []
        names: set[str] = set()
        for child in self.path.iterdir():
            if child.suffix == ".md":
                names.add(child.stem)
            elif child.is_dir():
                for f in child.iterdir():
                    if f.suffix == ".md":
                        names.add(f.stem)
        return sorted(names)

    def copy_to(self, dst: Path, names: list[str]):
        """Copy selected agents into dst/agents/<name>.md."""
        if not names:
            return
        agents_dir = dst / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            src_file = self.path / f"{name}.md"
            if src_file.exists():
                shutil.copy2(src_file, agents_dir / f"{name}.md")
                continue
            src_dir = self.path / name
            if src_dir.is_dir():
                for f in src_dir.iterdir():
                    if f.suffix == ".md":
                        shutil.copy2(f, agents_dir / f.name)
                        break


# ── Configuration ──

@dataclass
class ProfileConfig:
    """Per-invocation configuration for an opencode run."""
    skills: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    model: Optional[str] = None       # override default model from .env
    profile_dir: Optional[str | Path] = None  # persistent profile path


@dataclass
class OpenCodeResult:
    """Result from an opencode CLI invocation."""
    text: str
    exit_code: int
    timed_out: bool = False


# Default config template — model resolved from env at runtime
BASE_CONFIG = {
    "$schema": "https://opencode.ai/config.json",
    "model": "{env:OPENCODE_DEFAULT_MODEL}",
    "autoupdate": False,
    "permission": {"*": "allow"},
    "snapshot": False,
}

# Env vars to isolate from system defaults
ISOLATION_ENV = {
    "OPENCODE_DISABLE_CLAUDE_CODE": "true",
    "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS": "true",
    "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT": "true",
    "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
    "OPENCODE_DISABLE_AUTOUPDATE": "true",
    "OPENCODE_DISABLE_MODELS_FETCH": "true",
    "OPENCODE_DISABLE_PRUNE": "true",
}


# ── Client ──

class OpenCodeClient:
    """Run opencode CLI in fully isolated profiles.

    Each call to ``run()`` creates a temporary directory with its own config,
    skills, agents, data, cache, logs and state — no cross-run interference.
    """

    def __init__(
        self,
        opencode_bin: str = "opencode",
        skills_repo: Optional[SkillsRepo] = None,
        agents_repo: Optional[AgentsRepo] = None,
        env_path: str | Path = ".env",
    ):
        self.opencode_bin = opencode_bin
        self.skills_repo = skills_repo
        self.agents_repo = agents_repo
        self.env_path = Path(env_path)
        self._env_cache: dict[str, str] | None = None

    # ── public API ──

    def run(self, prompt: str, profile: ProfileConfig | None = None,
            verbose: bool = False,
            timeout: int | None = None) -> OpenCodeResult:
        """Run prompt through llm-run.sh in a fully isolated profile.

        Args:
            prompt: The prompt to send to the LLM.
            profile: Controls which skills/agents/model to use.
            verbose: If True, print stderr logs.
            timeout: Timeout in seconds. None means no timeout.

        Returns:
            OpenCodeResult with the response text and exit code.
        """
        if profile is None:
            profile = ProfileConfig()

        return self._run_via_script(prompt, profile, verbose, timeout)

    def _run_via_script(self, prompt: str, profile: ProfileConfig,
                        verbose: bool = False,
                        timeout: int | None = None) -> OpenCodeResult:
        """Run prompt via llm-run.sh (Linux) or llm-run.py (Windows)."""
        is_windows = sys.platform.startswith("win")
        script_path = Path(__file__).parent / ("llm-run.py" if is_windows else "llm-run.sh")
        shell_cmd = [sys.executable, str(script_path)] if is_windows else ["bash", str(script_path)]
        profile_dir, needs_cleanup = self._prepare_profile_dir(profile)

        try:
            self._populate_skills_agents(profile_dir, profile)
            self._write_config(profile_dir, profile)
            work_dir = Path(os.environ.get("OPENCODE_WORK_DIR", os.getcwd()))
            env = self._build_env(profile_dir, profile, work_dir)

            proc = subprocess.Popen(
                shell_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                env=env,
                start_new_session=True,
            )

            try:
                stdout_bytes, stderr_bytes = proc.communicate(
                    input=prompt.encode("utf-8"), timeout=timeout
                )
            except subprocess.TimeoutExpired:
                _kill_proc(proc)
                stdout_bytes, stderr_bytes = proc.communicate()
                if verbose:
                    print(f"\n[TIMEOUT] Process killed after {timeout}s")
                return OpenCodeResult(text="", exit_code=-1, timed_out=True)
            except KeyboardInterrupt:
                _kill_proc(proc)
                proc.communicate()
                raise

            full_text = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")

            if verbose:
                print(strip_ansi(full_text), end="", flush=True)
                if stderr_text:
                    print("\n[stderr]", strip_ansi(stderr_text[:500]), sep="\n")

            return OpenCodeResult(text=full_text, exit_code=proc.returncode)

        finally:
            if needs_cleanup:
                shutil.rmtree(profile_dir, ignore_errors=True)

    def _run_direct(self, prompt: str, profile: ProfileConfig,
                    verbose: bool = False) -> OpenCodeResult:
        """Direct opencode invocation (fallback when llm-run.sh is absent)."""
        profile_dir, needs_cleanup = self._prepare_profile_dir(profile)

        try:
            self._populate_skills_agents(profile_dir, profile)
            self._write_config(profile_dir, profile)
            work_dir = Path(os.environ.get("OPENCODE_WORK_DIR", os.getcwd()))
            env = self._build_env(profile_dir, profile, work_dir)

            proc = subprocess.Popen(
                [self.opencode_bin, "--pure", "run", "--dir", str(work_dir), prompt],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                env=env,
            )

            # Read stdout chunk by chunk (only print when verbose)
            output_chunks: list[str] = []
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read(1024)
                if not chunk:
                    break
                decoded = chunk.decode("utf-8", errors="replace")
                if verbose:
                    print(strip_ansi(decoded), end="", flush=True)
                output_chunks.append(decoded)

            full_text = "".join(output_chunks).strip()

            # Collect stderr
            assert proc.stderr is not None
            stderr_text = proc.stderr.read().decode("utf-8", errors="replace")
            proc.wait()

            if verbose and stderr_text:
                print("\n[stderr]", stderr_text[:500], sep="\n")

            return OpenCodeResult(text=full_text, exit_code=proc.returncode)

        finally:
            if needs_cleanup:
                shutil.rmtree(profile_dir, ignore_errors=True)

    # ── internals ──

    def _load_dotenv(self) -> dict[str, str]:
        if self._env_cache is None:
            self._env_cache = load_env(self.env_path)
        return self._env_cache

    def _prepare_profile_dir(self, profile: ProfileConfig) -> tuple[Path, bool]:
        if profile.profile_dir:
            p = Path(profile.profile_dir)
            p.mkdir(parents=True, exist_ok=True)
            return p, False
        return Path(tempfile.mkdtemp(prefix="opencode-profile-")), True

    def _populate_skills_agents(self, profile_dir: Path, profile: ProfileConfig):
        """Copy selected skills/agents into profile_dir/.opencode/."""
        dot_opencode = profile_dir / ".opencode"
        if self.skills_repo and profile.skills:
            self.skills_repo.copy_to(dot_opencode, profile.skills)
        if self.agents_repo and profile.agents:
            self.agents_repo.copy_to(dot_opencode, profile.agents)

    def _write_config(self, profile_dir: Path, profile: ProfileConfig):
        config = dict(BASE_CONFIG)

        # Deny all skills by default; only allow the ones the user selected.
        # This blocks system skills (global opencode, .claude, plugins, etc.)
        # from being visible to the agent.
        skill_perms: dict[str, str] = {"*": "deny"}
        for s in profile.skills:
            skill_perms[s] = "allow"

        perm: dict = config.setdefault("permission", {})
        perm["skill"] = skill_perms

        with open(profile_dir / "config.json", "w") as f:
            json.dump(config, f, indent=2)

    def _build_env(self, profile_dir: Path, profile: ProfileConfig,
                   work_dir: Path | None = None) -> dict[str, str]:
        env = os.environ.copy()

        # Isolation flags
        env.update(ISOLATION_ENV)

        # .env values (low priority, don't override existing env vars)
        dotenv = self._load_dotenv()
        for k, v in dotenv.items():
            env.setdefault(k, v)

        # Work directory
        actual_work_dir = work_dir or Path(os.environ.get("OPENCODE_WORK_DIR", os.getcwd()))
        env.setdefault("OPENCODE_WORK_DIR", str(actual_work_dir))

        # Isolation directories (temp profile)
        env.update({
            "OPENCODE_CONFIG": str(profile_dir / "config.json"),
            "OPENCODE_DATA_DIR": str(profile_dir / "data"),
            "OPENCODE_CACHE_DIR": str(profile_dir / "cache"),
            "OPENCODE_LOG_DIR": str(profile_dir / "logs"),
            "OPENCODE_STATE_DIR": str(profile_dir / "state"),
            "OPENCODE_CLIENT": "python-wrapper",
        })

        # Model override
        if profile.model:
            env["OPENCODE_DEFAULT_MODEL"] = profile.model

        return env
