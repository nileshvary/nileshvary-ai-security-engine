"""Internal subprocess driver for running garak from inside RemediAX.

Wraps the ``python -m garak ...`` CLI behind a small object that:

* checks whether garak is importable in the current Python environment;
* locates garak's per-user output directory across Linux / macOS / Windows;
* builds an argv list using garak's current ``--target_type`` /
  ``--target_name`` flags (the deprecated ``--model_type`` /
  ``--model_name`` aliases are avoided);
* runs the scan as a child process and yields stdout lines as they
  arrive so the Streamlit caller can stream progress live;
* finds the newest ``.report.jsonl`` produced by the run; and
* hands that report off to ``GarakParser`` to produce ``Finding`` records.

Security notes:
    * ``subprocess.Popen`` is always invoked with ``shell=False`` and an
      argv list, never a shell string. User-supplied values are passed
      through ``argv`` only — no string interpolation into shell.
    * API keys are exported into the child process's environment, NOT
      placed on the command line where they would leak into process
      listings and shell history.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

logger = logging.getLogger(__name__)


# Maximum seconds a single garak scan is allowed to run before the
# Popen wait() is cancelled. Conservative ceiling — garak's own
# "all probes" sweep can take an hour; the streamed UI lets the user
# notice activity well before this.
DEFAULT_SCAN_TIMEOUT_SECONDS: int = 60 * 60  # 1 hour


class GarakRunner:
    """Spawn garak as a subprocess and surface its results to RemediAX."""

    # garak's user-data directory follows platformdirs conventions.
    # We probe both the standard Linux/macOS path and the Windows
    # AppData path so the runner works on any host.
    _LINUX_MAC_DIR: Path = Path.home() / ".local" / "share" / "garak" / "garak_runs"
    _WINDOWS_DIR: Path = (
        Path.home() / "AppData" / "Local" / "garak" / "garak_runs"
    )

    def __init__(self, python_exe: str | None = None) -> None:
        """Initialize the runner.

        Args:
            python_exe: Override the python interpreter used to invoke
                ``python -m garak``. Defaults to ``sys.executable`` so
                the child process inherits the same venv as the app.
        """
        self.python_exe: str = python_exe or sys.executable

    # ------------------------------------------------------------------
    # Environment / discovery
    # ------------------------------------------------------------------

    def is_garak_installed(self) -> bool:
        """True when ``python -m garak --version`` succeeds in the active env."""
        try:
            result = subprocess.run(
                [self.python_exe, "-m", "garak", "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.info("garak install check failed: %s", exc)
            return False
        installed = result.returncode == 0
        if installed:
            logger.info(
                "garak is installed (version output: %s)",
                result.stdout.strip()[:80],
            )
        else:
            logger.info(
                "garak not installed (rc=%d, stderr=%s)",
                result.returncode,
                result.stderr.strip()[:200],
            )
        return installed

    def get_garak_runs_dir(self) -> Path:
        """Return the per-user garak_runs directory for this host.

        Returns the first path that exists, falling back to the
        platform default when neither exists yet (garak creates the
        directory on its first run).
        """
        if self._WINDOWS_DIR.exists():
            return self._WINDOWS_DIR
        if self._LINUX_MAC_DIR.exists():
            return self._LINUX_MAC_DIR
        # Neither exists — default to the platform's canonical path so
        # the caller has somewhere to look once garak finishes.
        if os.name == "nt":
            return self._WINDOWS_DIR
        return self._LINUX_MAC_DIR

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    def build_command(
        self,
        target_type: str,
        target_name: str,
        probes: list[str] | None = None,
        *,
        api_key: str | None = None,  # noqa: ARG002 - kept for API parity
    ) -> list[str]:
        """Build the argv list for ``python -m garak ...``.

        Uses the current ``--target_type`` / ``--target_name`` flags
        (the deprecated ``--model_type`` / ``--model_name`` aliases
        still work in garak but emit a deprecation notice).

        Note ``api_key`` is intentionally ignored here — secrets must
        be passed through the child process environment, not the
        command line. ``run_scan`` accepts an ``env_extra`` argument
        for that.

        Args:
            target_type: garak module (or ``module.Class``) for the
                target, e.g. ``"huggingface"`` or
                ``"rest.RestGenerator"``.
            target_name: model identifier, e.g. ``"gpt2"`` or
                ``"meta-llama/Meta-Llama-3-8B-Instruct"``. Ignored
                when empty (REST targets typically use ``--uri``).
            probes: garak probe identifiers to run. Empty / ``None``
                means "all probes" (no ``--probes`` flag emitted).

        Returns:
            The argv list ready to hand to ``subprocess.Popen``.
        """
        cmd: list[str] = [self.python_exe, "-m", "garak"]
        if target_type:
            cmd.extend(["--target_type", target_type.strip()])
        if target_name:
            cmd.extend(["--target_name", target_name.strip()])
        if probes:
            cleaned = [p.strip() for p in probes if p and p.strip()]
            if cleaned:
                cmd.extend(["--probes", ",".join(cleaned)])
        return cmd

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run_scan(
        self,
        command: list[str],
        *,
        env_extra: dict[str, str] | None = None,
        timeout: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    ) -> Generator[str, None, int]:
        """Run garak as a subprocess, yielding stdout lines as they arrive.

        The generator returns the subprocess exit code from
        ``StopIteration.value`` (so the caller can write
        ``rc = yield from runner.run_scan(...)`` if they want it).

        Args:
            command: argv list, as produced by ``build_command``.
            env_extra: extra environment variables for the child
                process. The expected use is supplying API keys
                (``{"OPENAI_API_KEY": "sk-..."}``) without putting
                them on the command line.
            timeout: hard cap on wall-clock seconds.

        Yields:
            One stdout line at a time (without trailing newline).
        """
        env = os.environ.copy()
        # Force unbuffered output so progress lines arrive promptly,
        # not in 4KB chunks at end-of-scan.
        env["PYTHONUNBUFFERED"] = "1"
        if env_extra:
            env.update(env_extra)

        logger.info(
            "GarakRunner.run_scan: spawning %s",
            # Don't log env_extra values — they may contain API keys.
            " ".join(command),
        )
        try:
            proc = subprocess.Popen(  # noqa: S603 - shell=False, argv list
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
                env=env,
            )
        except FileNotFoundError as exc:
            logger.warning("garak runner: command not found: %s", exc)
            yield f"ERROR: {exc}"
            return -1

        deadline = time.monotonic() + timeout
        try:
            assert proc.stdout is not None  # for the type-checker
            for line in proc.stdout:
                if time.monotonic() > deadline:
                    proc.kill()
                    yield f"ERROR: scan exceeded {timeout}s timeout — killed"
                    break
                yield line.rstrip("\n")
        finally:
            try:
                rc = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()
        logger.info("GarakRunner.run_scan: exit code %d", rc)
        return rc

    # ------------------------------------------------------------------
    # Report discovery + parsing
    # ------------------------------------------------------------------

    def get_latest_report(self) -> Path | None:
        """Return the path to the newest ``.report.jsonl`` produced by garak.

        Searches the per-user garak_runs directory recursively.
        Returns ``None`` when the directory does not exist yet or
        contains no reports.
        """
        runs_dir = self.get_garak_runs_dir()
        if not runs_dir.exists():
            logger.info("garak_runs dir does not exist: %s", runs_dir)
            return None
        reports = list(runs_dir.rglob("*.report.jsonl"))
        if not reports:
            logger.info("no .report.jsonl files found under %s", runs_dir)
            return None
        latest = max(reports, key=lambda p: p.stat().st_mtime)
        logger.info("get_latest_report: %s", latest)
        return latest

    def parse_report(self, report_path: Path) -> list:
        """Parse ``report_path`` via the project's ``GarakParser``.

        Returns a list of ``Finding`` objects ready to drop into the
        RemediAX pipeline. Local import so that this module is safe
        to import even before the ``src/`` path has been wired up.
        """
        # Local import so the runner module stays import-safe in
        # environments where the integration_bridge path is not on
        # sys.path yet (e.g. ad-hoc test runners).
        from integration_bridge import GarakParser  # type: ignore[import-not-found]

        return list(GarakParser(report_path).parse())


def garak_is_on_path() -> bool:
    """Module-level convenience: is the ``garak`` CLI script on PATH?

    Independent of ``GarakRunner.is_garak_installed`` — the latter
    checks ``python -m garak`` (preferred), this just checks for a
    bare ``garak`` script as installed by ``pip install garak``.
    """
    return shutil.which("garak") is not None
