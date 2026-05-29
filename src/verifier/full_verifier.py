"""v1.0 stub for the FULL verification mode.

The full verifier re-runs garak against the patched prompt to compute
real before/after attack success rates. That requires garak as a
subprocess dependency plus a per-probe garak run config, neither of
which is wired up in v1.0.

The v1.1 implementation plan is captured in the class docstring so a
future contributor has everything they need.
"""

from __future__ import annotations

import logging

from remediation_engine.models import RemediationResult

from verifier.models import VerificationResult

logger = logging.getLogger(__name__)


class FullVerifier:
    """v1.0 stub. v1.1 will subprocess garak against the patched prompt.

    Planned v1.1 algorithm (captured so the next implementer has the
    full picture):

    1. Validate ``garak_runner_path`` points to an executable garak
       binary (defaulting to whatever ``shutil.which("garak")`` finds).
    2. Build a garak run config that uses ``remediation_result.prompt_patch
       .patched_prompt`` as the system prompt, and runs ONLY the probe
       implicated by the finding's ``probe_name`` to keep the run cheap.
    3. Invoke garak via ``subprocess.run()`` with a short per-probe
       timeout; capture stdout/stderr for diagnostics on failure.
    4. Parse the resulting ``hitlog.jsonl`` using
       ``integration_bridge.parser.GarakParser``.
    5. Compute ``after_success_rate = new_hits / new_attempts`` for the
       targeted probe. The before-rate comes from the original finding's
       severity bucket midpoint (the same mapping ``QuickVerifier`` uses).
    6. Return a ``VerificationResult`` with ``mode=FULL`` and the real
       numbers, classifying status by improvement_percent thresholds
       (e.g., >80% → VERIFIED, 30-80% → PARTIAL, else FAILED).

    Until v1.1 lands, ``verify()`` raises ``NotImplementedError`` with
    the exact message the spec specifies so callers can detect the stub.
    """

    def verify(
        self,
        remediation_result: RemediationResult,
        garak_runner_path: str | None = None,
    ) -> VerificationResult:
        """Raise ``NotImplementedError`` (v1.0 stub).

        Args:
            remediation_result: The Phase 3 result that would be
                re-tested against garak.
            garak_runner_path: Path to a garak executable (will be
                consulted by the v1.1 implementation).

        Raises:
            NotImplementedError: Always, in v1.0.
        """
        logger.debug(
            "FullVerifier.verify called with garak_runner_path=%r; not implemented",
            garak_runner_path,
        )
        raise NotImplementedError(
            "FullVerifier requires garak integration via subprocess. "
            "Stub for v1.0 — implement in v1.1."
        )
