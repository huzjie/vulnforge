"""Lightweight fuzzing scanner.

Drives :class:`vulnforge.fuzz.engine.FuzzEngine` against executable targets
(Python callables or CLI commands) declared in ``config["fuzz"]["targets"]``,
and converts any discovered crash into a :class:`Finding`.  No-op when fuzzing
is disabled or no targets are configured.
"""

import importlib
import logging
import os
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from vulnforge.fuzz.engine import FuzzEngine
from vulnforge.models import Finding, Severity
from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.registry import register

logger = logging.getLogger(__name__)

_DEFAULT_SEEDS: List[bytes] = [b"", b"A", b"0", b"hello", b"<script>alert(1)</script>"]

_CRASH_SEVERITY = {
    "timeout": Severity.MEDIUM,
    "assertion": Severity.MEDIUM,
    "out-of-bounds": Severity.HIGH,
    "stack-overflow": Severity.HIGH,
    "exception": Severity.HIGH,
    "unknown": Severity.HIGH,
}


def _resolve_python_function(spec: str) -> Callable[[bytes], None]:
    """Resolve ``"package.module:function_name"`` into a callable."""
    if ":" not in spec:
        raise ValueError(f"python_function spec must be 'module:function': {spec!r}")
    module_name, func_name = spec.rsplit(":", 1)
    module = importlib.import_module(module_name)
    func = getattr(module, func_name)
    if not callable(func):
        raise TypeError(f"{spec!r} is not callable")
    return func


def _make_cli_runner(command: str, timeout: Optional[float]) -> Callable[[bytes], None]:
    """Wrap a CLI command into a callable that fails on non-zero exit codes.

    The ``@@`` placeholder in ``command`` is replaced by a temp file holding the
    fuzzed input; if absent, input is piped via stdin.
    """
    def runner(data: bytes) -> None:
        use_placeholder = "@@" in command
        if use_placeholder:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(data)
                tmp_path = tf.name
            try:
                cmd = command.replace("@@", tmp_path)
                proc = subprocess.run(
                    cmd, shell=True, capture_output=True,
                    timeout=timeout or 60,
                )
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        else:
            proc = subprocess.run(
                command, shell=True, input=data, capture_output=True,
                timeout=timeout or 60,
            )
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace")[:2000]
            raise RuntimeError(f"exit code {proc.returncode}: {stderr}")

    return runner


def _resolve_target(spec: Dict[str, Any]) -> Tuple[str, Callable[[bytes], None]]:
    """Return ``(name, callable)`` from a fuzz target spec."""
    name = spec.get("name") or spec.get("value") or "target"
    target_type = spec.get("type") or "python_function"
    value = spec.get("value") or spec.get("function") or spec.get("command") or ""
    if not value:
        raise ValueError(f"fuzz target {name!r} missing value")

    if target_type == "python_function":
        return name, _resolve_python_function(value)
    if target_type == "cli":
        return name, _make_cli_runner(value, spec.get("timeout"))
    raise ValueError(f"unsupported fuzz target type: {target_type!r}")


@register
class FuzzScanner(BaseScanner):
    """Run lightweight fuzzing against configured executable targets."""

    name = "fuzz"

    def scan(self, targets, config: Dict[str, Any]) -> List[Finding]:
        scanners_cfg: Dict[str, Any] = config.get("scanners", {}) or {}
        fuzz_cfg: Dict[str, Any] = config.get("fuzz", {}) or {}

        if not scanners_cfg.get("fuzz", False):
            return []

        target_specs: List[Any] = fuzz_cfg.get("targets", []) or []
        # Backward-friendly: allow a list of "module:func" strings.
        for fn_spec in fuzz_cfg.get("functions", []) or []:
            target_specs.append({"type": "python_function", "value": fn_spec})

        if not target_specs:
            return []

        seeds = self._collect_seeds(fuzz_cfg)
        engine = FuzzEngine(config)
        findings: List[Finding] = []

        for spec in target_specs:
            try:
                name, callable_target = _resolve_target(spec)
            except Exception as exc:
                logger.warning("Fuzz scanner: cannot resolve target %r: %s", spec, exc)
                continue

            iterations = spec.get("iterations")
            try:
                crashes = engine.fuzz(callable_target, seeds, iterations=iterations)
            except Exception as exc:  # FuzzTimeoutError etc.
                logger.warning("Fuzz scanner: fuzzing %s aborted: %s", name, exc)
                crashes = engine.collector.list()

            for crash in crashes:
                findings.append(self._crash_to_finding(name, crash))

        try:
            engine.collector.save()
        except OSError as exc:
            logger.warning("Fuzz scanner: cannot persist crashes: %s", exc)

        return findings

    @staticmethod
    def _collect_seeds(fuzz_cfg: Dict[str, Any]) -> List[bytes]:
        seeds: List[bytes] = list(_DEFAULT_SEEDS)
        for raw in fuzz_cfg.get("seeds", []) or []:
            if isinstance(raw, bytes):
                seeds.append(raw)
            elif isinstance(raw, str):
                seeds.append(raw.encode("utf-8", errors="replace"))
        return seeds

    @staticmethod
    def _crash_to_finding(target_name: str, crash) -> Finding:
        severity = _CRASH_SEVERITY.get(crash.crash_type, Severity.HIGH)
        return Finding(
            rule_id=f"fuzz.crash.{crash.crash_type}",
            title=f"Fuzz crash ({crash.crash_type}) in {target_name}",
            description=(
                f"Fuzzing target '{target_name}' crashed with {crash.exc_type}: "
                f"{crash.message}"
            ),
            severity=severity,
            file_path=target_name,
            line=0,
            column=0,
            code=crash.input_bytes[:256].decode("utf-8", errors="replace"),
            cwe="CWE-20",
            cvss=None,
            confidence=1.0,
            scanner="fuzz",
            recommendation=(
                "加固输入校验与边界处理；复现崩溃输入并修复根因。"
            ),
            references=[],
            tags=["fuzz", crash.crash_type],
            raw=crash.to_dict(),
        )
