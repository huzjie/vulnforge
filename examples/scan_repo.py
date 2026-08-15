"""Scan a local git repository.

Demonstrates how to point vulnforge at a checked-out repository (or a remote
URL cloned on the fly) and emit a full report.  By default it scans the current
working tree in mock mode.
"""
from __future__ import annotations

import sys
import subprocess
import tempfile
from pathlib import Path

from vulnforge.config import load_config
from vulnforge.core.engine import ScanEngine
from vulnforge.core.target import TargetCollector
from vulnforge.report import write


def clone(url: str, dest: Path) -> None:
    """Clone a repository into ``dest`` (shallow, single branch)."""
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
    )


def main(argv: list[str]) -> int:
    config = load_config()

    repo = argv[1] if len(argv) > 1 else None
    tmpdir = None

    if repo and (repo.startswith("http://") or repo.startswith("https://")
                 or repo.startswith("git@")):
        tmpdir = tempfile.mkdtemp(prefix="vulnforge-repo-")
        print(f"Cloning {repo} -> {tmpdir}")
        clone(repo, Path(tmpdir))
        scan_root = tmpdir
    else:
        scan_root = repo or "."

    try:
        collector = TargetCollector()
        targets = collector.collect([scan_root], config)
        print(f"Collected {len(targets)} target(s) from '{scan_root}'.")

        engine = ScanEngine(config)
        report = engine.scan(targets)

        stats = report.stats
        print(f"Findings: {stats.get('total', 0)} "
              f"(critical={stats.get('critical', 0)}, high={stats.get('high', 0)}, "
              f"medium={stats.get('medium', 0)}, low={stats.get('low', 0)})")

        output_dir = Path(config["general"]["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        write(report, "json", str(output_dir / "repo-report.json"))
        write(report, "sarif", str(output_dir / "repo-report.sarif"))
        print(f"Wrote reports to {output_dir}")
        return 0
    finally:
        if tmpdir is not None:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
