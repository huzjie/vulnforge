"""End-to-end Python API example: collect targets -> scan -> write reports.

Runs entirely offline in ``mock`` mode (no API key / network required)::

    python examples/run_scan.py examples/vulnerable
"""
from __future__ import annotations

import sys
from pathlib import Path

from vulnforge.config import load_config
from vulnforge.core.engine import ScanEngine
from vulnforge.core.target import TargetCollector
from vulnforge.report import write


def main(argv: list[str]) -> int:
    # 1. Load configuration (falls back to offline mock defaults).
    config = load_config()

    # 2. Determine scan paths (a directory of vulnerable samples by default).
    paths = argv[1:] or ["examples/vulnerable"]
    if not paths:
        paths = ["."]

    # 3. Collect scan targets from the paths.
    collector = TargetCollector()
    targets = collector.collect(paths, config)
    if not targets:
        print("No targets found under:", paths, file=sys.stderr)
        return 1
    print(f"Collected {len(targets)} target(s).")

    # 4. Run the scan engine over the targets.
    engine = ScanEngine(config)
    report = engine.scan(targets)

    # 5. Print a summary and write reports to disk.
    stats = report.stats
    print(f"Scan '{report.scan_id}' finished in {stats.get('duration_ms', 0)} ms.")
    print(f"Findings: {stats.get('total', 0)} "
          f"(critical={stats.get('critical', 0)}, high={stats.get('high', 0)}, "
          f"medium={stats.get('medium', 0)}, low={stats.get('low', 0)})")

    output_dir = Path(config["general"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    for fmt in ("json", "markdown"):
        out_path = output_dir / f"report.{fmt}"
        write(report, fmt, str(out_path))
        print(f"Wrote {fmt} report -> {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
