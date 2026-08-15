"""Self-contained HTML report renderer.

Produces a single HTML document (no external assets) with a dark theme,
severity-coloured stat cards, a findings table and code snippets.
"""

import html
from typing import Any, List

from .summary import SEVERITY_ORDER, severity_name, summarize

# Severity -> (colour, background) for badges / cards.
_SEVERITY_COLORS = {
    "CRITICAL": ("#ff4d6d", "#3a0d16"),
    "HIGH": ("#ff9f43", "#33200a"),
    "MEDIUM": ("#ffd166", "#332b0a"),
    "LOW": ("#4d9fff", "#0a1a33"),
    "INFO": ("#8a93a6", "#141a24"),
}


def _esc(text: Any) -> str:
    return html.escape("" if text is None else str(text))


def render(report) -> str:
    """Render ``report`` as a self-contained HTML string."""
    findings = list(getattr(report, "findings", []) or [])
    stats = summarize(report)
    counts = stats["severity_counts"]

    cards = "".join(_stat_card(name, counts.get(name, 0)) for name in SEVERITY_ORDER)
    table_rows = "".join(_table_row(f) for f in findings)

    top_rules = "".join(
        f"<li>{_esc(r['rule_id'])} <span class='muted'>× {r['count']}</span></li>"
        for r in stats.get("top_rules", [])[:10]
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vulnforge 安全扫描报告</title>
<style>
  :root {{
    --bg: #0f1117; --panel: #161923; --border: #262b3a; --text: #e6e8ee;
    --muted: #8a93a6; --accent: #4d9fff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
    line-height: 1.6;
  }}
  .wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }}
  h1 {{ font-size: 26px; margin: 0 0 4px; }}
  .sub {{ color: var(--muted); font-size: 14px; margin-bottom: 24px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }}
  .card {{
    flex: 1 1 130px; background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 16px; border-left: 4px solid var(--accent);
  }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .label {{ color: var(--muted); font-size: 13px; }}
  h2 {{ font-size: 18px; margin: 28px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
  pre {{
    background: #0a0c12; border: 1px solid var(--border); border-radius: 6px;
    padding: 10px; overflow-x: auto; font-size: 12.5px; margin: 4px 0;
    color: #c9d1d9;
  }}
  code {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }}
  .muted {{ color: var(--muted); }}
  ul {{ margin: 6px 0; padding-left: 20px; }}
</style>
</head>
<body>
<div class="wrap">
  <!-- 标题与统计卡片 -->
  <h1>vulnforge 安全扫描报告</h1>
  <div class="sub">共发现 {stats['total']} 个问题</div>
  <div class="cards">{cards}</div>

  <!-- Top 规则 -->
  <h2>Top 规则</h2>
  <ul>{top_rules or '<li class="muted">无</li>'}</ul>

  <!-- 漏洞明细表 -->
  <h2>漏洞明细</h2>
  <table>
    <thead>
      <tr><th>严重度</th><th>规则</th><th>标题</th><th>位置</th><th>描述 / 代码</th></tr>
    </thead>
    <tbody>{table_rows or '<tr><td colspan="5" class="muted">未发现漏洞</td></tr>'}</tbody>
  </table>
</div>
</body>
</html>
"""


def _stat_card(name: str, count: int) -> str:
    color, bg = _SEVERITY_COLORS.get(name, ("#8a93a6", "#141a24"))
    return (
        f'<div class="card" style="border-left-color:{color}; background:{bg};">'
        f'<div class="num" style="color:{color};">{count}</div>'
        f'<div class="label">{name}</div></div>'
    )


def _table_row(f) -> str:
    name = severity_name(f)
    color, _ = _SEVERITY_COLORS.get(name, ("#8a93a6", "#141a24"))
    badge = f'<span class="badge" style="color:{color}; background:#0a0c12;">{_esc(name)}</span>'
    rule = _esc(getattr(f, "rule_id", ""))
    title = _esc(getattr(f, "title", ""))
    location = f"{_esc(getattr(f, 'file_path', ''))}:{getattr(f, 'line', 0)}"
    cwe = _esc(getattr(f, "cwe", "") or "")

    desc = _esc(getattr(f, "description", "") or "")
    code = _esc(getattr(f, "code", "") or "")
    snippet = f"<pre><code>{code}</code></pre>" if code else ""

    extra = ""
    if cwe:
        extra += f"<div class='muted'>CWE: {cwe}</div>"

    recommendation = _esc(getattr(f, "recommendation", "") or "")
    if recommendation:
        extra += f"<div class='muted'>建议: {recommendation}</div>"

    return (
        f"<tr><td>{badge}</td><td><code>{rule}</code></td><td>{title}</td>"
        f"<td><code>{location}</code></td>"
        f"<td>{desc}{snippet}{extra}</td></tr>"
    )
