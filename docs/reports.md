# 报告格式

vulnforge 支持 5 种报告格式，通过统一接口 `render` / `write` 输出。

## 格式一览

| 格式 | 别名 | 说明 |
| --- | --- | --- |
| `json` | — | 结构化 JSON（meta + stats + findings） |
| `markdown` | `md` | 人类可读 Markdown |
| `html` | `htm` | HTML 报告 |
| `sarif` | — | SARIF 2.1.0（可上传 GitHub Code Scanning） |
| `cyclonedx` | `sbom` | CycloneDX 1.5 SBOM |

## API

```python
from vulnforge.report import render, write, summarize

text = render(report, "json")     # 返回字符串
path = write(report, "sarif", "./out/report.sarif")  # 渲染并写盘，返回路径
summary = summarize(report)       # 汇总字典
```

不支持的格式抛 `ReportError`。

## JSON 格式

```json
{
  "meta": { "config": {...}, "version": "1.0.0" },
  "stats": {
    "total": 12,
    "severity_counts": {"CRITICAL": 2, "HIGH": 5, ...},
    "top_rules": [...],
    "top_files": [...],
    "top_cwe": [...],
    "by_scanner": [...],
    "remediation_priority": [...]
  },
  "findings": [
    {"rule_id": "sql-query-concat", "severity": "MEDIUM", "file_path": "...", ...}
  ]
}
```

## Markdown 格式

结构：标题 → 概览表 → 修复优先级 → Top 规则/文件/CWE → 按严重度分组列出 finding。

## SARIF 格式

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "vulnforge", "rules": [...]}},
    "results": [{"ruleId": "sql-query-concat", "level": "warning", ...}]
  }]
}
```

严重度 → SARIF level 映射：

| 严重度 | level |
| --- | --- |
| CRITICAL / HIGH | `error` |
| MEDIUM | `warning` |
| LOW / INFO | `note` |

### 接入 GitHub Code Scanning

1. 生成 SARIF：

```bash
vulnforge scan src/ --format sarif -o ./results
```

2. 上传（GitHub Actions）：

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results
```

详见 [ci-integration.md](ci-integration.md)。

## CycloneDX SBOM

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "components": [
    {"type": "library", "name": "requests", "version": "2.31.0",
     "purl": "pkg:pypi/requests@2.31.0"}
  ]
}
```

组件来自带 `sbom` 标签的依赖 finding（`raw` 中的 package/version/purl）。

## CLI 生成报告

```bash
vulnforge scan src/ --format json --format sarif --format markdown
vulnforge report results/scan.json --format html -o report.html
vulnforge sbom . -o sbom.json
```

## 输出目录

默认 `./results/`，可用 `-o` 或 `general.output_dir` 修改。
