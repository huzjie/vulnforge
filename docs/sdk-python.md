# Python SDK 用法

vulnforge 本身即是一个 Python 库，所有能力通过 `vulnforge.*` 暴露。

## 安装

```bash
pip install vulnforge
# 或源码
pip install -e .
```

## 完整流程

```python
from vulnforge.config import load_config
from vulnforge.core.target import TargetCollector
from vulnforge.core.engine import ScanEngine
from vulnforge.report import write

config = load_config()
targets = TargetCollector().collect(["src"], config)
report = ScanEngine(config).scan(targets)

print(report.stats)
write(report, "json", "./results/report.json")
write(report, "sarif", "./results/report.sarif")
```

## 数据模型

```python
from vulnforge.models import Finding, Severity, Target, ScanReport

finding = Finding(
    rule_id="custom.rule",
    title="...",
    description="...",
    severity=Severity.HIGH,
    file_path="a.py",
    line=3,
    cwe="CWE-89",
)
```

## 单扫描器调用

```python
from vulnforge.models import Target
from vulnforge.scanners.static.scanner import StaticScanner

scanner = StaticScanner()
findings = scanner.scan([Target(path="a.py", kind="file")], config={})
```

## LLM Provider

```python
from vulnforge.llm import get_provider, list_providers

provider = get_provider("mock", {})
print(provider.complete("eval(user_input)"))
```

## CVSS

```python
from vulnforge.cvss.calculator import score_cvss31, severity_from_cvss
print(score_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))  # 9.8
print(severity_from_cvss(9.8))                              # critical
```

## Fuzz

```python
from vulnforge.fuzz import FuzzEngine

def target(data: bytes):
    if b"boom" in data:
        raise ValueError("crash")

crashes = FuzzEngine({"fuzz": {"max_iterations": 200}}).fuzz(
    target, seeds=[b"seed"], iterations=200
)
```

## 依赖扫描

```python
from vulnforge.models import Target
from vulnforge.scanners.dependency import DependencyScanner

findings = DependencyScanner().scan(
    [Target(path="requirements.txt", kind="file")],
    {"dependency": {"offline": True}},
)
```

## 报告渲染

```python
from vulnforge.report import render, write, summarize

text = render(report, "markdown")
summary = summarize(report)
write(report, "cyclonedx", "./sbom.json")
```

## 去重与排序

```python
from vulnforge.core.dedup import dedupe
from vulnforge.core.severity import sort_findings, filter_by_threshold

unique = dedupe(findings)
ordered = sort_findings(unique)
high_and_up = filter_by_threshold(ordered, "high")
```

## 异常

```python
from vulnforge.errors import ConfigError, ScannerError, ProviderError, ReportError
```

## 完整示例

- `examples/run_scan.py`：端到端扫描
- `examples/custom_rule.py`：自定义规则
- `examples/scan_repo.py`：扫描 git 仓库
