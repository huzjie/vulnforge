# CI 集成

将 vulnforge 接入 CI/CD，在每次提交/PR 时自动做安全扫描。

## GitHub Actions

### 基础工作流

`.github/workflows/security.yml`：

```yaml
name: vulnforge scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install vulnforge
        run: pip install -e .
      - name: Run scan
        run: vulnforge scan . --format sarif -o ./results
      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results
```

### 按严重度门禁

```yaml
      - name: Gate on severity
        run: vulnforge scan . --severity high --format json -o ./results
        # 结合 fail_on 语义在脚本里判定
```

## CodeQL 对比与互补

| 维度 | CodeQL | vulnforge |
| --- | --- | --- |
| 分析方式 | 语义数据流查询 | 正则规则 + LLM 推理 |
| 语言覆盖 | 广泛 | 多语言（规则驱动） |
| AI 推理 | 无 | 支持 LLM |
| 离线 | 需依赖 | mock 完全离线 |

两者可并存：CodeQL 做深度数据流，vulnforge 做快速规则 + AI 发现。

## GitLab CI

`.gitlab-ci.yml`：

```yaml
security_scan:
  image: python:3.12
  script:
    - pip install -e .
    - vulnforge scan . --format sarif -o ./results
    - vulnforge scan . --format json -o ./results
  artifacts:
    paths:
      - results/
    reports:
      sast: results/*.sarif
```

## Jenkins / 其它

任何 CI 只需三步：

```bash
pip install -e .
vulnforge scan src/ --format sarif --format json -o results/
# 后续上传/门禁
```

## 门禁脚本示例

```bash
#!/usr/bin/env bash
set -euo pipefail

vulnforge scan src/ --format json -o results/ --severity critical

# 解析 JSON，若存在 critical 则失败
python - <<'PY'
import json, glob, sys
for p in glob.glob("results/*.json"):
    doc = json.load(open(p))
    total = doc["stats"]["total"]
    critical = doc["stats"]["severity_counts"].get("CRITICAL", 0)
    print(f"{p}: total={total} critical={critical}")
    if critical:
        sys.exit(1)
PY
```

## 建议

- 在 **PR** 上跑：反馈快，聚焦增量风险。
- 生成 **SARIF**：无缝接入 GitHub Code Scanning。
- mock 模式适合 CI 基线；接入 LLM 可提升发现能力（注意密钥走 Secrets）。
- 将 `--severity high` 用于门禁，避免低危噪声阻断合入。
