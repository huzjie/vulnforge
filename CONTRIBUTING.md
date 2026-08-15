# 贡献指南（CONTRIBUTING）

感谢你对 vulnforge 的关注！本指南说明如何搭建环境、遵守代码规范、提交变更与运行测试。

## 行为准则

请遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

## 环境搭建

```bash
# 1. 克隆仓库
git clone https://github.com/huzjie/vulnforge.git
cd vulnforge

# 2. 创建虚拟环境（可选但推荐）
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. 安装（含测试依赖）
pip install -e ".[test]"

# 4. 完整功能依赖（可选）
pip install -e ".[full]"
```

## 目录约定

- 核心代码：`vulnforge/`
- 测试：`tests/`（与包同名 `test_*.py`）
- 文档：`docs/`（中文为主）
- 示例：`examples/`

## 代码规范

### 通用

- Python 3.9+ 语法，使用 `from __future__ import annotations`。
- 遵循 PEP 8，行宽 88（与 black 一致）。
- 核心模块（mock 模式）**只依赖标准库**；可选功能依赖放在 `[full]`/`[web]` 分组。
- 公开 API 需有 docstring；命名清晰。

### 数据模型契约

`vulnforge/models.py` 的字段名与签名是**稳定公开契约**，不得随意修改：

- `Finding`：`rule_id, title, description, severity, file_path, line, column, code, cwe, cvss, confidence, scanner, recommendation, references, tags, raw`
- `Severity`：`INFO/LOW/MEDIUM/HIGH/CRITICAL`（值 `info/low/medium/high/critical`）
- `Target`：`path, kind, language, size`
- `ScanReport`：`scan_id, created_at, targets, findings, stats, config`

### 提交规范（Conventional Commits）

提交信息遵循 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>(<scope>): <subject>

[body]

[footer]
```

| type | 说明 |
| --- | --- |
| `feat` | 新功能 |
| `fix` | 缺陷修复 |
| `docs` | 文档 |
| `test` | 测试 |
| `refactor` | 重构（不改变行为） |
| `perf` | 性能优化 |
| `chore` | 构建/工具/杂项 |
| `style` | 格式（不影响逻辑） |

示例：

```
feat(scanners): 新增 SQL 注入 f-string 规则
fix(cvss): 修正 Scope=Changed 时的 PR 权重
docs(static-rules): 补充规则 id 速查表
```

## 测试

```bash
# 全部测试（离线可跑）
pytest tests/ -q

# 单文件
pytest tests/test_cvss.py -q

# 覆盖率
pytest tests/ --cov=vulnforge --cov-report=term-missing
```

测试要求：

- 全部**离线可跑**，禁止真实网络调用。
- 真实断言，禁止 `pass` / 空测试。
- 使用 `pytest` fixture（`tmp_path` 等），不写死绝对路径。
- 新增功能必须补充对应测试。

## 提交流程

1. Fork 仓库并创建特性分支：

```bash
git checkout -b feat/my-feature
```

2. 开发 + 测试通过。
3. 提交（遵循 Conventional Commits）。
4. 推送到你的 Fork，发起 Pull Request。
5. CI 通过、维护者 review 后合入。

## 代码评审要点

- 是否保持核心零依赖？
- 是否破坏 `models.py` 契约？
- 是否有离线可跑的测试覆盖？
- 文档是否同步更新？
- 是否存在安全风险（如命令注入、未转义输出）？

## 报告问题

- Bug 或特性请求：提交 [Issue](https://github.com/huzjie/vulnforge/issues)。
- 安全漏洞：见 [SECURITY.md](SECURITY.md)，请勿公开披露。
