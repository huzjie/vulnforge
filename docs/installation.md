# 安装

vulnforge 支持多种安装方式：`pip`、源码安装、Docker。核心包（mock 模式）**零第三方依赖**，仅需 Python 标准库。

## 环境要求

| 项 | 要求 |
| --- | --- |
| Python | >= 3.9（推荐 3.11+） |
| 操作系统 | Linux / macOS / Windows |
| 网络 | mock 模式不需要；接入 LLM 需能访问对应 API 端点 |
| 磁盘 | 源码安装约 10 MB |

## 方式一：pip 安装（推荐）

```bash
pip install -e .
```

> 这是可编辑安装，适合开发与本地使用。

## 方式二：源码安装

```bash
git clone https://github.com/huzjie/vulnforge.git
cd vulnforge
python -m pip install .
```

## 方式三：安装完整依赖（含 Web 控制台 / API）

```bash
# 完整功能：FastAPI + uvicorn + httpx + PyYAML
pip install -e ".[full]"

# 仅 Web 控制台
pip install -e ".[web]"

# 仅测试
pip install -e ".[test]"
```

## 方式四：Docker

```bash
# 使用 CLI 镜像
docker build -f docker/Dockerfile -t vulnforge .

# 使用 Web 控制台镜像
docker build -f docker/Dockerfile.web -t vulnforge-web .
```

或者用 `docker-compose.yml`：

```bash
docker compose up -d
```

详见 [deployment.md](deployment.md)。

## 验证安装

```bash
vulnforge version
# 1.0.0

python -c "import vulnforge; print(vulnforge.__version__)"
# 1.0.0
```

## 目录结构（安装后）

```
vulnforge/
├── _version.py            # 版本号
├── models.py              # Finding / Severity / Target / ScanReport
├── config.py              # 配置加载（内置 YAML 解析 + 深度合并）
├── cwe.py                 # CWE 查询表
├── errors.py              # 异常层级
├── logging.py             # 日志工具
├── core/
│   ├── engine.py          # ScanEngine 编排引擎
│   ├── target.py          # TargetCollector 目标发现
│   ├── dedup.py           # finding 去重
│   ├── severity.py        # 严重度排序/过滤
│   └── scheduler.py       # 并行调度
├── scanners/
│   ├── registry.py        # 扫描器注册表
│   ├── base.py            # BaseScanner 抽象基类
│   ├── static/            # 静态规则扫描器 + 规则库
│   ├── llm.py             # LLM 推理扫描器
│   ├── fuzz.py            # Fuzz 扫描器
│   └── dependency.py      # 依赖/SBOM 扫描器
├── llm/                   # LLM provider（mock/openai_compat/anthropic/gemini/ollama）
├── fuzz/                  # 模糊测试引擎（corpus/mutator/crash/sanitizers）
├── cvss/                  # CVSS 3.1 评分
├── report/                # 报告渲染（json/markdown/html/sarif/cyclonedx）
├── db/                    # 内置 CVE 库 + OSV 客户端 + 缓存
├── cli/                   # CLI 入口与子命令
└── webhook.py             # Webhook HMAC 签名校验
```

## 升级与卸载

```bash
pip install --upgrade .
pip uninstall vulnforge
```

## 常见安装问题

| 问题 | 解决 |
| --- | --- |
| `ModuleNotFoundError: vulnforge` | 确认在项目根目录执行 `pip install -e .`，或把仓库根加入 `PYTHONPATH`。 |
| `uvicorn` 缺失（启动 serve 时报错） | 执行 `pip install -e ".[full]"`。 |
| Windows 下 `python -m vulnforge` 无反应 | 使用 `python -m vulnforge` 或直接 `vulnforge` 命令；确认安装了 `[project.scripts]` 入口。 |
