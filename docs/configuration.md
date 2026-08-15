# 配置说明（config.yaml 全字段）

vulnforge 使用 YAML 配置。未提供配置文件时，自动回退到内置默认值并运行在**离线 mock 模式**。

## 配置加载与优先级

`load_config()` 按以下优先级（高者后应用，覆盖低者）：

1. 内置 `DEFAULT_CONFIG`（mock 默认值）
2. 包内 `config.example.yaml`（若存在）
3. 当前目录 `./config.yaml`（若存在）
4. 显式传入的 `path` 参数

合并方式为**深度合并**（dict 递归合并、标量覆盖、不修改原对象）。

```python
from vulnforge.config import load_config
config = load_config()            # 默认
config = load_config("custom.yaml")  # 指定文件
```

## 全字段说明

### `general` — 通用

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `mode` | str | `mock` | 运行模式：`mock` / `live` |
| `concurrency` | int | `8` | 并行文件扫描 worker 数 |
| `timeout_seconds` | int | `120` | 单目标扫描超时（秒） |
| `output_dir` | str | `./results` | 报告输出目录 |
| `default_formats` | list | `[json, markdown, html, sarif]` | 默认输出格式 |
| `fail_on` | str | `critical` | 达到该严重度即判定失败：`none/low/medium/high/critical` |

### `targets` — 目标发现

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `default_extensions` | list | `[.py,.js,...]` | 参与扫描的文件扩展名 |

### `scanners` — 扫描器开关

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `static` | bool | `true` | 规则式静态分析 |
| `llm` | bool | `true` | LLM 辅助漏洞推理 |
| `fuzz` | bool | `true` | 轻量模糊测试（需配置 fuzz targets） |
| `dependency` | bool | `true` | SBOM + 依赖 CVE 查询 |
| `secrets` | bool | `true` | 硬编码密钥检测（含于 static 规则） |

### `static` — 静态规则配置

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `min_severity` | str | `low` | 最低报告严重度 |
| `max_line_length` | int | `160` | 单行最大长度（质量规则） |
| `max_function_complexity` | int | `20` | 函数最大圈复杂度（质量规则） |
| `banned_imports` | list | `[pickle, subprocess, eval, exec, yaml.load]` | 禁用导入列表 |

### `llm` — LLM 配置

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `default_provider` | str | `mock` | 默认 provider 名称 |
| `max_tokens` | int | `2048` | 单次调用最大 token |
| `temperature` | float | `0.0` | 采样温度（0 = 确定性） |
| `chunk_lines` | int | `400` | 代码切块行数 |
| `providers.<name>` | map | 见下 | 各 provider 的扁平配置 |

`providers` 子项通用字段：

| 字段 | 说明 |
| --- | --- |
| `type` | provider 类型：`mock` / `openai_compat` / `anthropic` / `gemini` / `ollama` |
| `base_url` | OpenAI 兼容端点 |
| `api_key` | API Key（留空则读环境变量） |
| `model` | 模型名 |

### `fuzz` — 模糊测试

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `max_iterations` | int | `5000` | 最大迭代次数 |
| `max_runtime_seconds` | int | `30` | 总时长上限（秒） |
| `corpus_dir` | str | `./.corpus` | 语料目录 |
| `crash_dir` | str | `./.crash` | 崩溃样本目录 |
| `seed` | int | `0` | 随机种子（可复现） |
| `targets` | list | `[]` | fuzz 目标（`{type, value, ...}`） |
| `seeds` | list | `[]` | 附加种子 |

### `dependency` — 依赖/SBOM

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `ecosystem` | str | `auto` | 依赖生态：`auto/pypi/npm/maven/cargo/go` |
| `osv_endpoint` | str | `https://api.osv.dev/v1/query` | OSV API 端点 |
| `offline` | bool | `true` | `true` 时跳过网络，仅本地缓存 |

### `webhook` — Webhook

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | 是否启用 webhook 接收 |
| `secret` | str | `` | HMAC 共享密钥 |
| `port` | int | `8000` | 监听端口 |

### `api` — 控制面

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `host` | str | `127.0.0.1` | 监听地址 |
| `port` | int | `8000` | 监听端口 |
| `auth_token` | str | `` | Bearer Token（空 = 无鉴权） |
| `cors_origins` | list | `["*"]` | CORS 允许来源 |

## 完整示例

见仓库根目录 `config.example.yaml`，或 `examples/config.mock.yaml`（纯 mock）。

## 环境变量

LLM provider 的 `api_key` 留空时，会按顺序读取：

```
OPENAI_API_KEY → GLM_API_KEY → DEEPSEEK_API_KEY → QWEN_API_KEY
→ ANTHROPIC_API_KEY → GEMINI_API_KEY
```

## 常见配置

### 只跑静态扫描

```yaml
scanners:
  static: true
  llm: false
  fuzz: false
  dependency: false
  secrets: true
```

### 接入 GLM-5.3

```yaml
llm:
  default_provider: glm
  providers:
    glm:
      type: openai_compat
      base_url: https://open.bigmodel.cn/api/paas/v4
      model: glm-5.3
```

然后：

```bash
export GLM_API_KEY=your-key
vulnforge scan src/
```
