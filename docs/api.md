# REST API 参考

vulnforge 提供 FastAPI 控制面，通过 `vulnforge serve` 启动。

## 启动

```bash
pip install -e ".[full]"
vulnforge serve --host 127.0.0.1 --port 8000
```

应用工厂：

```python
from vulnforge.api import create_app
app = create_app(config_dict)
```

## 鉴权

`config["api"]["auth_token"]` 非空时，需在请求头携带：

```
Authorization: Bearer <auth_token>
```

## 端点总览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康检查 |
| GET | `/api/v1/version` | 版本信息 |
| POST | `/api/v1/scan` | 提交扫描任务 |
| GET | `/api/v1/scan/{scan_id}` | 查询扫描结果 |
| GET | `/api/v1/findings` | 查询 finding 列表（支持过滤） |
| GET | `/api/v1/rules` | 列出静态规则 |
| GET | `/api/v1/providers` | 列出 LLM provider |
| GET | `/api/v1/scanners` | 列出扫描器 |
| POST | `/api/v1/sbom` | 生成 SBOM |
| POST | `/webhook` | 接收 GitHub/GitLab webhook |

## 详细示例

### GET /health

```json
{"status": "ok", "version": "1.0.0"}
```

### POST /api/v1/scan

请求体：

```json
{"paths": ["src/"], "config": {}, "formats": ["json", "sarif"]}
```

响应：

```json
{
  "scan_id": "a1b2c3...",
  "status": "completed",
  "stats": {"total": 12, "critical": 2, "high": 5, "...": "..."},
  "report": {...}
}
```

### GET /api/v1/scan/{scan_id}

返回该次扫描的 `ScanReport`（JSON）。

### GET /api/v1/findings

查询参数：

| 参数 | 说明 |
| --- | --- |
| `severity` | 按严重度过滤 |
| `cwe` | 按 CWE 过滤 |
| `scanner` | 按扫描器过滤 |
| `file` | 按文件路径过滤 |
| `limit` | 返回条数上限 |

响应：

```json
{"total": 3, "findings": [...]}
```

### POST /api/v1/sbom

请求体：`{"paths": ["."], "ecosystem": "auto"}`

响应：CycloneDX 1.5 JSON。

### POST /webhook

接收 GitHub/GitLab webhook，用 `config["webhook"]["secret"]` 校验 HMAC-SHA256（头 `X-Hub-Signature-256`）。校验失败返回 401。

详见 [webhook.md](webhook.md)。

## 错误码

| 码 | 含义 |
| --- | --- |
| 400 | 请求参数错误 |
| 401 | 鉴权失败 / 签名校验失败 |
| 404 | 资源不存在 |
| 500 | 内部错误 |

## 编程访问

```python
from vulnforge.api import create_app
from vulnforge.config import load_config

app = create_app(load_config())
```

配合 `uvicorn` 运行：

```bash
uvicorn "vulnforge.api:create_app" --factory --host 0.0.0.0 --port 8000
```

> 说明：REST API 属可选功能，依赖 `fastapi` + `uvicorn`（`pip install -e ".[full]"`）。核心扫描能力不依赖 API。
