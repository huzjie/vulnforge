# vulnforge-sdk (Python)

与 vulnforge API 控制面交互的轻量 Python 客户端。**零第三方依赖**（基于标准库
`urllib`），也提供可选的 `requests` extra。

## 安装

```bash
pip install ./sdk/python
# 或开发模式
pip install -e ./sdk/python
```

## 用法

```python
from vulnforge_sdk import VulnforgeClient

with VulnforgeClient("http://127.0.0.1:8000", token="your-token") as client:
    # 健康检查
    print(client.health())

    # 发起扫描
    resp = client.scan(["./src"])
    print(resp.scan_id, resp.status)

    # 轮询扫描结果
    result = client.get_scan(resp.scan_id)
    print(result.status, result.findings_count)

    # 查询 findings
    data = client.findings(scan_id=resp.scan_id, severity="high")
    print(data["total"], data["items"])

    # 导出报告
    markdown = client.reports(resp.scan_id, "markdown")
    print(markdown)
```

## 异常

所有 API 错误统一抛出 `vulnforge_sdk.VulnforgeAPIError`，可通过 `status_code`
与 `body` 获取详情。
