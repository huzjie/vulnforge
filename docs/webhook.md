# Webhook 配置

vulnforge 支持接收 GitHub / GitLab webhook，用 HMAC 签名校验请求真伪。

## 校验工具

```python
from vulnforge.webhook import verify_signature, parse_github_event

# payload: 原始请求体字节
# signature: X-Hub-Signature-256 头，形如 "sha256=..."
verify_signature(payload, signature, secret)  # bool

parse_github_event(event, payload)            # 提取仓库/分支/提交信息
```

## 配置

```yaml
webhook:
  enabled: true
  secret: "your-shared-secret"
  port: 8000
```

## GitHub 配置

1. 在仓库 Settings → Webhooks → Add webhook。
2. Payload URL 填 `https://your-host/webhook`。
3. Content type 选 `application/json`。
4. Secret 填与配置一致的密钥。
5. 选择事件（如 Pull requests、Pushes）。

GitHub 会在 `X-Hub-Signature-256` 头中附带 HMAC-SHA256 签名。

## 签名算法

```
signature = "sha256=" + HMAC_SHA256(secret, raw_payload_body)
```

校验使用 `hmac.compare_digest`（常数时间比较），防时序攻击。

## 事件解析

### pull_request

```python
parse_github_event("pull_request", payload)
# {"event": "pull_request", "repo": "acme/app", "action": "opened",
#  "number": 7, "branch": "feature/x", "base_branch": "main",
#  "commit": "abc123", "title": "..."}
```

### push

```python
parse_github_event("push", payload)
# {"event": "push", "repo": "acme/app", "branch": "main",
#  "ref": "refs/heads/main", "commit": "deadbeef", "commits": [...]}
```

无法识别的事件返回 `None`。

## 接收端示例

```python
from vulnforge.webhook import verify_signature, parse_github_event

def handle_webhook(headers, raw_body, secret):
    sig = headers.get("X-Hub-Signature-256", "")
    if not verify_signature(raw_body, sig, secret):
        return 401, {"error": "invalid signature"}
    event = parse_github_event(headers.get("X-GitHub-Event", ""), json.loads(raw_body))
    # 触发扫描/CI 等后续逻辑
    return 200, {"ok": True, "event": event}
```

## 安全建议

- 使用强随机密钥（>= 32 字节）。
- 通过环境变量注入密钥，勿硬编码到源码。
- 校验失败立即返回 401，不处理请求体。
- 使用 HTTPS 暴露接收端点。
