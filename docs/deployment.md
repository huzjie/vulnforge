# 部署

vulnforge 支持 Docker、Kubernetes（Helm）等多种部署方式。

## Docker

### CLI 镜像

`docker/Dockerfile`：

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install .
ENTRYPOINT ["vulnforge"]
```

构建与使用：

```bash
docker build -f docker/Dockerfile -t vulnforge .
docker run --rm -v "$PWD:/src" vulnforge scan /src
```

### Web 控制台镜像

`docker/Dockerfile.web`：包含 FastAPI + uvicorn + 前端静态资源。

```bash
docker build -f docker/Dockerfile.web -t vulnforge-web .
docker run --rm -p 8000:8000 vulnforge-web
```

### docker-compose

`docker-compose.yml`：

```bash
docker compose up -d
```

## Kubernetes

### Deployment 示例

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnforge
spec:
  replicas: 2
  selector:
    matchLabels: { app: vulnforge }
  template:
    metadata:
      labels: { app: vulnforge }
    spec:
      containers:
        - name: vulnforge
          image: vulnforge:latest
          ports:
            - containerPort: 8000
          env:
            - name: GLM_API_KEY
              valueFrom:
                secretKeyRef:
                  name: vulnforge-secrets
                  key: glm-api-key
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: vulnforge
spec:
  selector: { app: vulnforge }
  ports:
    - port: 80
      targetPort: 8000
```

### Secret

```bash
kubectl create secret generic vulnforge-secrets \
  --from-literal=glm-api-key=your-key \
  --from-literal=webhook-secret=your-webhook-secret
```

## Helm

`deploy/helm/` 提供 Helm Chart：

```bash
helm install vulnforge ./deploy/helm \
  --set image.tag=latest \
  --set llm.glmApiKey=your-key \
  --set webhook.secret=your-secret
```

常用 values：

| 参数 | 说明 |
| --- | --- |
| `image.repository` | 镜像仓库 |
| `image.tag` | 镜像标签 |
| `replicaCount` | 副本数 |
| `service.port` | 服务端口 |
| `llm.glmApiKey` | GLM API Key |
| `webhook.secret` | Webhook 密钥 |
| `config` | 内联 `config.yaml` 覆盖 |

## 配置注入

部署时将 `config.yaml` 挂载为 ConfigMap：

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulnforge-config
data:
  config.yaml: |
    general:
      mode: live
    llm:
      default_provider: glm
```

容器内将 `config.yaml` 放到工作目录即可被 `load_config()` 自动加载。

## 资源建议

| 场景 | CPU | 内存 |
| --- | --- | --- |
| mock 离线扫描 | 0.5-1 核 | 512 MB |
| LLM 推理扫描（大仓库） | 2-4 核 | 2-4 GB |
| 并发扫描（worker 8+） | 4 核+ | 4 GB+ |

## 持久化

- 报告输出：挂载 volume 到 `general.output_dir`。
- 崩溃样本：挂载 `fuzz.crash_dir`。
- 缓存：挂载 `dependency` 缓存目录。

## 反向代理

Web 控制台可用 Nginx 代理（`docker/nginx.conf`），注意：
- `/api/` 转发到后端；
- WebSocket（如有）需升级支持；
- 配置 CORS 或同源。
