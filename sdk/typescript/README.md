# vulnforge-sdk (TypeScript)

与 vulnforge API 控制面交互的轻量 TypeScript 客户端（基于 `fetch`，无运行时依赖）。

## 安装

```bash
npm install ./sdk/typescript
```

## 用法

```ts
import { VulnforgeClient } from "vulnforge-sdk";

const client = new VulnforgeClient({
  baseUrl: "http://127.0.0.1:8000",
  token: "your-token", // 可选
});

// 健康检查
console.log(await client.health());

// 发起扫描
const resp = await client.scan(["./src"]);
console.log(resp.scan_id, resp.status);

// 查询结果
const result = await client.getScan(resp.scan_id);
console.log(result.status, result.findings_count);

// 查询 findings
const data = await client.findings({ scan_id: resp.scan_id, severity: "high" });

// 导出报告
const markdown = await client.reports(resp.scan_id, "markdown");
console.log(markdown);
```

## 构建

```bash
npm install
npm run build
```
