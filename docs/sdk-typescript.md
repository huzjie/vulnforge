# TypeScript SDK 用法

vulnforge 的 TypeScript SDK 面向浏览器/Node 环境，通过 REST API 与控制面交互。

## 安装

```bash
npm install vulnforge-sdk
# 或本地链接
npm link
```

## 初始化

```typescript
import { VulnforgeClient } from "vulnforge-sdk";

const client = new VulnforgeClient({
  baseUrl: "http://localhost:8000",
  authToken: "optional-bearer-token",
});
```

## 健康检查

```typescript
const health = await client.health();
// { status: "ok", version: "1.0.0" }
```

## 提交扫描

```typescript
const scan = await client.scan({
  paths: ["src/"],
  formats: ["json", "sarif"],
});

// { scan_id: "...", status: "completed", stats: {...} }
```

## 查询扫描结果

```typescript
const report = await client.getScan(scan.scan_id);
// report.findings: Finding[]
```

## 查询 findings

```typescript
const { total, findings } = await client.findings({
  severity: "high",
  cwe: "CWE-89",
  limit: 100,
});
```

## 生成 SBOM

```typescript
const sbom = await client.sbom({ paths: ["."], ecosystem: "auto" });
// CycloneDX 1.5 JSON
```

## 类型定义

```typescript
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  file_path: string;
  line: number;
  column?: number;
  code?: string;
  cwe?: string;
  cvss?: string | null;
  confidence?: number;
  scanner?: string;
  recommendation?: string;
  references?: string[];
  tags?: string[];
  raw?: Record<string, unknown>;
}

export interface ScanStats {
  total: number;
  severity_counts: Record<string, number>;
  top_rules: Array<{ rule_id: string; count: number }>;
}

export interface ScanReport {
  scan_id: string;
  created_at: string;
  findings: Finding[];
  stats: ScanStats;
}
```

## 错误处理

```typescript
try {
  await client.scan({ paths: ["src/"] });
} catch (err) {
  if (err instanceof VulnforgeError) {
    console.error(err.status, err.message);
  }
}
```

## 与浏览器前端集成

`web/` 目录提供了基于 React 的控制台前端，SDK 的 `web/src/api.js` 展示了如何封装 REST 调用。

## 完整示例

```typescript
import { VulnforgeClient } from "vulnforge-sdk";

async function main() {
  const client = new VulnforgeClient({ baseUrl: process.env.VULNFORGE_URL });

  const scan = await client.scan({ paths: ["./src"], formats: ["sarif"] });
  const report = await client.getScan(scan.scan_id);

  for (const f of report.findings) {
    console.log(`[${f.severity}] ${f.rule_id} @ ${f.file_path}:${f.line}`);
  }
}

main();
```

> 说明：TypeScript SDK 依赖控制面（`vulnforge serve`）运行；离线场景请直接使用 Python SDK。
