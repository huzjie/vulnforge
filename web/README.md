# vulnforge console

vulnforge 的 React 控制台（Vite + React 18），通过 REST API 连接后端服务。

## 开发

```bash
npm install
npm run dev
```

开发服务器默认运行于 <http://localhost:3000>，并将 `/api` 代理到
`http://localhost:8000`（见 `vite.config.js`）。

可通过环境变量 `VITE_API_BASE` 覆盖 API 前缀（例如 `VITE_API_BASE=http://other:8000/api npm run dev`）。

## 构建

```bash
npm run build
```

产物输出到 `dist/`，用于 nginx 等静态托管。

## 目录结构

```
web/
├── index.html
├── vite.config.js
├── package.json
└── src/
    ├── main.jsx          # 入口
    ├── App.jsx           # 顶部导航 + 路由
    ├── api.js            # fetch 封装（VITE_API_BASE + token）
    ├── theme.css         # 深色安全主题
    ├── components/
    │   ├── SeverityBadge.jsx
    │   ├── StatCard.jsx
    │   └── DataTable.jsx
    └── pages/
        ├── Dashboard.jsx
        ├── Scans.jsx
        ├── Findings.jsx
        ├── Rules.jsx
        ├── Providers.jsx
        └── Settings.jsx
```

## 后端约定

控制台假定后端暴露以下 JSON 端点（Bearer token 认证）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查 |
| GET | `/api/stats` | 仪表盘统计（total/critical/high/medium/low/by_severity/by_scanner/recent_scans） |
| GET | `/api/scans` | 扫描列表 |
| POST | `/api/scans` | 发起扫描 `{ target, scanners }` |
| POST | `/api/scans/:id/cancel` | 取消扫描 |
| GET | `/api/findings` | findings 列表 |
| GET | `/api/rules` | 静态规则列表 |
| GET | `/api/providers` | LLM provider 列表 |
