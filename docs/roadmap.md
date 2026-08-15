# 路线图

vulnforge 的演进规划，按优先级排序。

## 1.0.0（当前）

- ✅ 静态规则扫描（15 类、60+ 条规则）
- ✅ LLM 推理扫描（mock + OpenAI 兼容 + Anthropic + Gemini + Ollama）
- ✅ 轻量变异模糊测试引擎
- ✅ 依赖/SBOM 扫描 + 内置 CVE 库 + OSV 客户端
- ✅ 密钥检测（CWE-798）
- ✅ CVSS 3.1 基评分
- ✅ 报告：JSON / Markdown / HTML / SARIF / CycloneDX
- ✅ CLI + Python SDK + Webhook HMAC
- ✅ Web 控制台（React 前端）+ REST API
- ✅ Docker / K8s / Helm 部署

## 1.1（规划中）

- [ ] 语义级数据流分析（超越正则）
- [ ] 更多语言规则（Ruby、PHP、Swift、Kotlin）
- [ ] 增量扫描（仅扫描变更文件）
- [ ] 扫描结果数据库持久化与历史对比
- [ ] 自定义规则 DSL 与热加载

## 1.2（规划中）

- [ ] 覆盖率引导（coverage-guided）Fuzz，接入 AFL/libFuzzer 风格插桩
- [ ] 多模型投票 / 交叉验证提升 LLM 发现精度
- [ ] CVE 数据库在线同步与本地缓存策略优化
- [ ] 修复建议自动生成（AI 生成补丁）

## 2.0（远期）

- [ ] 自主漏洞挖掘闭环：发现 → 复现 → 生成 PoC → 提交
- [ ] 分布式扫描（多 worker、任务队列）
- [ ] 与 SCA/SAST/DAST 生态深度集成
- [ ] 面向「40 年老漏洞」级别的长期自主审计能力

## 贡献

欢迎通过 Issue / PR 参与，详见 `CONTRIBUTING.md`。路线图会随社区反馈持续调整。
