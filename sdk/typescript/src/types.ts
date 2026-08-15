/** vulnforge TypeScript SDK 类型定义。 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id?: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  file_path: string;
  line: number;
  column?: number;
  code?: string;
  cwe?: string;
  cvss?: number | null;
  confidence?: number;
  scanner?: string;
  recommendation?: string;
  references?: string[];
  tags?: string[];
  raw?: Record<string, unknown>;
}

export interface ScanRequest {
  paths: string[];
  scanners?: Record<string, unknown>;
}

export type ScanStatus = "running" | "completed" | "failed";

export interface ScanResponse {
  scan_id: string;
  status: ScanStatus;
  findings_count: number;
  report?: unknown;
  error?: string | null;
}
