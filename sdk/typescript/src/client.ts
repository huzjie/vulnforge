import type { ScanRequest, ScanResponse } from "./types.js";

export interface VulnforgeClientOptions {
  /** vulnforge 控制面地址，如 http://127.0.0.1:8000 */
  baseUrl: string;
  /** 可选 Bearer token */
  token?: string;
  /** 请求超时（毫秒），默认 30000 */
  timeoutMs?: number;
}

/**
 * 与 vulnforge API 控制面交互的轻量客户端（基于 fetch）。
 */
export class VulnforgeClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly timeoutMs: number;

  constructor(options: VulnforgeClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  private async request<T>(
    method: string,
    path: string,
    params?: Record<string, unknown>,
    body?: unknown,
  ): Promise<T> {
    let url = this.baseUrl + path;
    if (params) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null) qs.set(k, String(v));
      }
      const s = qs.toString();
      if (s) url += "?" + s;
    }

    const headers: Record<string, string> = { Accept: "application/json" };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;

    let init: RequestInit = { method, headers };
    if (typeof AbortSignal !== "undefined" && "timeout" in AbortSignal) {
      init.signal = (AbortSignal as unknown as {
        timeout(ms: number): AbortSignal;
      }).timeout(this.timeoutMs);
    }
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    const resp = await fetch(url, init);
    const text = await resp.text();
    if (!resp.ok) {
      throw new Error(`vulnforge API error ${resp.status}: ${text}`);
    }
    if (!text) return undefined as T;
    const ctype = resp.headers.get("content-type") ?? "";
    return ctype.includes("json") ? (JSON.parse(text) as T) : (text as unknown as T);
  }

  /** GET /healthz */
  async health(): Promise<{ status: string }> {
    return this.request<{ status: string }>("GET", "/healthz");
  }

  /** POST /scan */
  async scan(paths: string[], scanners?: Record<string, unknown>): Promise<ScanResponse> {
    const payload: ScanRequest = { paths };
    if (scanners) payload.scanners = scanners;
    return this.request<ScanResponse>("POST", "/scan", undefined, payload);
  }

  /** GET /scan/:id */
  async getScan(scanId: string): Promise<ScanResponse> {
    return this.request<ScanResponse>("GET", `/scan/${encodeURIComponent(scanId)}`);
  }

  /** GET /scans */
  async listScans(): Promise<unknown> {
    return this.request("GET", "/scans");
  }

  /** GET /findings */
  async findings(params?: {
    scan_id?: string;
    severity?: string;
    file?: string;
    limit?: number;
    offset?: number;
  }): Promise<unknown> {
    return this.request("GET", "/findings", params as Record<string, unknown>);
  }

  /** GET /reports/:id?format=... */
  async reports(
    scanId: string,
    format: "json" | "markdown" | "html" | "sarif" | "text" = "json",
  ): Promise<string> {
    return this.request<string>(
      "GET",
      `/reports/${encodeURIComponent(scanId)}`,
      { format },
    );
  }

  /** GET /rules */
  async rules(): Promise<unknown> {
    return this.request("GET", "/rules");
  }

  /** GET /providers */
  async providers(): Promise<unknown> {
    return this.request("GET", "/providers");
  }
}
