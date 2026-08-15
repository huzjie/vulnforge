import React, { useEffect, useRef, useState } from 'react'
import { getScans, createScan, cancelScan } from '../api.js'

const SCANNERS = [
  { key: 'static', label: '静态规则分析' },
  { key: 'llm', label: 'LLM 推理' },
  { key: 'fuzz', label: '模糊测试' },
  { key: 'dependency', label: '依赖 CVE' },
  { key: 'secrets', label: '密钥检测' },
]

function statusClass(status) {
  switch ((status || '').toLowerCase()) {
    case 'running':
      return 'badge-running'
    case 'done':
    case 'completed':
      return 'badge-done'
    case 'failed':
    case 'error':
      return 'badge-failed'
    default:
      return 'badge-pending'
  }
}

function isActive(status) {
  const s = (status || '').toLowerCase()
  return s === 'running' || s === 'pending' || s === 'queued'
}

export default function Scans() {
  const [scans, setScans] = useState([])
  const [target, setTarget] = useState('')
  const [scannerFlags, setScannerFlags] = useState({
    static: true,
    llm: true,
    fuzz: false,
    dependency: true,
    secrets: true,
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const pollTimer = useRef(null)

  const loadScans = async () => {
    try {
      const data = await getScans()
      setScans(Array.isArray(data) ? data : [])
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadScans()
    pollTimer.current = setInterval(loadScans, 5000)
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current)
    }
  }, [])

  const toggleScanner = (key) => {
    setScannerFlags((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!target.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await createScan({ target: target.trim(), scanners: scannerFlags })
      setTarget('')
      await loadScans()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const handleCancel = async (id) => {
    try {
      await cancelScan(id)
      await loadScans()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Scans</h1>
          <p className="page-subtitle">发起并跟踪安全扫描任务</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h2 className="card-title">发起扫描</h2>
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="scan-target">目标路径 / 仓库</label>
            <input
              id="scan-target"
              type="text"
              placeholder="/path/to/repo 或 https://github.com/org/repo"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="field">
            <label>扫描器</label>
            <div className="flex" style={{ flexWrap: 'wrap' }}>
              {SCANNERS.map((scanner) => (
                <label key={scanner.key} className="switch">
                  <input
                    type="checkbox"
                    checked={!!scannerFlags[scanner.key]}
                    onChange={() => toggleScanner(scanner.key)}
                  />
                  <span className="track" />
                  <span>{scanner.label}</span>
                </label>
              ))}
            </div>
          </div>
          <button type="submit" className="btn-primary" disabled={submitting || !target.trim()}>
            {submitting ? '提交中…' : '开始扫描'}
          </button>
        </form>
      </div>

      {error ? <div className="error-banner">{error}</div> : null}

      <div className="card">
        <h2 className="card-title">扫描历史</h2>
        {loading ? (
          <div className="loading">加载中…</div>
        ) : scans.length === 0 ? (
          <div className="empty-state">暂无扫描记录</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>目标</th>
                  <th>状态</th>
                  <th>扫描器</th>
                  <th>findings</th>
                  <th>开始时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const scanners = scan.scanners
                    ? Object.entries(scan.scanners)
                        .filter(([, v]) => v)
                        .map(([k]) => k)
                    : []
                  return (
                    <tr key={scan.id}>
                      <td className="mono">{scan.id}</td>
                      <td className="mono">{scan.target}</td>
                      <td>
                        <span className={`badge ${statusClass(scan.status)}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="muted">{scanners.join(', ') || '—'}</td>
                      <td>{scan.findings_count ?? '—'}</td>
                      <td className="muted">{scan.started_at || scan.created_at || '—'}</td>
                      <td>
                        {isActive(scan.status) ? (
                          <button className="btn btn-sm" onClick={() => handleCancel(scan.id)}>
                            取消
                          </button>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
