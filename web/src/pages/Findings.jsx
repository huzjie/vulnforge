import React, { useEffect, useMemo, useState } from 'react'
import { getFindings } from '../api.js'
import SeverityBadge from '../components/SeverityBadge.jsx'

const SEVERITY_FILTERS = [
  { key: '', label: '全部' },
  { key: 'critical', label: 'critical' },
  { key: 'high', label: 'high' },
  { key: 'medium', label: 'medium' },
  { key: 'low', label: 'low' },
  { key: 'info', label: 'info' },
]

export default function Findings() {
  const [findings, setFindings] = useState([])
  const [severityFilter, setSeverityFilter] = useState('')
  const [fileFilter, setFileFilter] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getFindings()
      .then((data) => setFindings(Array.isArray(data) ? data : []))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    let rows = findings
    if (severityFilter) {
      rows = rows.filter((f) => (f.severity || 'info').toLowerCase() === severityFilter)
    }
    if (fileFilter.trim()) {
      const q = fileFilter.trim().toLowerCase()
      rows = rows.filter((f) =>
        (f.file_path || f.file || '').toLowerCase().includes(q),
      )
    }
    return rows
  }, [findings, severityFilter, fileFilter])

  const toggleExpand = (id) => {
    setExpanded((prev) => (prev === id ? null : id))
  }

  const findingKey = (f) =>
    f.id ||
    `${f.rule_id || f.rule || 'rule'}:${f.file_path || f.file || ''}:${f.line || 0}`

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="page-subtitle">漏洞发现列表 · {filtered.length} 条</p>
        </div>
      </div>

      <div className="flex" style={{ marginBottom: 16, flexWrap: 'wrap' }}>
        <div className="chip-row" style={{ marginBottom: 0 }}>
          {SEVERITY_FILTERS.map((f) => (
            <button
              key={f.key}
              className={`chip${severityFilter === f.key ? ' active' : ''}`}
              onClick={() => setSeverityFilter(f.key)}
            >
              {f.label}
            </button>
          ))}
        </div>
        <input
          type="text"
          placeholder="按文件过滤…"
          value={fileFilter}
          onChange={(e) => setFileFilter(e.target.value)}
          style={{ maxWidth: 240 }}
        />
      </div>

      {error ? <div className="error-banner">{error}</div> : null}

      {loading ? (
        <div className="loading">加载中…</div>
      ) : filtered.length === 0 ? (
        <div className="empty-state">暂无 findings</div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>严重度</th>
                  <th>文件:行号</th>
                  <th>规则</th>
                  <th>CWE</th>
                  <th>扫描器</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((finding) => (
                  <React.Fragment key={findingKey(finding)}>
                    <tr className="clickable" onClick={() => toggleExpand(findingKey(finding))}>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="mono">
                        {finding.file_path || finding.file}
                        {finding.line ? `:${finding.line}` : ''}
                      </td>
                      <td>{finding.rule_id || finding.rule || finding.title || '—'}</td>
                      <td className="mono">{finding.cwe || '—'}</td>
                      <td className="muted">{finding.scanner || '—'}</td>
                    </tr>
                    {expanded === findingKey(finding) ? (
                      <tr>
                        <td colSpan={5} style={{ background: 'var(--bg-inset)' }}>
                          <div className="detail-row">
                            <span className="k">标题</span>
                            <span>{finding.title || '—'}</span>
                          </div>
                          <div className="detail-row">
                            <span className="k">描述</span>
                            <span>{finding.description || '—'}</span>
                          </div>
                          {finding.code || finding.snippet ? (
                            <pre className="code-block">{finding.code || finding.snippet}</pre>
                          ) : null}
                          {finding.recommendation ? (
                            <div className="detail-row">
                              <span className="k">建议</span>
                              <span>{finding.recommendation}</span>
                            </div>
                          ) : null}
                          {finding.cvss ? (
                            <div className="detail-row">
                              <span className="k">CVSS</span>
                              <span className="mono">{finding.cvss}</span>
                            </div>
                          ) : null}
                        </td>
                      </tr>
                    ) : null}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
