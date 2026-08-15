import React, { useEffect, useState } from 'react'
import { getRules } from '../api.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import DataTable from '../components/DataTable.jsx'

export default function Rules() {
  const [rules, setRules] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getRules()
      .then((data) => setRules(Array.isArray(data) ? data : []))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const columns = [
    { key: 'id', label: 'ID', render: (r) => <span className="mono">{r.id}</span> },
    { key: 'name', label: '规则名', render: (r) => <span className="mono">{r.name}</span> },
    { key: 'severity', label: '严重度', render: (r) => <SeverityBadge severity={r.severity} /> },
    { key: 'cwe', label: 'CWE', render: (r) => <span className="mono">{r.cwe || '—'}</span> },
    { key: 'description', label: '描述', render: (r) => <span className="muted">{r.description || '—'}</span> },
  ]

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Rules</h1>
          <p className="page-subtitle">静态分析规则库 · {rules.length} 条</p>
        </div>
      </div>

      {error ? <div className="error-banner">{error}</div> : null}

      <div className="card">
        {loading ? (
          <div className="loading">加载中…</div>
        ) : (
          <DataTable columns={columns} rows={rules} rowKey={(r) => r.id || r.name} />
        )}
      </div>
    </div>
  )
}
