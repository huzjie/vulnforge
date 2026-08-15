import React, { useEffect, useState } from 'react'
import { getProviders } from '../api.js'
import DataTable from '../components/DataTable.jsx'

export default function Providers() {
  const [providers, setProviders] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getProviders()
      .then((data) => setProviders(Array.isArray(data) ? data : []))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const columns = [
    {
      key: 'name',
      label: '名称',
      render: (p) => (
        <span className="mono">
          {p.name}
          {p.default ? <span style={{ marginLeft: 8 }} className="badge badge-done">default</span> : null}
        </span>
      ),
    },
    { key: 'type', label: '类型', render: (p) => <span className="muted">{p.type}</span> },
    { key: 'model', label: '模型', render: (p) => <span className="mono">{p.model || '—'}</span> },
    { key: 'base_url', label: 'Base URL', render: (p) => <span className="mono muted">{p.base_url || '—'}</span> },
    {
      key: 'status',
      label: '状态',
      render: (p) => (
        <span className={`badge ${p.available ? 'badge-done' : 'badge-failed'}`}>
          {p.available ? '可用' : '不可用'}
        </span>
      ),
    },
  ]

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Providers</h1>
          <p className="page-subtitle">LLM provider 配置列表</p>
        </div>
      </div>

      {error ? <div className="error-banner">{error}</div> : null}

      <div className="card">
        {loading ? (
          <div className="loading">加载中…</div>
        ) : (
          <DataTable columns={columns} rows={providers} rowKey={(p) => p.name} />
        )}
      </div>
    </div>
  )
}
