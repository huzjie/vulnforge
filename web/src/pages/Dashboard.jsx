import React, { useEffect, useState } from 'react'
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { getStats } from '../api.js'
import StatCard from '../components/StatCard.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'

const SEVERITY_COLORS = {
  info: '#8b949e',
  low: '#58a6ff',
  medium: '#d29922',
  high: '#f0883e',
  critical: '#e60012',
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

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

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getStats()
      .then((data) => {
        if (!cancelled) setStats(data)
      })
      .catch((err) => {
        if (!cancelled) setError(err.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (loading) return <div className="loading">加载中…</div>
  if (error) return <div className="error-banner">加载失败：{error}</div>

  const s = stats || {}

  const total = s.total || 0
  const severityPie = SEVERITY_ORDER
    .map((key) => ({ name: key, value: s[key] || 0 }))
    .filter((item) => item.value > 0)

  const byScanner = Array.isArray(s.by_scanner) ? s.by_scanner : []
  const recentScans = Array.isArray(s.recent_scans) ? s.recent_scans : []

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">漏洞挖掘与安全审计总览</p>
        </div>
      </div>

      <div className="stat-grid">
        <StatCard label="总 findings" value={total} tone="blue" />
        <StatCard label="critical" value={s.critical || 0} tone="red" />
        <StatCard label="high" value={s.high || 0} tone="orange" />
        <StatCard label="medium" value={s.medium || 0} tone="yellow" />
        <StatCard label="low" value={s.low || 0} tone="gray" />
      </div>

      <div className="grid-2">
        <div className="card">
          <h2 className="card-title">按严重度分布</h2>
          {severityPie.length === 0 ? (
            <div className="empty-state">暂无数据</div>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={severityPie}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={2}
                >
                  {severityPie.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={SEVERITY_COLORS[entry.name] || '#8b949e'}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#161b22',
                    border: '1px solid #30363d',
                    borderRadius: 8,
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <h2 className="card-title">按扫描器分布</h2>
          {byScanner.length === 0 ? (
            <div className="empty-state">暂无数据</div>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={byScanner}>
                <XAxis dataKey="name" stroke="#8b949e" fontSize={12} />
                <YAxis stroke="#8b949e" fontSize={12} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: '#161b22',
                    border: '1px solid #30363d',
                    borderRadius: 8,
                  }}
                  cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                />
                <Bar dataKey="value" fill="#e60012" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h2 className="card-title">最近扫描</h2>
        {recentScans.length === 0 ? (
          <div className="empty-state">暂无扫描记录</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>目标</th>
                  <th>状态</th>
                  <th>严重度</th>
                  <th>时间</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="mono">{scan.target}</td>
                    <td>
                      <span className={`badge ${statusClass(scan.status)}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={scan.top_severity || 'info'} />
                    </td>
                    <td className="muted">{scan.created_at || scan.started_at || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
