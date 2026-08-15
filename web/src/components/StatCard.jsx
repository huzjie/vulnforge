import React from 'react'

const ACCENT_BY_TONE = {
  red: 'var(--accent-red)',
  blue: 'var(--accent-blue)',
  gray: 'var(--text-muted)',
  yellow: 'var(--sev-medium)',
  orange: 'var(--sev-high)',
  green: '#3fb950',
}

export default function StatCard({ label, value, tone = 'red', hint }) {
  const accent = ACCENT_BY_TONE[tone] || ACCENT_BY_TONE.red
  return (
    <div className="stat-card">
      <span className="stat-accent" style={{ background: accent }} />
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint ? <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{hint}</div> : null}
    </div>
  )
}
