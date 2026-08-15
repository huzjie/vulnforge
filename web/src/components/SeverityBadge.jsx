import React from 'react'

const SEVERITY_META = {
  info: { label: 'info', className: 'sev-info' },
  low: { label: 'low', className: 'sev-low' },
  medium: { label: 'medium', className: 'sev-medium' },
  high: { label: 'high', className: 'sev-high' },
  critical: { label: 'critical', className: 'sev-critical' },
}

export default function SeverityBadge({ severity }) {
  const key = (severity || 'info').toLowerCase()
  const meta = SEVERITY_META[key] || SEVERITY_META.info
  return <span className={`badge ${meta.className}`}>{meta.label}</span>
}
