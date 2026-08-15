import React, { useState } from 'react'
import { getApiBase, getToken, setApiBase, setToken } from '../api.js'

export default function Settings() {
  const [apiBase, setApiBaseState] = useState(getApiBase())
  const [token, setTokenState] = useState(getToken())
  const [saved, setSaved] = useState(false)

  const handleSave = (e) => {
    e.preventDefault()
    setApiBase(apiBase)
    setToken(token)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleReset = () => {
    setApiBase('/api')
    setToken('')
    setApiBase('/api')
    setToken('')
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">控制台连接配置（保存于浏览器 localStorage）</p>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 560 }}>
        <form onSubmit={handleSave}>
          <div className="field">
            <label htmlFor="api-base">API Base URL</label>
            <input
              id="api-base"
              type="text"
              placeholder="/api 或 http://localhost:8000/api"
              value={apiBase}
              onChange={(e) => setApiBaseState(e.target.value)}
            />
            <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
              默认为 <code>/api</code>（由 Vite 代理或 nginx 反代转发到后端）。
            </p>
          </div>

          <div className="field">
            <label htmlFor="token">Bearer Token</label>
            <input
              id="token"
              type="password"
              placeholder="可选：后端 auth_token"
              value={token}
              onChange={(e) => setTokenState(e.target.value)}
              autoComplete="off"
            />
          </div>

          <div className="flex">
            <button type="submit" className="btn-primary">保存</button>
            <button type="button" className="btn" onClick={handleReset}>重置</button>
            {saved ? <span style={{ color: '#3fb950', fontSize: 13 }}>已保存</span> : null}
          </div>
        </form>
      </div>
    </div>
  )
}
