import React from 'react'

/**
 * Generic table component.
 * @param {Array<{key, label, render}>} columns
 * @param {Array} rows
 * @param {Function} rowKey
 * @param {Function} onRowClick
 */
export default function DataTable({ columns, rows, rowKey, onRowClick }) {
  if (!rows || rows.length === 0) {
    return <div className="empty-state">暂无数据</div>
  }

  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key}>{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey ? rowKey(row) : row.id || row.key
            return (
              <tr
                key={key}
                className={onRowClick ? 'clickable' : undefined}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
              >
                {columns.map((col) => (
                  <td key={col.key}>
                    {col.render ? col.render(row) : row[col.key]}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
