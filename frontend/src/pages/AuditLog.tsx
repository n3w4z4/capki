import { useEffect, useState } from 'react'
import { auditApi, type AuditLogEntry } from '../api/audit'
import { ApiError } from '../api/client'
import { badgeClass, styles } from '../ui/styles'

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    auditApi
      .list(200)
      .then(setEntries)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load audit log.'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  return (
    <div className="space-y-6">
      {error && <p className={styles.errorBanner}>{error}</p>}
      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Audit Log</h2>
        {entries.length === 0 ? (
          <p className={styles.muted}>No activity recorded yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className={styles.tableHeadRow}>
                  <th className="py-2 pr-4 font-medium">Time</th>
                  <th className="py-2 pr-4 font-medium">Actor</th>
                  <th className="py-2 pr-4 font-medium">Action</th>
                  <th className="py-2 pr-4 font-medium">Target</th>
                  <th className="py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id} className={styles.tableRow}>
                    <td className="py-2 pr-4 whitespace-nowrap text-gray-700">
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2 pr-4 text-gray-900">{e.actor_username ?? e.actor_type}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-gray-700">{e.action}</td>
                    <td className="py-2 pr-4 text-gray-700">
                      {e.target_type ? `${e.target_type} #${e.target_id}` : '—'}
                    </td>
                    <td className="py-2">
                      <span className={badgeClass(e.success ? 'green' : 'red')}>
                        {e.success ? 'ok' : 'failed'}
                      </span>
                    </td>
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
