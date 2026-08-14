import { useCallback, useEffect, useState } from 'react'
import { certificateRequestsApi, type CertRequestSummary } from '../api/certificateRequests'
import { ApiError } from '../api/client'
import { styles } from '../ui/styles'

function formatDate(value: string): string {
  return new Date(value).toLocaleString()
}

export default function Approvals() {
  const [requests, setRequests] = useState<CertRequestSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    setRequests(await certificateRequestsApi.pending())
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load requests.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function handleApprove(id: number) {
    setError(null)
    setBusy(true)
    try {
      await certificateRequestsApi.approve(id)
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Approval failed.')
    } finally {
      setBusy(false)
    }
  }

  async function handleReject(id: number) {
    const reason = window.prompt('Reason for rejection:')
    if (reason === null) {
      return
    }
    setError(null)
    setBusy(true)
    try {
      await certificateRequestsApi.reject(id, reason || 'unspecified')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Rejection failed.')
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  return (
    <div className="space-y-6">
      {error && <p className={styles.errorBanner}>{error}</p>}

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Pending Certificate Requests</h2>
        {requests.length === 0 ? (
          <p className={styles.muted}>No pending requests.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className={styles.tableHeadRow}>
                  <th className="py-2 pr-4 font-medium">Subject</th>
                  <th className="py-2 pr-4 font-medium">Profile</th>
                  <th className="py-2 pr-4 font-medium">Requested by</th>
                  <th className="py-2 pr-4 font-medium whitespace-nowrap">Submitted</th>
                  <th className="py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id} className={styles.tableRow}>
                    <td className="max-w-[220px] truncate py-2 pr-4 text-gray-900" title={r.subject_dn}>
                      {r.subject_dn}
                    </td>
                    <td className="py-2 pr-4 text-gray-700">{r.profile_code}</td>
                    <td className="py-2 pr-4 text-gray-700">
                      {r.requested_by_username ?? `user #${r.requested_by_user_id}`}
                    </td>
                    <td className="py-2 pr-4 whitespace-nowrap text-gray-700">
                      {formatDate(r.created_at)}
                    </td>
                    <td className="py-2 text-right whitespace-nowrap">
                      <button
                        onClick={() => handleApprove(r.id)}
                        disabled={busy}
                        className={`mr-3 ${styles.link}`}
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => handleReject(r.id)}
                        disabled={busy}
                        className={styles.linkDanger}
                      >
                        Reject
                      </button>
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
