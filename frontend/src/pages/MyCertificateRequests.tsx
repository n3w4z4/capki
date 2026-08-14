import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { certificateRequestsApi, type CertRequestSummary } from '../api/certificateRequests'
import { apiClient, ApiError } from '../api/client'
import { badgeClass, styles, type BadgeTone } from '../ui/styles'
import CsrGenerator from '../components/CsrGenerator'

const PROFILES = [
  { code: 'server', label: 'TLS Server' },
  { code: 'client', label: 'mTLS Client' },
  { code: 'user', label: 'User / S-MIME' },
  { code: 'code_signing', label: 'Code Signing' },
]

const STATUS_TONE: Record<string, BadgeTone> = {
  pending: 'amber',
  approved: 'green',
  rejected: 'red',
}

function formatDate(value: string): string {
  return new Date(value).toLocaleString()
}

export default function MyCertificateRequests() {
  const [requests, setRequests] = useState<CertRequestSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [csrPem, setCsrPem] = useState('')
  const [profileCode, setProfileCode] = useState('server')

  const refresh = useCallback(async () => {
    setRequests(await certificateRequestsApi.mine())
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load requests.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await certificateRequestsApi.submit({ csr_pem: csrPem, profile_code: profileCode })
      setCsrPem('')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Submission failed.')
    } finally {
      setBusy(false)
    }
  }

  async function handleDownload(req: CertRequestSummary, kind: 'pem' | 'chain.pem') {
    setError(null)
    try {
      const cn = req.subject_dn.match(/CN=([^,]+)/)?.[1] ?? `cert-${req.id}`
      const suffix = kind === 'pem' ? '.pem' : '-chain.pem'
      await apiClient.download(`/api/v1/certificate-requests/${req.id}/${kind}`, `${cn}${suffix}`)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Download failed.')
    }
  }

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  return (
    <div className="space-y-6">
      {error && <p className={styles.errorBanner}>{error}</p>}

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Request a Certificate</h2>
        <p className={`mb-4 ${styles.mutedXs}`}>
          Submit a CSR for review — an operator or admin will approve or reject it.
        </p>
        <form className="space-y-4" onSubmit={handleSubmit}>
          <div>
            <label className={styles.label}>Profile</label>
            <select
              className={styles.input}
              value={profileCode}
              onChange={(e) => setProfileCode(e.target.value)}
            >
              {PROFILES.map((p) => (
                <option key={p.code} value={p.code}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className={styles.label}>CSR (PEM)</label>
            <textarea
              className={`${styles.input} h-40 font-mono text-xs`}
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              value={csrPem}
              onChange={(e) => setCsrPem(e.target.value)}
              required
            />
          </div>
          <CsrGenerator onGenerated={setCsrPem} />
          <button type="submit" disabled={busy} className={styles.button}>
            Submit request
          </button>
        </form>
      </div>

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>My Requests</h2>
        {requests.length === 0 ? (
          <p className={styles.muted}>No requests submitted yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className={styles.tableHeadRow}>
                  <th className="py-2 pr-4 font-medium">Subject</th>
                  <th className="py-2 pr-4 font-medium">Profile</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
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
                    <td className="py-2 pr-4">
                      <span className={badgeClass(STATUS_TONE[r.status])}>{r.status}</span>
                      {r.status === 'rejected' && r.rejection_reason && (
                        <span className={`ml-2 ${styles.mutedXs}`}>({r.rejection_reason})</span>
                      )}
                    </td>
                    <td className="py-2 pr-4 whitespace-nowrap text-gray-700">
                      {formatDate(r.created_at)}
                    </td>
                    <td className="py-2 text-right whitespace-nowrap">
                      {r.status === 'approved' && (
                        <>
                          <button onClick={() => handleDownload(r, 'pem')} className={`mr-3 ${styles.link}`}>
                            Download PEM
                          </button>
                          <button onClick={() => handleDownload(r, 'chain.pem')} className={styles.link}>
                            Download Chain
                          </button>
                        </>
                      )}
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
