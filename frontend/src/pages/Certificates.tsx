import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { certificatesApi, type CertificateSummary } from '../api/certificates'
import { apiClient, ApiError } from '../api/client'
import { badgeClass, styles, type BadgeTone } from '../ui/styles'
import CsrGenerator from '../components/CsrGenerator'

const PROFILES = [
  { code: 'server', label: 'TLS Server' },
  { code: 'client', label: 'mTLS Client' },
  { code: 'user', label: 'User / S-MIME' },
  { code: 'code_signing', label: 'Code Signing' },
]

const STATUS_OPTIONS = [
  { value: 'valid', label: 'Valid' },
  { value: 'revoked', label: 'Revoked' },
]

const VALID_OPTIONS = [
  { value: 'true', label: 'Not expired' },
  { value: 'false', label: 'Expired' },
]

const VIA_OPTIONS = [
  { value: 'ui', label: 'UI' },
  { value: 'api', label: 'API' },
]

const STATUS_TONE: Record<string, BadgeTone> = {
  valid: 'green',
  revoked: 'red',
  expired: 'gray',
}

function formatDate(value: string): string {
  return new Date(value).toLocaleDateString()
}

function commonNameOf(subjectDn: string): string | undefined {
  return subjectDn.match(/CN=([^,]+)/)?.[1]
}

function filenameFor(subjectDn: string, id: number, suffix: string): string {
  return `${commonNameOf(subjectDn) ?? `cert-${id}`}${suffix}`
}

interface ViewingCert {
  subjectDn: string
  pem: string
}

export default function Certificates() {
  const [certs, setCerts] = useState<CertificateSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [issuedChain, setIssuedChain] = useState<string | null>(null)
  const [viewingCert, setViewingCert] = useState<ViewingCert | null>(null)

  const [csrPem, setCsrPem] = useState('')
  const [profileCode, setProfileCode] = useState('server')
  const [search, setSearch] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')

  const [profileFilter, setProfileFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [validFilter, setValidFilter] = useState('')
  const [viaFilter, setViaFilter] = useState('')

  const refresh = useCallback(async () => {
    setCerts(
      await certificatesApi.list({
        q: appliedSearch || undefined,
        status: statusFilter || undefined,
        profile_code: profileFilter || undefined,
        issued_via: viaFilter || undefined,
        valid: validFilter === '' ? undefined : validFilter === 'true',
      })
    )
  }, [appliedSearch, statusFilter, profileFilter, viaFilter, validFilter])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load certificates.'))
      .finally(() => setLoading(false))
  }, [refresh])

  function handleSearch(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setAppliedSearch(search)
  }

  async function handleRevoke(id: number) {
    if (!window.confirm('Revoke this certificate? This cannot be undone.')) {
      return
    }
    setError(null)
    setBusy(true)
    try {
      await certificatesApi.revoke(id, 'unspecified')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Revocation failed.')
    } finally {
      setBusy(false)
    }
  }

  async function handleIssue(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setIssuedChain(null)
    setBusy(true)
    try {
      const result = await certificatesApi.issue({ csr_pem: csrPem, profile_code: profileCode })
      setIssuedChain(result.chain_pem)
      setCsrPem('')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Issuance failed.')
    } finally {
      setBusy(false)
    }
  }

  async function handleView(cert: CertificateSummary) {
    setError(null)
    try {
      const pem = await apiClient.getText(`/api/v1/certificates/${cert.id}/pem`)
      setViewingCert({ subjectDn: cert.subject_dn, pem })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load certificate.')
    }
  }

  async function handleDownloadPem(cert: CertificateSummary) {
    setError(null)
    try {
      await apiClient.download(
        `/api/v1/certificates/${cert.id}/pem`,
        filenameFor(cert.subject_dn, cert.id, '.pem')
      )
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Download failed.')
    }
  }

  async function handleDownloadChain(cert: CertificateSummary) {
    setError(null)
    try {
      await apiClient.download(
        `/api/v1/certificates/${cert.id}/chain.pem`,
        filenameFor(cert.subject_dn, cert.id, '-chain.pem')
      )
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

      {viewingCert && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/40 p-4 backdrop-blur-sm"
          onClick={() => setViewingCert(null)}
        >
          <div
            className="max-h-[80vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-gray-200 bg-white p-6 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 className={styles.sectionTitle}>Certificate</h2>
                <p className="mt-1 break-all text-xs text-gray-500">{viewingCert.subjectDn}</p>
              </div>
              <button
                onClick={() => setViewingCert(null)}
                className="text-gray-400 hover:text-gray-700"
                aria-label="Close"
              >
                ✕
              </button>
            </div>
            <textarea
              readOnly
              className={`${styles.input} mt-0 h-80 font-mono text-xs`}
              value={viewingCert.pem}
              onFocus={(e) => e.target.select()}
            />
          </div>
        </div>
      )}

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Issue Certificate</h2>
        <form className="space-y-4" onSubmit={handleIssue}>
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
            Issue certificate
          </button>
        </form>
        {issuedChain && (
          <div className="mt-4">
            <label className={styles.label}>Issued chain (leaf + intermediate + root)</label>
            <textarea
              readOnly
              className={`${styles.input} h-40 font-mono text-xs`}
              value={issuedChain}
              onFocus={(e) => e.target.select()}
            />
          </div>
        )}
      </div>

      <div className={styles.card}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className={styles.sectionTitle}>Issued Certificates</h2>
          <form onSubmit={handleSearch} className="flex gap-2">
            <input
              className={`${styles.input} mt-0 w-56`}
              placeholder="Search subject…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <button type="submit" className={styles.buttonSecondary}>
              Search
            </button>
          </form>
        </div>

        <div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-1.5">
            <label className={styles.filterLabel}>Profile</label>
            <select
              className={styles.selectSm}
              value={profileFilter}
              onChange={(e) => setProfileFilter(e.target.value)}
            >
              <option value="">All</option>
              {PROFILES.map((p) => (
                <option key={p.code} value={p.code}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-1.5">
            <label className={styles.filterLabel}>Status</label>
            <select
              className={styles.selectSm}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All</option>
              {STATUS_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-1.5">
            <label className={styles.filterLabel}>Valid</label>
            <select
              className={styles.selectSm}
              value={validFilter}
              onChange={(e) => setValidFilter(e.target.value)}
            >
              <option value="">Any</option>
              {VALID_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-1.5">
            <label className={styles.filterLabel}>Via</label>
            <select
              className={styles.selectSm}
              value={viaFilter}
              onChange={(e) => setViaFilter(e.target.value)}
            >
              <option value="">All</option>
              {VIA_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        {certs.length === 0 ? (
          <p className={styles.muted}>No certificates found.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className={styles.tableHeadRow}>
                  <th className="py-2 pr-4 font-medium">FQDN</th>
                  <th className="py-2 pr-4 font-medium">Profile</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 pr-4 font-medium whitespace-nowrap">Valid until</th>
                  <th className="py-2 pr-4 font-medium">Via</th>
                  <th className="py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {certs.map((cert) => (
                  <tr key={cert.id} className={styles.tableRow}>
                    <td
                      className="max-w-[220px] truncate py-2 pr-4 text-gray-900"
                      title={cert.subject_dn}
                    >
                      {commonNameOf(cert.subject_dn) ?? cert.subject_dn}
                    </td>
                    <td className="py-2 pr-4 text-gray-700">{cert.profile_code}</td>
                    <td className="py-2 pr-4">
                      <span className={badgeClass(STATUS_TONE[cert.status] ?? 'gray')}>
                        {cert.status}
                      </span>
                    </td>
                    <td className="py-2 pr-4 whitespace-nowrap text-gray-700">
                      {formatDate(cert.not_after)}
                    </td>
                    <td className="py-2 pr-4 text-gray-700">{cert.issued_via}</td>
                    <td className="py-2 text-right whitespace-nowrap">
                      <button onClick={() => handleView(cert)} className={`mr-3 ${styles.link}`}>
                        View
                      </button>
                      <button onClick={() => handleDownloadPem(cert)} className={`mr-3 ${styles.link}`}>
                        Download PEM
                      </button>
                      <button onClick={() => handleDownloadChain(cert)} className={`mr-3 ${styles.link}`}>
                        Download Chain
                      </button>
                      {cert.status === 'valid' && (
                        <button
                          onClick={() => handleRevoke(cert.id)}
                          disabled={busy}
                          className={styles.linkDanger}
                        >
                          Revoke
                        </button>
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
