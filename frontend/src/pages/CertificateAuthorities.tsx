import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { caApi, type CaSummary, type RootStatus } from '../api/ca'
import { ApiError } from '../api/client'
import { badgeClass, styles } from '../ui/styles'

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleDateString() : '—'
}

export default function CertificateAuthorities() {
  const [cas, setCas] = useState<CaSummary[]>([])
  const [rootStatus, setRootStatus] = useState<RootStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [rootCommonName, setRootCommonName] = useState('')
  const [rootOrg, setRootOrg] = useState('')
  const [rootPassphrase, setRootPassphrase] = useState('')

  const [intermediateCommonName, setIntermediateCommonName] = useState('')
  const [intermediateOrg, setIntermediateOrg] = useState('')

  const [unlockPassphrase, setUnlockPassphrase] = useState('')

  const refresh = useCallback(async () => {
    const [casResult, statusResult] = await Promise.all([caApi.list(), caApi.rootStatus()])
    setCas(casResult)
    setRootStatus(statusResult)
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load CA data.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function withBusy(fn: () => Promise<void>) {
    setError(null)
    setBusy(true)
    try {
      await fn()
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Request failed.')
    } finally {
      setBusy(false)
    }
  }

  function handleInitRoot(e: FormEvent) {
    e.preventDefault()
    withBusy(async () => {
      await caApi.initRoot({
        common_name: rootCommonName,
        organization_name: rootOrg || undefined,
        passphrase: rootPassphrase,
      })
      setRootPassphrase('')
    })
  }

  function handleInitIntermediate(e: FormEvent) {
    e.preventDefault()
    withBusy(async () => {
      await caApi.initIntermediate({
        common_name: intermediateCommonName,
        organization_name: intermediateOrg || undefined,
      })
    })
  }

  function handleUnlockRoot(e: FormEvent) {
    e.preventDefault()
    withBusy(async () => {
      await caApi.unlockRoot(unlockPassphrase)
      setUnlockPassphrase('')
    })
  }

  function handleLockRoot() {
    withBusy(async () => {
      await caApi.lockRoot()
    })
  }

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  const hasIntermediate = cas.some((ca) => ca.type === 'intermediate' && ca.status === 'active')

  return (
    <div className="space-y-6">
      {error && <p className={styles.errorBanner}>{error}</p>}

      {cas.length > 0 && (
        <div className={styles.card}>
          <h2 className={`mb-4 ${styles.sectionTitle}`}>Certificate Authorities</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className={styles.tableHeadRow}>
                  <th className="py-2 pr-4 font-medium">Type</th>
                  <th className="py-2 pr-4 font-medium">Name</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 pr-4 font-medium">Valid from</th>
                  <th className="py-2 font-medium">Valid until</th>
                </tr>
              </thead>
              <tbody>
                {cas.map((ca) => (
                  <tr key={ca.id} className={styles.tableRow}>
                    <td className="py-2 pr-4 capitalize text-gray-700">{ca.type}</td>
                    <td className="py-2 pr-4 text-gray-900">{ca.name}</td>
                    <td className="py-2 pr-4">
                      <span className={badgeClass(ca.status === 'active' ? 'green' : 'gray')}>
                        {ca.status}
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-gray-700">{formatDate(ca.not_before)}</td>
                    <td className="py-2 text-gray-700">{formatDate(ca.not_after)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {!rootStatus?.initialized && (
        <div className={styles.card}>
          <h2 className={`mb-4 ${styles.sectionTitle}`}>Initialize Root CA</h2>
          <form className="space-y-4" onSubmit={handleInitRoot}>
            <div>
              <label className={styles.label}>Common name</label>
              <input
                className={styles.input}
                placeholder="Example Root CA"
                value={rootCommonName}
                onChange={(e) => setRootCommonName(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>Organization</label>
              <input
                className={styles.input}
                placeholder="Example Org"
                value={rootOrg}
                onChange={(e) => setRootOrg(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>Root passphrase (min. 12 characters)</label>
              <input
                type="password"
                className={styles.input}
                value={rootPassphrase}
                onChange={(e) => setRootPassphrase(e.target.value)}
                minLength={12}
                required
              />
              <p className={`mt-1 ${styles.mutedXs}`}>
                Store this somewhere safe — it's required to unlock the root CA after every restart, and
                it cannot be recovered if lost.
              </p>
            </div>
            <button type="submit" disabled={busy} className={styles.button}>
              Generate root CA
            </button>
          </form>
        </div>
      )}

      {rootStatus?.initialized && (
        <div className={styles.card}>
          <h2 className={`mb-4 flex items-center justify-between ${styles.sectionTitle}`}>
            Root CA
            <span className={badgeClass(rootStatus.unlocked ? 'green' : 'gray')}>
              {rootStatus.unlocked ? 'Unlocked' : 'Locked'}
            </span>
          </h2>
          {rootStatus.unlocked ? (
            <button onClick={handleLockRoot} disabled={busy} className={styles.buttonSecondary}>
              Lock root CA
            </button>
          ) : (
            <form className="space-y-4" onSubmit={handleUnlockRoot}>
              <div>
                <label className={styles.label}>Root passphrase</label>
                <input
                  type="password"
                  className={styles.input}
                  value={unlockPassphrase}
                  onChange={(e) => setUnlockPassphrase(e.target.value)}
                  required
                />
              </div>
              <button type="submit" disabled={busy} className={styles.button}>
                Unlock root CA
              </button>
            </form>
          )}
        </div>
      )}

      {rootStatus?.initialized && rootStatus.unlocked && !hasIntermediate && (
        <div className={styles.card}>
          <h2 className={`mb-4 ${styles.sectionTitle}`}>Initialize Intermediate CA</h2>
          <form className="space-y-4" onSubmit={handleInitIntermediate}>
            <div>
              <label className={styles.label}>Common name</label>
              <input
                className={styles.input}
                placeholder="Example Intermediate CA"
                value={intermediateCommonName}
                onChange={(e) => setIntermediateCommonName(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>Organization</label>
              <input
                className={styles.input}
                placeholder="Example Org"
                value={intermediateOrg}
                onChange={(e) => setIntermediateOrg(e.target.value)}
              />
            </div>
            <button type="submit" disabled={busy} className={styles.button}>
              Generate intermediate CA
            </button>
          </form>
        </div>
      )}
    </div>
  )
}
