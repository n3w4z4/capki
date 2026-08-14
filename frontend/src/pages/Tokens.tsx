import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { tokensApi, type TokenSummary } from '../api/tokens'
import { ApiError } from '../api/client'
import { badgeClass, styles } from '../ui/styles'

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—'
}

export default function Tokens() {
  const [tokens, setTokens] = useState<TokenSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [justCreated, setJustCreated] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setTokens(await tokensApi.list())
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load tokens.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setJustCreated(null)
    setBusy(true)
    try {
      const result = await tokensApi.create(name)
      setJustCreated(result.token)
      setName('')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create token.')
    } finally {
      setBusy(false)
    }
  }

  async function handleRevoke(id: number) {
    if (!window.confirm('Revoke this token? Anything using it will stop working immediately.')) {
      return
    }
    setBusy(true)
    try {
      await tokensApi.revoke(id)
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke token.')
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
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Create API Token</h2>
        <p className={`mb-4 ${styles.mutedXs}`}>
          Use this token with <code>Authorization: Bearer &lt;token&gt;</code> to call the API — e.g.{' '}
          <code>POST /api/v1/certificates</code> — without a browser session. It runs with your own
          role's permissions. Full endpoint reference:{' '}
          <a href="/docs" target="_blank" rel="noreferrer" className={styles.link}>
            API docs (Swagger)
          </a>
          .
        </p>
        <form className="flex items-end gap-3" onSubmit={handleCreate}>
          <div className="flex-1">
            <label className={styles.label}>Name</label>
            <input
              className={styles.input}
              placeholder="e.g. ci-automation"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <button type="submit" disabled={busy} className={styles.button}>
            Create
          </button>
        </form>
        {justCreated && (
          <div className="mt-4">
            <label className={styles.label}>New token — copy it now, it won't be shown again</label>
            <input
              readOnly
              className={`${styles.input} font-mono text-xs`}
              value={justCreated}
              onFocus={(e) => e.target.select()}
            />
          </div>
        )}
      </div>

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Your Tokens</h2>
        {tokens.length === 0 ? (
          <p className={styles.muted}>No tokens yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className={styles.tableHeadRow}>
                  <th className="py-2 pr-4 font-medium">Name</th>
                  <th className="py-2 pr-4 font-medium">Prefix</th>
                  <th className="py-2 pr-4 font-medium">Last used</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => (
                  <tr key={t.id} className={styles.tableRow}>
                    <td className="py-2 pr-4 text-gray-900">{t.name}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-gray-700">catk_{t.token_prefix}…</td>
                    <td className="py-2 pr-4 text-gray-700">{formatDate(t.last_used_at)}</td>
                    <td className="py-2 pr-4">
                      <span className={badgeClass(t.revoked_at ? 'red' : 'green')}>
                        {t.revoked_at ? 'Revoked' : 'Active'}
                      </span>
                    </td>
                    <td className="py-2 text-right">
                      {!t.revoked_at && (
                        <button
                          onClick={() => handleRevoke(t.id)}
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
