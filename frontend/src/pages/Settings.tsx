import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { settingsApi, type TlsStatus } from '../api/settings'
import { ApiError } from '../api/client'
import { styles } from '../ui/styles'

function roleMapToText(map: Record<string, string> | null): string {
  return Object.entries(map ?? {})
    .map(([claim, role]) => `${claim}=${role}`)
    .join('\n')
}

function roleMapFromText(text: string): Record<string, string> {
  const map: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const [claim, role] = line.split('=').map((s) => s.trim())
    if (claim && role) {
      map[claim] = role
    }
  }
  return map
}

function TlsSettingsCard() {
  const [status, setStatus] = useState<TlsStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [restarting, setRestarting] = useState(false)
  const [busy, setBusy] = useState(false)
  const [certPem, setCertPem] = useState('')
  const [keyPem, setKeyPem] = useState('')

  useEffect(() => {
    settingsApi
      .getTls()
      .then(setStatus)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load TLS status.'))
      .finally(() => setLoading(false))
  }, [])

  async function handleUpload(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const result = await settingsApi.uploadTls(certPem, keyPem)
      setStatus(result.status)
      setRestarting(true)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Upload failed.')
      setBusy(false)
    }
  }

  async function handleIssueFromIntermediate() {
    setError(null)
    setBusy(true)
    try {
      const result = await settingsApi.issueTlsFromIntermediate()
      setStatus(result.status)
      setRestarting(true)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Issuance failed.')
      setBusy(false)
    }
  }

  return (
    <div className={styles.card}>
      <h2 className={`mb-4 ${styles.sectionTitle}`}>Web Server TLS Certificate</h2>

      {restarting && (
        <p className={`mb-4 ${styles.warningBanner}`}>
          New certificate saved. The server is restarting to apply it — reload this page in a few
          seconds.
        </p>
      )}
      {error && <p className={`mb-4 ${styles.errorBanner}`}>{error}</p>}

      {!loading && status && (
        <p className={`mb-4 ${styles.mutedXs}`}>
          Current source: <strong className="text-gray-700">{status.source}</strong> · valid{' '}
          {new Date(status.not_before).toLocaleDateString()} –{' '}
          {new Date(status.not_after).toLocaleDateString()}
        </p>
      )}

      <button
        onClick={handleIssueFromIntermediate}
        disabled={busy || restarting}
        className={`${styles.buttonSecondary} mb-6`}
      >
        Issue from managed intermediate CA
      </button>

      <form className="space-y-4 border-t border-gray-200 pt-4" onSubmit={handleUpload}>
        <p className={styles.label}>Or upload your own certificate + key</p>
        <div>
          <label className={styles.label}>Certificate (PEM)</label>
          <textarea
            className={`${styles.input} h-24 font-mono text-xs`}
            value={certPem}
            onChange={(e) => setCertPem(e.target.value)}
            required
          />
        </div>
        <div>
          <label className={styles.label}>Private Key (PEM, unencrypted)</label>
          <textarea
            className={`${styles.input} h-24 font-mono text-xs`}
            value={keyPem}
            onChange={(e) => setKeyPem(e.target.value)}
            required
          />
        </div>
        <button type="submit" disabled={busy || restarting} className={styles.button}>
          Upload &amp; apply
        </button>
      </form>
    </div>
  )
}

export default function Settings() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)

  const [enabled, setEnabled] = useState(false)
  const [idpEntityId, setIdpEntityId] = useState('')
  const [idpSsoUrl, setIdpSsoUrl] = useState('')
  const [idpCert, setIdpCert] = useState('')
  const [roleMapText, setRoleMapText] = useState('')

  const refresh = useCallback(async () => {
    const c = await settingsApi.getSaml()
    setEnabled(c.enabled)
    setIdpEntityId(c.idp_entity_id ?? '')
    setIdpSsoUrl(c.idp_sso_url ?? '')
    setIdpCert(c.idp_x509_cert ?? '')
    setRoleMapText(roleMapToText(c.group_role_map))
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load settings.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function handleSave(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setSaved(false)
    setBusy(true)
    try {
      await settingsApi.updateSaml({
        enabled,
        idp_entity_id: idpEntityId,
        idp_sso_url: idpSsoUrl,
        idp_x509_cert: idpCert,
        group_role_map: roleMapFromText(roleMapText),
      })
      setSaved(true)
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save settings.')
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  return (
    <div className="space-y-6">
      <TlsSettingsCard />

      {error && <p className={styles.errorBanner}>{error}</p>}

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>SAML SSO — Microsoft Entra ID</h2>
        <p className={`mb-4 ${styles.mutedXs}`}>
          Register capki as an Enterprise Application in Entra, add App Roles for Admin/Operator/Auditor,
          and use these endpoints:
          <br />
          ACS URL: <code>/api/v1/auth/saml/acs</code> &nbsp;·&nbsp; SP Entity ID / metadata:{' '}
          <code>/api/v1/auth/saml/metadata</code>
        </p>
        <form className="space-y-4" onSubmit={handleSave}>
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            Enable SAML sign-in
          </label>
          <div>
            <label className={styles.label}>IdP Entity ID (Issuer)</label>
            <input
              className={styles.input}
              placeholder="https://sts.windows.net/&lt;tenant-id&gt;/"
              value={idpEntityId}
              onChange={(e) => setIdpEntityId(e.target.value)}
            />
          </div>
          <div>
            <label className={styles.label}>IdP SSO URL</label>
            <input
              className={styles.input}
              placeholder="https://login.microsoftonline.com/&lt;tenant-id&gt;/saml2"
              value={idpSsoUrl}
              onChange={(e) => setIdpSsoUrl(e.target.value)}
            />
          </div>
          <div>
            <label className={styles.label}>IdP Signing Certificate (PEM body, no header/footer)</label>
            <textarea
              className={`${styles.input} h-24 font-mono text-xs`}
              value={idpCert}
              onChange={(e) => setIdpCert(e.target.value)}
            />
          </div>
          <div>
            <label className={styles.label}>App Role → capki role mapping (one per line: claim=role)</label>
            <textarea
              className={`${styles.input} h-24 font-mono text-xs`}
              placeholder={'CA.Admin=admin\nCA.Operator=operator\nCA.Auditor=auditor'}
              value={roleMapText}
              onChange={(e) => setRoleMapText(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-3">
            <button type="submit" disabled={busy} className={styles.button}>
              Save
            </button>
            {saved && <span className={styles.successText}>Saved.</span>}
          </div>
        </form>
      </div>
    </div>
  )
}
