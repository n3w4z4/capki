import { useState } from 'react'
import { csrApi } from '../api/csr'
import { ApiError } from '../api/client'
import { styles } from '../ui/styles'

interface Props {
  onGenerated: (csrPem: string) => void
}

const MIN_PASSPHRASE_LEN = 8

function downloadText(text: string, filename: string): void {
  const blob = new Blob([text], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export default function CsrGenerator({ onGenerated }: Props) {
  const [open, setOpen] = useState(false)
  const [commonName, setCommonName] = useState('')
  const [organization, setOrganization] = useState('')
  const [sansText, setSansText] = useState('')
  const [encryptKey, setEncryptKey] = useState(false)
  const [passphrase, setPassphrase] = useState('')
  const [passphraseConfirm, setPassphraseConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [privateKeyPem, setPrivateKeyPem] = useState<string | null>(null)
  const [wasEncrypted, setWasEncrypted] = useState(false)
  const [savedConfirmed, setSavedConfirmed] = useState(false)

  async function handleGenerate() {
    if (!commonName.trim()) {
      setError('Common name is required.')
      return
    }
    if (encryptKey) {
      if (passphrase.length < MIN_PASSPHRASE_LEN) {
        setError(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters.`)
        return
      }
      if (passphrase !== passphraseConfirm) {
        setError('Passphrases do not match.')
        return
      }
    }
    setError(null)
    setBusy(true)
    try {
      const sans = sansText
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      const result = await csrApi.generate({
        common_name: commonName,
        organization_name: organization || undefined,
        sans,
        passphrase: encryptKey ? passphrase : undefined,
      })
      setPrivateKeyPem(result.private_key_pem)
      setWasEncrypted(result.encrypted)
      setSavedConfirmed(false)
      setPassphrase('')
      setPassphraseConfirm('')
      onGenerated(result.csr_pem)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Generation failed.')
    } finally {
      setBusy(false)
    }
  }

  function handleDismiss() {
    setPrivateKeyPem(null)
    setOpen(false)
  }

  if (!open) {
    return (
      <div>
        <button type="button" onClick={() => setOpen(true)} className={styles.link}>
          Don't have a CSR? Generate a key pair for me instead
        </button>
      </div>
    )
  }

  if (privateKeyPem) {
    return (
      <div className="space-y-3 rounded-md border border-amber-300 bg-amber-50 p-4">
        <p className="text-sm font-semibold text-amber-800">
          {wasEncrypted
            ? "Save this private key now — it's encrypted with the passphrase you chose, but the app never stores it and can't show it again."
            : 'Save this private key now — it is never stored by the app and cannot be shown again.'}
        </p>
        <textarea
          readOnly
          className={`${styles.input} mt-0 h-32 font-mono text-xs`}
          value={privateKeyPem}
          onFocus={(e) => e.target.select()}
        />
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => downloadText(privateKeyPem, `${commonName || 'private-key'}.key.pem`)}
            className={styles.button}
          >
            Download private key
          </button>
          <label className="flex items-center gap-2 text-sm text-amber-800">
            <input
              type="checkbox"
              checked={savedConfirmed}
              onChange={(e) => setSavedConfirmed(e.target.checked)}
            />
            I've saved it
          </label>
          <button
            type="button"
            onClick={handleDismiss}
            disabled={!savedConfirmed}
            className={`${styles.buttonSecondary} disabled:cursor-not-allowed disabled:opacity-50`}
          >
            Done, discard from screen
          </button>
        </div>
        <p className={styles.mutedXs}>
          The matching CSR has been filled in below — submit it to get the certificate.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4 rounded-md border border-gray-200 bg-gray-50 p-4">
      {error && <p className={styles.errorBanner}>{error}</p>}
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className={styles.label}>Common name (e.g. FQDN or your name)</label>
            <input
              className={styles.input}
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
            />
          </div>
          <div>
            <label className={styles.label}>Organization</label>
            <input
              className={styles.input}
              placeholder="Example Org"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
            />
          </div>
        </div>
        <div>
          <label className={styles.label}>
            Subject alternative names (comma-separated — DNS names, IPs, or an email)
          </label>
          <input
            className={styles.input}
            placeholder="svc.example.org, www.svc.example.org, 10.0.0.5"
            value={sansText}
            onChange={(e) => setSansText(e.target.value)}
          />
        </div>

        <label className="flex items-center gap-2 text-sm text-gray-700">
          <input
            type="checkbox"
            checked={encryptKey}
            onChange={(e) => setEncryptKey(e.target.checked)}
          />
          Encrypt the private key with a passphrase
        </label>

        {encryptKey && (
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={styles.label}>Passphrase</label>
              <input
                type="password"
                className={styles.input}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                minLength={MIN_PASSPHRASE_LEN}
              />
            </div>
            <div>
              <label className={styles.label}>Confirm passphrase</label>
              <input
                type="password"
                className={styles.input}
                value={passphraseConfirm}
                onChange={(e) => setPassphraseConfirm(e.target.value)}
                minLength={MIN_PASSPHRASE_LEN}
              />
            </div>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button type="button" onClick={handleGenerate} disabled={busy} className={styles.button}>
            Generate key pair + CSR
          </button>
          <button type="button" onClick={() => setOpen(false)} className={styles.buttonSecondary}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}
