import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  settingsApi,
  type LogForwardingTestResult,
  type NotificationTestResult,
  type TlsStatus,
} from '../api/settings'
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

const TEST_ERROR_MESSAGES: Record<string, string> = {
  email_notifications_disabled_in_saved_settings: 'email notifications are disabled',
  telegram_notifications_disabled_in_saved_settings: 'Telegram notifications are disabled',
  no_email_on_account: 'your account has no email address',
  no_telegram_chat_id_on_account: "your account's Telegram Chat ID isn't set (Users tab)",
  hec_disabled_in_saved_settings: 'HEC forwarding is disabled',
  syslog_disabled_in_saved_settings: 'Syslog forwarding is disabled',
}

function describeTestError(code: string | null): string {
  if (!code) return 'unknown error'
  return TEST_ERROR_MESSAGES[code] ?? code
}

const LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const SYSLOG_PROTOCOLS = [
  { value: 'udp', label: 'UDP' },
  { value: 'tcp', label: 'TCP' },
  { value: 'tcp_tls', label: 'TCP + TLS' },
]

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

function NotificationsSettingsCard() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)
  const [testResult, setTestResult] = useState<NotificationTestResult | null>(null)
  const [testing, setTesting] = useState(false)

  const [expiryWarningDays, setExpiryWarningDays] = useState(30)
  const [emailEnabled, setEmailEnabled] = useState(false)
  const [smtpHost, setSmtpHost] = useState('')
  const [smtpPort, setSmtpPort] = useState(587)
  const [smtpUsername, setSmtpUsername] = useState('')
  const [smtpPassword, setSmtpPassword] = useState('')
  const [smtpPasswordSet, setSmtpPasswordSet] = useState(false)
  const [smtpUseTls, setSmtpUseTls] = useState(true)
  const [smtpFromAddress, setSmtpFromAddress] = useState('')
  const [telegramEnabled, setTelegramEnabled] = useState(false)
  const [telegramBotToken, setTelegramBotToken] = useState('')
  const [telegramBotTokenSet, setTelegramBotTokenSet] = useState(false)

  const refresh = useCallback(async () => {
    const c = await settingsApi.getNotifications()
    setExpiryWarningDays(c.expiry_warning_days)
    setEmailEnabled(c.email_enabled)
    setSmtpHost(c.smtp_host ?? '')
    setSmtpPort(c.smtp_port)
    setSmtpUsername(c.smtp_username ?? '')
    setSmtpPasswordSet(c.smtp_password_set)
    setSmtpUseTls(c.smtp_use_tls)
    setSmtpFromAddress(c.smtp_from_address ?? '')
    setTelegramEnabled(c.telegram_enabled)
    setTelegramBotTokenSet(c.telegram_bot_token_set)
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load settings.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function saveConfig() {
    await settingsApi.updateNotifications({
      expiry_warning_days: expiryWarningDays,
      email_enabled: emailEnabled,
      smtp_host: smtpHost,
      smtp_port: smtpPort,
      smtp_username: smtpUsername,
      smtp_password: smtpPassword || undefined,
      smtp_use_tls: smtpUseTls,
      smtp_from_address: smtpFromAddress,
      telegram_enabled: telegramEnabled,
      telegram_bot_token: telegramBotToken || undefined,
    })
    setSmtpPassword('')
    setTelegramBotToken('')
    await refresh()
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setSaved(false)
    setTestResult(null)
    setBusy(true)
    try {
      await saveConfig()
      setSaved(true)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save settings.')
    } finally {
      setBusy(false)
    }
  }

  async function handleTest() {
    setError(null)
    setSaved(false)
    setTestResult(null)
    setTesting(true)
    try {
      // Save first so the test actually exercises whatever's currently in
      // the form, not whatever was last persisted — otherwise toggling a
      // channel on and testing before hitting Save silently tests against
      // the old (disabled) saved config.
      await saveConfig()
      setTestResult(await settingsApi.testNotifications())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Test notification failed.')
    } finally {
      setTesting(false)
    }
  }

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  return (
    <div className={styles.card}>
      <h2 className={`mb-4 ${styles.sectionTitle}`}>Certificate Expiry Notifications</h2>
      <p className={`mb-4 ${styles.mutedXs}`}>
        Once a day, any valid certificate expiring within the warning window below emails and/or
        Telegrams the user who requested it — see each user's Telegram Chat ID field on the Users tab
        (message your bot, then look it up via @userinfobot or the bot's own /start reply).
      </p>
      <form className="space-y-6" onSubmit={handleSave}>
        <div>
          <label className={styles.label}>Warn this many days before expiry</label>
          <input
            type="number"
            min={1}
            className={`${styles.input} w-32`}
            value={expiryWarningDays}
            onChange={(e) => setExpiryWarningDays(Number(e.target.value))}
          />
        </div>

        <div className="space-y-4 border-t border-gray-200 pt-4">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={emailEnabled}
              onChange={(e) => setEmailEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            Enable email notifications
          </label>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={styles.label}>SMTP host</label>
              <input
                className={styles.input}
                value={smtpHost}
                onChange={(e) => setSmtpHost(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>SMTP port</label>
              <input
                type="number"
                className={styles.input}
                value={smtpPort}
                onChange={(e) => setSmtpPort(Number(e.target.value))}
              />
            </div>
            <div>
              <label className={styles.label}>SMTP username</label>
              <input
                className={styles.input}
                value={smtpUsername}
                onChange={(e) => setSmtpUsername(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>SMTP password{smtpPasswordSet ? ' (set — leave blank to keep)' : ''}</label>
              <input
                type="password"
                className={styles.input}
                value={smtpPassword}
                onChange={(e) => setSmtpPassword(e.target.value)}
                placeholder={smtpPasswordSet ? '••••••••' : ''}
              />
            </div>
            <div className="col-span-2">
              <label className={styles.label}>From address</label>
              <input
                type="email"
                className={styles.input}
                value={smtpFromAddress}
                onChange={(e) => setSmtpFromAddress(e.target.value)}
              />
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={smtpUseTls}
              onChange={(e) => setSmtpUseTls(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            Use STARTTLS
          </label>
        </div>

        <div className="space-y-4 border-t border-gray-200 pt-4">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={telegramEnabled}
              onChange={(e) => setTelegramEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            Enable Telegram notifications
          </label>
          <div>
            <label className={styles.label}>
              Bot token{telegramBotTokenSet ? ' (set — leave blank to keep)' : ''}
            </label>
            <input
              type="password"
              className={styles.input}
              value={telegramBotToken}
              onChange={(e) => setTelegramBotToken(e.target.value)}
              placeholder={telegramBotTokenSet ? '••••••••' : '123456789:AA...'}
            />
          </div>
        </div>

        {error && <p className={styles.errorBanner}>{error}</p>}
        {testResult && (
          <p className={testResult.email_error || testResult.telegram_error ? styles.warningBanner : styles.successText}>
            {emailEnabled &&
              (testResult.email_sent
                ? 'Email test sent. '
                : `Email test failed: ${describeTestError(testResult.email_error)}. `)}
            {telegramEnabled &&
              (testResult.telegram_sent
                ? 'Telegram test sent.'
                : `Telegram test failed: ${describeTestError(testResult.telegram_error)}.`)}
          </p>
        )}

        <div className="flex items-center gap-3">
          <button type="submit" disabled={busy} className={styles.button}>
            Save
          </button>
          <button
            type="button"
            disabled={testing || (!emailEnabled && !telegramEnabled)}
            onClick={handleTest}
            className={styles.buttonSecondary}
          >
            Send test notification to me
          </button>
          {saved && <span className={styles.successText}>Saved.</span>}
        </div>
      </form>
    </div>
  )
}

function LogForwardingSettingsCard() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)
  const [testResult, setTestResult] = useState<LogForwardingTestResult | null>(null)
  const [testing, setTesting] = useState(false)

  const [appLogMinLevel, setAppLogMinLevel] = useState('WARNING')

  const [hecEnabled, setHecEnabled] = useState(false)
  const [hecSendAppLogs, setHecSendAppLogs] = useState(true)
  const [hecSendAuditLogs, setHecSendAuditLogs] = useState(true)
  const [hecUrl, setHecUrl] = useState('')
  const [hecToken, setHecToken] = useState('')
  const [hecTokenSet, setHecTokenSet] = useState(false)
  const [hecSource, setHecSource] = useState('')
  const [hecSourcetype, setHecSourcetype] = useState('')
  const [hecIndex, setHecIndex] = useState('')
  const [hecVerifyTls, setHecVerifyTls] = useState(true)

  const [syslogEnabled, setSyslogEnabled] = useState(false)
  const [syslogSendAppLogs, setSyslogSendAppLogs] = useState(true)
  const [syslogSendAuditLogs, setSyslogSendAuditLogs] = useState(true)
  const [syslogHost, setSyslogHost] = useState('')
  const [syslogPort, setSyslogPort] = useState(514)
  const [syslogProtocol, setSyslogProtocol] = useState('udp')
  const [syslogFacility, setSyslogFacility] = useState(16)

  const refresh = useCallback(async () => {
    const c = await settingsApi.getLogForwarding()
    setAppLogMinLevel(c.app_log_min_level)
    setHecEnabled(c.hec_enabled)
    setHecSendAppLogs(c.hec_send_app_logs)
    setHecSendAuditLogs(c.hec_send_audit_logs)
    setHecUrl(c.hec_url ?? '')
    setHecTokenSet(c.hec_token_set)
    setHecSource(c.hec_source ?? '')
    setHecSourcetype(c.hec_sourcetype ?? '')
    setHecIndex(c.hec_index ?? '')
    setHecVerifyTls(c.hec_verify_tls)
    setSyslogEnabled(c.syslog_enabled)
    setSyslogSendAppLogs(c.syslog_send_app_logs)
    setSyslogSendAuditLogs(c.syslog_send_audit_logs)
    setSyslogHost(c.syslog_host ?? '')
    setSyslogPort(c.syslog_port)
    setSyslogProtocol(c.syslog_protocol)
    setSyslogFacility(c.syslog_facility)
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load settings.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function saveConfig() {
    await settingsApi.updateLogForwarding({
      app_log_min_level: appLogMinLevel,
      hec_enabled: hecEnabled,
      hec_send_app_logs: hecSendAppLogs,
      hec_send_audit_logs: hecSendAuditLogs,
      hec_url: hecUrl,
      hec_token: hecToken || undefined,
      hec_source: hecSource,
      hec_sourcetype: hecSourcetype,
      hec_index: hecIndex,
      hec_verify_tls: hecVerifyTls,
      syslog_enabled: syslogEnabled,
      syslog_send_app_logs: syslogSendAppLogs,
      syslog_send_audit_logs: syslogSendAuditLogs,
      syslog_host: syslogHost,
      syslog_port: syslogPort,
      syslog_protocol: syslogProtocol,
      syslog_facility: syslogFacility,
    })
    setHecToken('')
    await refresh()
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setSaved(false)
    setTestResult(null)
    setBusy(true)
    try {
      await saveConfig()
      setSaved(true)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save settings.')
    } finally {
      setBusy(false)
    }
  }

  async function handleTest() {
    setError(null)
    setSaved(false)
    setTestResult(null)
    setTesting(true)
    try {
      // Same reasoning as the notifications test button: save first so the
      // test actually exercises the form's current values.
      await saveConfig()
      setTestResult(await settingsApi.testLogForwarding())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Test event failed.')
    } finally {
      setTesting(false)
    }
  }

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  return (
    <div className={styles.card}>
      <h2 className={`mb-4 ${styles.sectionTitle}`}>External Log Forwarding</h2>
      <p className={`mb-4 ${styles.mutedXs}`}>
        Mirrors application logs and/or audit-log entries (JSON, UTC timestamps with offset, audit
        entries include the requester's IP) to a Splunk/Cribl HTTP Event Collector and/or a syslog
        receiver. Delivery is best-effort and asynchronous — a slow or unreachable collector never blocks
        cert issuance or logins, but events can be dropped if the collector is down for a while or the
        app restarts.
      </p>
      <form className="space-y-6" onSubmit={handleSave}>
        <div>
          <label className={styles.label}>Minimum level for application logs</label>
          <select
            className={`${styles.input} w-40`}
            value={appLogMinLevel}
            onChange={(e) => setAppLogMinLevel(e.target.value)}
          >
            {LOG_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
          <p className={`mt-1 ${styles.mutedXs}`}>
            Audit-log entries (cert issued, user created, etc.) always forward regardless of this
            setting — they're already discrete, meaningful events, not chatty.
          </p>
        </div>

        <div className="space-y-4 border-t border-gray-200 pt-4">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={hecEnabled}
              onChange={(e) => setHecEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            Enable HTTP Event Collector (Splunk / Cribl)
          </label>
          <div className="flex gap-6">
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                checked={hecSendAppLogs}
                onChange={(e) => setHecSendAppLogs(e.target.checked)}
                className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
              />
              Application logs
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                checked={hecSendAuditLogs}
                onChange={(e) => setHecSendAuditLogs(e.target.checked)}
                className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
              />
              Audit logs
            </label>
          </div>
          <div>
            <label className={styles.label}>HEC URL</label>
            <input
              className={styles.input}
              placeholder="https://cribl.internal:8088/services/collector/event"
              value={hecUrl}
              onChange={(e) => setHecUrl(e.target.value)}
            />
          </div>
          <div>
            <label className={styles.label}>
              HEC token{hecTokenSet ? ' (set — leave blank to keep)' : ''}
            </label>
            <input
              type="password"
              className={styles.input}
              value={hecToken}
              onChange={(e) => setHecToken(e.target.value)}
              placeholder={hecTokenSet ? '••••••••' : ''}
            />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className={styles.label}>Source (optional)</label>
              <input
                className={styles.input}
                placeholder="capki"
                value={hecSource}
                onChange={(e) => setHecSource(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>Sourcetype (optional)</label>
              <input
                className={styles.input}
                placeholder="_json"
                value={hecSourcetype}
                onChange={(e) => setHecSourcetype(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>Index (optional)</label>
              <input
                className={styles.input}
                value={hecIndex}
                onChange={(e) => setHecIndex(e.target.value)}
              />
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={hecVerifyTls}
              onChange={(e) => setHecVerifyTls(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            Verify TLS certificate (turn off only for a self-signed/internal collector you trust)
          </label>
        </div>

        <div className="space-y-4 border-t border-gray-200 pt-4">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={syslogEnabled}
              onChange={(e) => setSyslogEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            Enable syslog (RFC 5424, JSON message body)
          </label>
          <div className="flex gap-6">
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                checked={syslogSendAppLogs}
                onChange={(e) => setSyslogSendAppLogs(e.target.checked)}
                className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
              />
              Application logs
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                checked={syslogSendAuditLogs}
                onChange={(e) => setSyslogSendAuditLogs(e.target.checked)}
                className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
              />
              Audit logs
            </label>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={styles.label}>Host</label>
              <input
                className={styles.input}
                value={syslogHost}
                onChange={(e) => setSyslogHost(e.target.value)}
              />
            </div>
            <div>
              <label className={styles.label}>Port</label>
              <input
                type="number"
                className={styles.input}
                value={syslogPort}
                onChange={(e) => setSyslogPort(Number(e.target.value))}
              />
            </div>
            <div>
              <label className={styles.label}>Protocol</label>
              <select
                className={styles.input}
                value={syslogProtocol}
                onChange={(e) => setSyslogProtocol(e.target.value)}
              >
                {SYSLOG_PROTOCOLS.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={styles.label}>Facility</label>
              <input
                type="number"
                min={0}
                max={23}
                className={styles.input}
                value={syslogFacility}
                onChange={(e) => setSyslogFacility(Number(e.target.value))}
              />
            </div>
          </div>
        </div>

        {error && <p className={styles.errorBanner}>{error}</p>}
        {testResult && (
          <p className={testResult.hec_error || testResult.syslog_error ? styles.warningBanner : styles.successText}>
            {hecEnabled &&
              (testResult.hec_sent
                ? 'HEC test event sent. '
                : `HEC test failed: ${describeTestError(testResult.hec_error)}. `)}
            {syslogEnabled &&
              (testResult.syslog_sent
                ? 'Syslog test event sent.'
                : `Syslog test failed: ${describeTestError(testResult.syslog_error)}.`)}
          </p>
        )}

        <div className="flex items-center gap-3">
          <button type="submit" disabled={busy} className={styles.button}>
            Save
          </button>
          <button
            type="button"
            disabled={testing || (!hecEnabled && !syslogEnabled)}
            onClick={handleTest}
            className={styles.buttonSecondary}
          >
            Send test event
          </button>
          {saved && <span className={styles.successText}>Saved.</span>}
        </div>
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
      <NotificationsSettingsCard />
      <LogForwardingSettingsCard />

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
