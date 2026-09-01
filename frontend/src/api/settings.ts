import { apiClient } from './client'

export interface SamlConfig {
  enabled: boolean
  idp_entity_id: string | null
  idp_sso_url: string | null
  idp_slo_url: string | null
  idp_x509_cert: string | null
  sp_entity_id: string | null
  group_role_map: Record<string, string> | null
}

export interface TlsStatus {
  source: string
  not_before: string
  not_after: string
}

export interface TlsReplaceResult {
  status: TlsStatus
  restarting: boolean
}

export interface NotificationConfig {
  expiry_warning_days: number
  email_enabled: boolean
  smtp_host: string | null
  smtp_port: number
  smtp_username: string | null
  smtp_password_set: boolean
  smtp_use_tls: boolean
  smtp_from_address: string | null
  telegram_enabled: boolean
  telegram_bot_token_set: boolean
}

export interface NotificationConfigUpdate {
  expiry_warning_days?: number
  email_enabled?: boolean
  smtp_host?: string
  smtp_port?: number
  smtp_username?: string
  smtp_password?: string
  smtp_use_tls?: boolean
  smtp_from_address?: string
  telegram_enabled?: boolean
  telegram_bot_token?: string
}

export interface NotificationTestResult {
  email_sent: boolean
  email_error: string | null
  telegram_sent: boolean
  telegram_error: string | null
}

export interface LogForwardingConfig {
  app_log_min_level: string
  hec_enabled: boolean
  hec_send_app_logs: boolean
  hec_send_audit_logs: boolean
  hec_url: string | null
  hec_token_set: boolean
  hec_source: string | null
  hec_sourcetype: string | null
  hec_index: string | null
  hec_verify_tls: boolean
  syslog_enabled: boolean
  syslog_send_app_logs: boolean
  syslog_send_audit_logs: boolean
  syslog_host: string | null
  syslog_port: number
  syslog_protocol: string
  syslog_facility: number
}

export interface LogForwardingConfigUpdate {
  app_log_min_level?: string
  hec_enabled?: boolean
  hec_send_app_logs?: boolean
  hec_send_audit_logs?: boolean
  hec_url?: string
  hec_token?: string
  hec_source?: string
  hec_sourcetype?: string
  hec_index?: string
  hec_verify_tls?: boolean
  syslog_enabled?: boolean
  syslog_send_app_logs?: boolean
  syslog_send_audit_logs?: boolean
  syslog_host?: string
  syslog_port?: number
  syslog_protocol?: string
  syslog_facility?: number
}

export interface LogForwardingTestResult {
  hec_sent: boolean
  hec_error: string | null
  syslog_sent: boolean
  syslog_error: string | null
}

export interface TrustedCa {
  id: number
  label: string | null
  subject_dn: string
  issuer_dn: string
  serial_hex: string
  sha256_fingerprint: string
  not_before: string
  not_after: string
  is_self_signed: boolean
  enabled: boolean
  added_at: string
}

export interface TrustedCaUrlTestResult {
  ok: boolean
  error: string | null
}

export const settingsApi = {
  getSaml: () => apiClient.get<SamlConfig>('/api/v1/settings/saml'),
  updateSaml: (payload: Partial<SamlConfig>) =>
    apiClient.patch<SamlConfig>('/api/v1/settings/saml', payload),
  getTls: () => apiClient.get<TlsStatus>('/api/v1/settings/tls'),
  uploadTls: (certificate_pem: string, private_key_pem: string) =>
    apiClient.post<TlsReplaceResult>('/api/v1/settings/tls/upload', {
      certificate_pem,
      private_key_pem,
    }),
  issueTlsFromIntermediate: () =>
    apiClient.post<TlsReplaceResult>('/api/v1/settings/tls/issue-from-intermediate'),
  getNotifications: () => apiClient.get<NotificationConfig>('/api/v1/settings/notifications'),
  updateNotifications: (payload: NotificationConfigUpdate) =>
    apiClient.patch<NotificationConfig>('/api/v1/settings/notifications', payload),
  testNotifications: () =>
    apiClient.post<NotificationTestResult>('/api/v1/settings/notifications/test'),
  getLogForwarding: () => apiClient.get<LogForwardingConfig>('/api/v1/settings/log-forwarding'),
  updateLogForwarding: (payload: LogForwardingConfigUpdate) =>
    apiClient.patch<LogForwardingConfig>('/api/v1/settings/log-forwarding', payload),
  testLogForwarding: () =>
    apiClient.post<LogForwardingTestResult>('/api/v1/settings/log-forwarding/test'),
  getTrustedCas: () => apiClient.get<TrustedCa[]>('/api/v1/settings/trusted-cas'),
  addTrustedCa: (pem: string, label?: string) =>
    apiClient.post<TrustedCa[]>('/api/v1/settings/trusted-cas', { pem, label: label || null }),
  updateTrustedCa: (id: number, payload: { enabled?: boolean; label?: string }) =>
    apiClient.patch<TrustedCa>(`/api/v1/settings/trusted-cas/${id}`, payload),
  deleteTrustedCa: (id: number) =>
    apiClient.delete<void>(`/api/v1/settings/trusted-cas/${id}`),
  testTrustedCaUrl: (url: string) =>
    apiClient.post<TrustedCaUrlTestResult>('/api/v1/settings/trusted-cas/test', { url }),
}
