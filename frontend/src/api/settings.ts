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
}
