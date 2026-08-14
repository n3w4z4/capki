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
}
