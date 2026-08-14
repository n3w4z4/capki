import { apiClient } from './client'

export interface CertificateSummary {
  id: number
  serial_hex: string
  profile_code: string
  subject_dn: string
  sans: string[]
  status: string
  not_before: string
  not_after: string
  issued_via: string
  requested_by_user_id: number | null
}

export interface IssueCertificateResponse extends CertificateSummary {
  certificate_pem: string
  chain_pem: string
}

export const certificatesApi = {
  list: (q?: string) =>
    apiClient.get<CertificateSummary[]>(
      `/api/v1/certificates${q ? `?q=${encodeURIComponent(q)}` : ''}`
    ),
  issue: (payload: { csr_pem: string; profile_code: string; validity_days?: number }) =>
    apiClient.post<IssueCertificateResponse>('/api/v1/certificates', payload),
  revoke: (id: number, reason: string) =>
    apiClient.post<CertificateSummary>(`/api/v1/certificates/${id}/revoke`, { reason }),
}
