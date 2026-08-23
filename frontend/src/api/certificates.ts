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

export interface RenewCertificateResponse extends IssueCertificateResponse {
  predecessor_superseded: boolean
}

export interface CertificateFilters {
  q?: string
  status?: string
  profile_code?: string
  issued_via?: string
  valid?: boolean
}

export const certificatesApi = {
  list: (filters?: CertificateFilters) => {
    const params = new URLSearchParams()
    if (filters?.q) params.set('q', filters.q)
    if (filters?.status) params.set('status', filters.status)
    if (filters?.profile_code) params.set('profile_code', filters.profile_code)
    if (filters?.issued_via) params.set('issued_via', filters.issued_via)
    if (filters?.valid !== undefined) params.set('valid', String(filters.valid))
    const qs = params.toString()
    return apiClient.get<CertificateSummary[]>(`/api/v1/certificates${qs ? `?${qs}` : ''}`)
  },
  issue: (payload: { csr_pem: string; profile_code: string; validity_days?: number }) =>
    apiClient.post<IssueCertificateResponse>('/api/v1/certificates', payload),
  revoke: (id: number, reason: string) =>
    apiClient.post<CertificateSummary>(`/api/v1/certificates/${id}/revoke`, { reason }),
  renew: (id: number, payload: { csr_pem: string; validity_days?: number }) =>
    apiClient.post<RenewCertificateResponse>(`/api/v1/certificates/${id}/renew`, payload),
}
