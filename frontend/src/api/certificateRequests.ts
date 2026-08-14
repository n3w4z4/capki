import { apiClient } from './client'

export interface CertRequestSummary {
  id: number
  subject_dn: string
  profile_code: string
  status: 'pending' | 'approved' | 'rejected'
  requested_by_user_id: number
  requested_by_username: string | null
  created_at: string
  reviewed_at: string | null
  rejection_reason: string | null
  certificate_id: number | null
}

export const certificateRequestsApi = {
  submit: (payload: { csr_pem: string; profile_code: string }) =>
    apiClient.post<CertRequestSummary>('/api/v1/certificate-requests', payload),
  mine: () => apiClient.get<CertRequestSummary[]>('/api/v1/certificate-requests/mine'),
  pending: () => apiClient.get<CertRequestSummary[]>('/api/v1/certificate-requests/pending'),
  approve: (id: number, validityDays?: number) =>
    apiClient.post<CertRequestSummary>(`/api/v1/certificate-requests/${id}/approve`, {
      validity_days: validityDays,
    }),
  reject: (id: number, reason: string) =>
    apiClient.post<CertRequestSummary>(`/api/v1/certificate-requests/${id}/reject`, { reason }),
}
