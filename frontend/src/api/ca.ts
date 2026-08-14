import { apiClient } from './client'

export interface CaSummary {
  id: number
  type: 'root' | 'intermediate'
  name: string
  subject_dn: string
  status: string
  not_before: string | null
  not_after: string | null
}

export interface RootStatus {
  initialized: boolean
  unlocked: boolean
}

export const caApi = {
  list: () => apiClient.get<CaSummary[]>('/api/v1/ca'),
  rootStatus: () => apiClient.get<RootStatus>('/api/v1/ca/root/status'),
  initRoot: (payload: { common_name: string; organization_name?: string; passphrase: string }) =>
    apiClient.post<CaSummary>('/api/v1/ca/root/init', payload),
  initIntermediate: (payload: { common_name: string; organization_name?: string }) =>
    apiClient.post<CaSummary>('/api/v1/ca/intermediate/init', payload),
  unlockRoot: (passphrase: string) =>
    apiClient.post<RootStatus>('/api/v1/ca/root/unlock', { passphrase }),
  lockRoot: () => apiClient.post<RootStatus>('/api/v1/ca/root/lock'),
}
