import { apiClient } from './client'

export interface GeneratedCsr {
  private_key_pem: string
  csr_pem: string
  encrypted: boolean
}

export const csrApi = {
  generate: (payload: {
    common_name: string
    organization_name?: string
    sans: string[]
    passphrase?: string
  }) => apiClient.post<GeneratedCsr>('/api/v1/csr/generate', payload),
}
