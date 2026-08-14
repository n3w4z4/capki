import { apiClient } from './client'

export interface TokenSummary {
  id: number
  name: string
  token_prefix: string
  created_at: string
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
}

export interface CreateTokenResponse extends TokenSummary {
  token: string
}

export const tokensApi = {
  list: () => apiClient.get<TokenSummary[]>('/api/v1/tokens'),
  create: (name: string) => apiClient.post<CreateTokenResponse>('/api/v1/tokens', { name }),
  revoke: (id: number) => apiClient.delete<void>(`/api/v1/tokens/${id}`),
}
