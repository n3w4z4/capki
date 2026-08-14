import { apiClient } from './client'

export interface UserSummary {
  id: number
  username: string
  email: string
  auth_source: string
  role: string | null
  is_active: boolean
}

export interface RoleSummary {
  name: string
  description: string | null
}

export const usersApi = {
  list: () => apiClient.get<UserSummary[]>('/api/v1/users'),
  listRoles: () => apiClient.get<RoleSummary[]>('/api/v1/users/roles'),
  create: (payload: { username: string; email: string; password: string; role: string }) =>
    apiClient.post<UserSummary>('/api/v1/users', payload),
  update: (
    id: number,
    payload: { role?: string; is_active?: boolean; new_password?: string }
  ) => apiClient.patch<UserSummary>(`/api/v1/users/${id}`, payload),
  deactivate: (id: number) => apiClient.delete<UserSummary>(`/api/v1/users/${id}`),
}
