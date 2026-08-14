import { apiClient } from './client'

export interface AuditLogEntry {
  id: number
  timestamp: string
  actor_type: string
  actor_username: string | null
  action: string
  target_type: string | null
  target_id: string | null
  success: boolean
  detail: Record<string, unknown> | null
}

export const auditApi = {
  list: (limit = 100) => apiClient.get<AuditLogEntry[]>(`/api/v1/audit-log?limit=${limit}`),
}
