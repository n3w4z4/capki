import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { apiClient, ApiError } from '../api/client'

export interface Actor {
  username: string
  role: string | null
  permissions: string[]
  auth_method: string
}

interface AuthContextValue {
  actor: Actor | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [actor, setActor] = useState<Actor | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const me = await apiClient.get<Actor>('/api/v1/auth/me')
      setActor(me)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setActor(null)
      } else {
        throw err
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const login = useCallback(async (username: string, password: string) => {
    const me = await apiClient.post<Actor>('/api/v1/auth/login', { username, password })
    setActor(me)
  }, [])

  const logout = useCallback(async () => {
    await apiClient.post('/api/v1/auth/logout')
    setActor(null)
  }, [])

  return (
    <AuthContext.Provider value={{ actor, loading, login, logout }}>{children}</AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return ctx
}
