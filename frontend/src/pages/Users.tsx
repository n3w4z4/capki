import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { usersApi, type RoleSummary, type UserSummary } from '../api/users'
import { ApiError } from '../api/client'
import { badgeClass, styles } from '../ui/styles'
import { useAuth } from '../auth/AuthContext'

export default function Users() {
  const { actor } = useAuth()
  const [users, setUsers] = useState<UserSummary[]>([])
  const [roles, setRoles] = useState<RoleSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('')

  const refresh = useCallback(async () => {
    const [u, r] = await Promise.all([usersApi.list(), usersApi.listRoles()])
    setUsers(u)
    setRoles(r)
    setRole((prev) => prev || r[0]?.name || '')
  }, [])

  useEffect(() => {
    refresh()
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load users.'))
      .finally(() => setLoading(false))
  }, [refresh])

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await usersApi.create({ username, email, password, role })
      setUsername('')
      setEmail('')
      setPassword('')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create user.')
    } finally {
      setBusy(false)
    }
  }

  async function handleRoleChange(id: number, newRole: string) {
    setError(null)
    setBusy(true)
    try {
      await usersApi.update(id, { role: newRole })
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update role.')
    } finally {
      setBusy(false)
    }
  }

  async function handleToggleActive(user: UserSummary) {
    setError(null)
    setBusy(true)
    try {
      if (user.is_active) {
        await usersApi.deactivate(user.id)
      } else {
        await usersApi.update(user.id, { is_active: true })
      }
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update user.')
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return <p className={styles.muted}>Loading…</p>
  }

  return (
    <div className="space-y-6">
      {error && <p className={styles.errorBanner}>{error}</p>}

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Create User</h2>
        <form className="grid grid-cols-2 gap-4" onSubmit={handleCreate}>
          <div>
            <label className={styles.label}>Username</label>
            <input
              className={styles.input}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div>
            <label className={styles.label}>Email</label>
            <input
              type="email"
              className={styles.input}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div>
            <label className={styles.label}>Password</label>
            <input
              type="password"
              className={styles.input}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={8}
              required
            />
          </div>
          <div>
            <label className={styles.label}>Role</label>
            <select className={styles.input} value={role} onChange={(e) => setRole(e.target.value)}>
              {roles.map((r) => (
                <option key={r.name} value={r.name}>
                  {r.name}
                  {r.description ? ` — ${r.description}` : ''}
                </option>
              ))}
            </select>
          </div>
          <div className="col-span-2">
            <button type="submit" disabled={busy} className={styles.button}>
              Create user
            </button>
          </div>
        </form>
      </div>

      <div className={styles.card}>
        <h2 className={`mb-4 ${styles.sectionTitle}`}>Users</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className={styles.tableHeadRow}>
                <th className="py-2 pr-4 font-medium">Username</th>
                <th className="py-2 pr-4 font-medium">Email</th>
                <th className="py-2 pr-4 font-medium">Auth</th>
                <th className="py-2 pr-4 font-medium">Role</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className={styles.tableRow}>
                  <td className="py-2 pr-4 text-gray-900">{u.username}</td>
                  <td className="py-2 pr-4 text-gray-700">{u.email}</td>
                  <td className="py-2 pr-4 text-gray-700">{u.auth_source}</td>
                  <td className="py-2 pr-4">
                    <select
                      className={`${styles.input} mt-0 py-1`}
                      value={u.role ?? ''}
                      disabled={busy}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    >
                      {roles.map((r) => (
                        <option key={r.name} value={r.name}>
                          {r.name}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="py-2 pr-4">
                    <span className={badgeClass(u.is_active ? 'green' : 'gray')}>
                      {u.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="py-2 text-right">
                    <button
                      onClick={() => handleToggleActive(u)}
                      disabled={busy || u.username === actor?.username}
                      className={u.is_active ? styles.linkDanger : styles.link}
                    >
                      {u.is_active ? 'Deactivate' : 'Reactivate'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
