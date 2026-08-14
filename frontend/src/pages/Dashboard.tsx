import { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import CertificateAuthorities from './CertificateAuthorities'
import Certificates from './Certificates'
import MyCertificateRequests from './MyCertificateRequests'
import Approvals from './Approvals'
import Tokens from './Tokens'
import Users from './Users'
import Settings from './Settings'
import AuditLog from './AuditLog'
import { styles } from '../ui/styles'

// `anyOf` permissions are OR-matched: the tab shows if the actor holds at
// least one of them. Certificates is visible to both cert:read (full
// management) and cert:request (self-service only) — which one determines
// what actually renders, in `TAB_CONTENT` below.
const ALL_TABS = [
  { key: 'cas', label: 'Certificate Authorities', anyOf: ['ca:read'] },
  { key: 'certs', label: 'Certificates', anyOf: ['cert:read', 'cert:request'] },
  { key: 'approvals', label: 'Approvals', anyOf: ['cert:approve'] },
  { key: 'tokens', label: 'API Tokens', anyOf: ['token:read_own'] },
  { key: 'users', label: 'Users', anyOf: ['user:read'] },
  { key: 'audit', label: 'Audit Log', anyOf: ['audit:read'] },
  { key: 'settings', label: 'Settings', anyOf: ['settings:manage'] },
] as const

type TabKey = (typeof ALL_TABS)[number]['key']

export default function Dashboard() {
  const { actor, logout } = useAuth()
  const permissions = actor?.permissions ?? []

  const tabs = ALL_TABS.filter((t) => t.anyOf.some((p) => permissions.includes(p)))
  const [tab, setTab] = useState<TabKey>(tabs[0]?.key ?? 'certs')

  const canReadCerts = permissions.includes('cert:read')

  return (
    <div className={styles.page}>
      <header className="flex items-center justify-between border-b border-gray-200 bg-white px-6 py-4">
        <div className="flex items-center gap-2">
          <img src="/logo.png" alt="" className="h-9 w-auto" />
          <span className="text-lg font-semibold text-gray-900">capki</span>
        </div>
        <div className="flex items-center gap-4 text-sm text-gray-600">
          <span>
            {actor?.username} <span className="text-gray-400">({actor?.role})</span>
          </span>
          <button onClick={() => logout()} className={styles.buttonSecondary}>
            Sign out
          </button>
        </div>
      </header>
      <nav className="border-b border-gray-200 bg-white px-6">
        <div className="mx-auto flex max-w-6xl gap-6">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={
                tab === t.key
                  ? 'border-b-2 border-indigo-600 py-3 text-sm font-medium text-indigo-600'
                  : 'border-b-2 border-transparent py-3 text-sm font-medium text-gray-500 hover:text-gray-800'
              }
            >
              {t.label}
            </button>
          ))}
        </div>
      </nav>
      <main className="mx-auto max-w-6xl px-6 py-8">
        {tab === 'cas' && <CertificateAuthorities />}
        {tab === 'certs' && (canReadCerts ? <Certificates /> : <MyCertificateRequests />)}
        {tab === 'approvals' && <Approvals />}
        {tab === 'tokens' && <Tokens />}
        {tab === 'users' && <Users />}
        {tab === 'audit' && <AuditLog />}
        {tab === 'settings' && <Settings />}
      </main>
    </div>
  )
}
