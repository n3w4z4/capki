import { AuthProvider, useAuth } from './auth/AuthContext'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'

function Shell() {
  const { actor, loading } = useAuth()

  if (loading) {
    return null
  }

  return actor ? <Dashboard /> : <Login />
}

function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  )
}

export default App
