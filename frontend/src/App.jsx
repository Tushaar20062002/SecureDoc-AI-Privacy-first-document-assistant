import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import { Spinner } from './components/ui'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import OnboardingPage from './pages/OnboardingPage'
import DashboardPage from './pages/DashboardPage'
import DocumentPage from './pages/DocumentPage'
import SettingsPage from './pages/SettingsPage'

function Loading() {
  return (
    <div className="flex h-screen items-center justify-center gap-2 text-sm text-slate-500">
      <Spinner className="h-5 w-5 text-indigo-600" /> Loading…
    </div>
  )
}

function RequireAuth({ children, onboarded = true }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (!user) return <Navigate to="/login" replace />
  if (onboarded && !user.onboarding_complete) return <Navigate to="/onboarding" replace />
  return children
}

function PublicOnly({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (user) return <Navigate to={user.onboarding_complete ? '/' : '/onboarding'} replace />
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<PublicOnly><LoginPage /></PublicOnly>} />
      <Route path="/register" element={<PublicOnly><RegisterPage /></PublicOnly>} />
      <Route path="/onboarding" element={<RequireAuth onboarded={false}><OnboardingPage /></RequireAuth>} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/documents/:id" element={<DocumentPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
