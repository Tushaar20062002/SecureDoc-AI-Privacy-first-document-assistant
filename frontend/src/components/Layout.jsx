import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Icon from './icons'

const linkClass = ({ isActive }) =>
  `group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
    isActive ? 'bg-indigo-50 text-indigo-700' : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
  }`

export function Logo({ compact = false }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-600 text-white shadow-sm">
        <Icon name="shield" className="h-5 w-5" strokeWidth={1.8} />
      </div>
      {!compact && (
        <div className="leading-tight">
          <div className="text-sm font-semibold text-slate-900">SecureDoc AI</div>
          <div className="text-[11px] text-slate-500">Privacy-first document assistant</div>
        </div>
      )}
    </div>
  )
}

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const doLogout = async () => { await logout(); navigate('/login') }
  const initial = (user?.email || '?').charAt(0).toUpperCase()

  return (
    <div className="min-h-screen md:flex">
      <aside className="border-b border-slate-200 bg-white md:fixed md:inset-y-0 md:flex md:w-64 md:flex-col md:overflow-y-auto md:border-b-0 md:border-r">
        <div className="flex items-center justify-between px-5 py-4 md:py-5">
          <Logo />
          <button onClick={doLogout} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 md:hidden" aria-label="Log out">
            <Icon name="logout" />
          </button>
        </div>
        <nav className="flex gap-1 px-3 pb-3 md:flex-1 md:flex-col md:pb-0" aria-label="Main">
          <p className="hidden px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400 md:block">Workspace</p>
          <NavLink to="/" end className={linkClass}><Icon name="home" />Documents</NavLink>
          <p className="hidden px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wider text-slate-400 md:block">Account</p>
          <NavLink to="/settings" className={linkClass}><Icon name="lock" />Privacy &amp; Permissions</NavLink>
        </nav>
        <div className="hidden shrink-0 border-t border-slate-200 p-4 md:block">
          <div className="mb-3 flex items-center gap-2 rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-800">
            <Icon name="shield" className="h-4 w-4 shrink-0" />
            Sensitive IDs are masked before AI processing
          </div>
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-200 text-sm font-semibold text-slate-700">{initial}</div>
            <div className="min-w-0 flex-1 truncate text-sm text-slate-700" title={user?.email}>{user?.email}</div>
            <button onClick={doLogout} className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900" aria-label="Log out" title="Log out">
              <Icon name="logout" className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 md:pl-64">
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
