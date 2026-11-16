import { NavLink, Route, Routes } from 'react-router-dom'
import { LiveProvider, useLive } from './hooks/useLiveFeed'
import { PseudoProvider, usePseudo } from './lib/pseudonymise'
import AlertDetail from './pages/AlertDetail'
import Dashboard from './pages/Dashboard'
import Replay from './pages/Replay'

function Header() {
  const { on, toggle } = usePseudo()
  const { connection } = useLive()
  const link = ({ isActive }) => `px-2 py-1 text-sm ${isActive ? 'text-ink underline underline-offset-4' : 'text-muted hover:text-ink'}`
  return (
    <header className="border-b border-rule bg-panel">
      <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-4 px-4 py-3">
        <div className="mr-4">
          <div className="font-display text-xl font-semibold leading-tight">One-way threat watch</div>
          <div className="text-xs text-muted">Passive detection from a copy of network traffic, metadata only</div>
        </div>
        <nav className="flex gap-1">
          <NavLink to="/" end className={link}>Dashboard</NavLink>
          <NavLink to="/replay" className={link}>Replay</NavLink>
        </nav>
        <div className="ml-auto flex items-center gap-4">
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input type="checkbox" checked={on} onChange={toggle} className="accent-[var(--color-signal)]" />
            Pseudonymise IPs
          </label>
          <span className="flex items-center gap-1.5 text-xs text-muted">
            <span className={`inline-block h-2 w-2 rounded-full ${connection === 'live' ? 'bg-ok' : 'bg-sev-medium'}`} />
            {connection === 'live' ? 'Live' : connection === 'offline' ? 'Reconnecting' : 'Connecting'}
          </span>
        </div>
      </div>
    </header>
  )
}

function Shell() {
  const { error } = useLive()
  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto max-w-[1400px] px-4 py-4">
        {error ? <p className="mb-4 rounded-sm border-l-4 border-sev-medium bg-panel px-3 py-2 text-sm">{error}</p> : null}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/replay" element={<Replay />} />
          <Route path="*" element={<p className="text-sm text-muted">Page not found.</p>} />
        </Routes>
      </main>
      <footer className="mx-auto max-w-[1400px] px-4 pb-6 text-xs text-muted">
        The system only informs. Analysts decide any action.
      </footer>
    </div>
  )
}

export default function App() {
  return (
    <PseudoProvider>
      <LiveProvider>
        <Shell />
      </LiveProvider>
    </PseudoProvider>
  )
}
