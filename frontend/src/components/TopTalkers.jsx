import { fmtBytes } from '../lib/format'
import { usePseudo } from '../lib/pseudonymise'

function List({ title, rows }) {
  const { mask } = usePseudo()
  const max = Math.max(1, ...rows.map((r) => r.bytes))
  return (
    <div>
      <h3 className="mb-2 text-xs text-muted">{title}</h3>
      {rows.length === 0 ? <p className="text-xs text-muted">Waiting for the first full minute of traffic.</p> : null}
      <ul className="space-y-1.5">
        {rows.map((r) => (
          <li key={r.ip} className="text-xs">
            <div className="flex justify-between gap-2">
              <span className="truncate">{mask(r.ip)}</span>
              <span className="text-muted">{fmtBytes(r.bytes)}</span>
            </div>
            <div className="mt-0.5 h-1 rounded bg-sunk">
              <div className="h-1 rounded bg-signal" style={{ width: `${(r.bytes / max) * 100}%` }} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function TopTalkers({ talkers }) {
  return (
    <div className="grid gap-5 sm:grid-cols-2">
      <List title="Sources, by bytes in the last minute" rows={talkers?.sources || []} />
      <List title="Destinations, by bytes in the last minute" rows={talkers?.destinations || []} />
    </div>
  )
}
