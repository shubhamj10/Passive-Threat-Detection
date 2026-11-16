export default function ConfidenceBar({ value, threshold }) {
  const pct = Math.round((value ?? 0) * 100)
  return (
    <div className="flex items-center gap-2" title={`confidence ${pct}%${threshold ? `, alert threshold ${threshold * 100}%` : ''}`}>
      <div className="relative h-1.5 w-20 overflow-hidden rounded-full bg-sunk">
        <div className="h-full bg-signal" style={{ width: `${pct}%` }} />
        {threshold ? <div className="absolute top-0 h-full w-px bg-ink" style={{ left: `${threshold * 100}%` }} /> : null}
      </div>
      <span className="w-9 text-right text-xs text-muted">{pct}%</span>
    </div>
  )
}
