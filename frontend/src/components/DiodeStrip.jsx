import { fmtNum } from '../lib/format'

function Metric({ label, value, unit }) {
  return (
    <div className="flex flex-col">
      <span className="font-display text-2xl font-semibold leading-none">
        {value}
        {unit ? <span className="ml-1 text-sm font-normal text-muted">{unit}</span> : null}
      </span>
      <span className="mt-1 text-xs text-muted">{label}</span>
    </div>
  )
}

// The signature of the product: production side -> one-way link -> enclave.
export default function DiodeStrip({ stats, connection }) {
  const fps = stats?.flows_per_s ?? 0
  const running = connection === 'live' && fps > 0
  return (
    <div className="rounded-md border border-rule bg-panel px-4 py-3">
      <div className="grid grid-cols-1 items-center gap-4 md:grid-cols-[auto_1fr_auto]">
        <div className="text-sm">
          <div className="font-display font-semibold">Production network</div>
          <div className="text-xs text-muted">TAP / SPAN copy, simulated</div>
        </div>
        <div className="flex items-center gap-3" aria-label="one-way link">
          <div className={`diode-line h-1 flex-1 rounded ${running ? '' : 'idle'}`} />
          <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true" className="shrink-0">
            <path d="M3 3 L17 11 L3 19 Z" fill="var(--color-signal)" />
            <rect x="17" y="3" width="2.5" height="16" fill="var(--color-signal)" />
          </svg>
          <span className="text-xs text-muted">no return path</span>
        </div>
        <div className="text-sm md:text-right">
          <div className="font-display font-semibold">Monitoring enclave</div>
          <div className="text-xs text-muted">
            {connection === 'live' ? 'receiving' : connection === 'offline' ? 'dashboard disconnected, retrying' : 'connecting'}
          </div>
        </div>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4 border-t border-rule pt-3 sm:grid-cols-3 lg:grid-cols-6">
        <Metric label="flows per second" value={fmtNum(fps, 0)} />
        <Metric label="p95 processing latency" value={fmtNum(stats?.p95_latency_ms, 1)} unit="ms" />
        <Metric label="p95 alert latency" value={fmtNum(stats?.p95_alert_latency_ms, 1)} unit="ms" />
        <Metric label="queue depth" value={fmtNum(stats?.queue_depth ?? 0, 0)} />
        <Metric label="records dropped" value={fmtNum(stats?.queue_dropped ?? 0, 0)} />
        <Metric label="flows processed" value={fmtNum(stats?.records_processed ?? 0, 0)} />
      </div>
    </div>
  )
}
