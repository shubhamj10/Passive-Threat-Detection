import Panel from '../components/Panel'
import ReplayControls from '../components/ReplayControls'
import { useLive } from '../hooks/useLiveFeed'
import { fmtNum } from '../lib/format'

export default function Replay() {
  const { stats } = useLive()
  const r = stats?.replay
  return (
    <div className="max-w-3xl space-y-4">
      <Panel title="Replay traffic">
        <p className="mb-4 text-sm text-muted">
          These controls drive the simulated production side only. The enclave keeps listening; nothing is ever sent back
          to the traffic source. Replay <code>drift_scenario.jsonl</code> to watch the beaconing detector lose trust.
        </p>
        <ReplayControls status={r} />
      </Panel>
      <Panel title="Generator status">
        {r ? (
          <dl className="grid grid-cols-2 gap-y-1 text-sm">
            <dt className="text-muted">State</dt><dd>{r.state}</dd>
            <dt className="text-muted">Source</dt><dd>{r.source}</dd>
            <dt className="text-muted">Speed</dt><dd>{r.speed}× event time</dd>
            <dt className="text-muted">Records sent</dt><dd>{fmtNum(r.sent_records, 0)}</dd>
            <dt className="text-muted">Event time now</dt>
            <dd>{r.last_event_ts ? new Date(r.last_event_ts * 1000).toLocaleTimeString() : '–'}</dd>
          </dl>
        ) : <p className="text-sm text-muted">The generator is not running. Start the backend with <code>python run_all.py --mode demo</code>.</p>}
      </Panel>
    </div>
  )
}
