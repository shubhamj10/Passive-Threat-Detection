import { Line, LineChart, ReferenceLine, ResponsiveContainer, YAxis } from 'recharts'
import { DETECTOR_LABEL, fmtNum, timeOf } from '../lib/format'

const ORDER = ['ddos_scorer', 'beacon_scorer', 'dns_scorer']

function scoreColor(score, threshold) {
  if (score === null || score === undefined) return 'var(--color-muted)'
  return score < threshold ? 'var(--color-sev-high)' : 'var(--color-trust)'
}

function Signal({ label, value, hint }) {
  return (
    <div className="flex justify-between gap-2 text-xs">
      <span className="text-muted" title={hint}>{label}</span>
      <span>{value}</span>
    </div>
  )
}

function DetectorRow({ name, st, threshold }) {
  const score = st?.trust_score
  const sig = st?.signals || {}
  const hist = (st?.history || []).filter((h) => h.score !== null && h.score !== undefined)
  return (
    <div className="border-t border-rule py-3 first:border-t-0 first:pt-0">
      <div className="flex items-center gap-3">
        <div className="w-24">
          <div className="font-display text-sm font-semibold">{DETECTOR_LABEL[name]}</div>
          <div className="text-xs text-muted">{st?.version ? `v${st.version}` : ''}</div>
        </div>
        <div className="w-16 text-right">
          <span className="font-display text-3xl font-semibold" style={{ color: scoreColor(score, threshold) }}>
            {score ?? '–'}
          </span>
        </div>
        <div className="h-10 flex-1" aria-label={`trust trend for ${DETECTOR_LABEL[name]}`}>
          {hist.length > 1 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={hist} margin={{ top: 3, right: 2, bottom: 3, left: 2 }}>
                <YAxis domain={[0, 100]} hide />
                <ReferenceLine y={threshold} stroke="var(--color-rule)" strokeDasharray="3 3" />
                <Line type="monotone" dataKey="score" stroke="var(--color-trust)" dot={false} strokeWidth={1.75} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center text-xs text-muted">trend appears after a few checks</div>
          )}
        </div>
      </div>
      {score === null || score === undefined ? (
        <p className="mt-1.5 text-xs text-muted">Insufficient data: normal at start-up.</p>
      ) : (
        <div className="mt-2 space-y-0.5">
          <Signal label="Feature drift (PSI)" value={fmtNum(sig.feature_drift_psi, 3)}
            hint="How different today's traffic looks from the training data" />
          <Signal label="Alert volume vs. baseline" value={sig.alert_volume_ratio == null ? '–' : `${fmtNum(sig.alert_volume_ratio, 2)}×`}
            hint="Alerts raised compared with what training predicted" />
          <Signal label="Analyst false-positive rate"
            value={sig.feedback_fp_rate == null ? `needs more labels (${sig.feedback_count ?? 0})` : `${Math.round(sig.feedback_fp_rate * 100)}%`}
            hint="From analysts marking alerts true or false positive" />
        </div>
      )}
    </div>
  )
}

export default function AssurancePanel({ status, alerts, threshold = 70 }) {
  const open = alerts.filter((a) => a.status === 'open')
  return (
    <div>
      <p className="mb-3 text-xs text-muted">
        Is each model still reliable? Trust drops when traffic drifts from training data, alert volume becomes unusual,
        or analysts report false positives. Below {threshold}, the system raises an assurance alert.
      </p>
      <div>
        {ORDER.map((n) => <DetectorRow key={n} name={n} st={status[n]} threshold={threshold} />)}
      </div>
      <div className="mt-3 border-t border-rule pt-3">
        <h3 className="mb-2 text-xs text-muted">
          {open.length ? `${open.length} open assurance alert${open.length > 1 ? 's' : ''}` : 'No open assurance alerts'}
        </h3>
        <ul className="space-y-2">
          {alerts.slice(0, 5).map((a) => (
            <li key={a.assurance_alert_id}
              className={`rounded-sm border-l-4 px-3 py-2 text-xs ${a.status === 'open' ? 'border-trust bg-trust-soft' : 'border-rule bg-sunk text-muted'}`}>
              <div className="flex justify-between gap-2">
                <span className="font-semibold">
                  {DETECTOR_LABEL[a.detector.name]} model trust {a.trust_score.previous ?? '–'} → {a.trust_score.current}
                </span>
                <span>{a.status === 'open' ? timeOf(a.timestamp) : 'resolved'}</span>
              </div>
              {a.status === 'open' ? <p className="mt-1">{a.recommended_action}</p> : null}
              {a.signals?.top_drift_features?.length ? (
                <p className="mt-1 text-muted">
                  Most changed: {a.signals.top_drift_features.map(([f]) => f.replaceAll('_', ' ')).join(', ')}
                </p>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
