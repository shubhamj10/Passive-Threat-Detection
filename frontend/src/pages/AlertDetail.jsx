import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import ConfidenceBar from '../components/ConfidenceBar'
import Panel from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { useLive } from '../hooks/useLiveFeed'
import { CLASS_LABEL, dateTimeOf, fmtNum, humanise } from '../lib/format'
import { usePseudo } from '../lib/pseudonymise'

// Which threshold (if any) a feature is compared against, for the evidence table.
const FEATURE_THRESHOLD = { flows: 'min_flows', events: 'min_events', span_s: 'min_span_s',
  n_queries: 'tunnel_min_queries', max_label_len: 'tunnel_min_label_len' }

function Row({ k, v }) {
  return (
    <div className="contents">
      <dt className="text-muted">{k}</dt>
      <dd className="break-all">{v}</dd>
    </div>
  )
}

export default function AlertDetail() {
  const { id } = useParams()
  const { updateAlert } = useLive()
  const { mask } = usePseudo()
  const [alert, setAlert] = useState(null)
  const [error, setError] = useState(null)
  const [replay, setReplay] = useState(null)
  const [busy, setBusy] = useState('')
  const [explanation, setExplanation] = useState(null)
  const [showJson, setShowJson] = useState(false)

  useEffect(() => {
    setAlert(null); setReplay(null); setExplanation(null)
    api.alert(id).then(setAlert).catch((e) => setError(e.message))
  }, [id])

  if (error) return <p className="text-sm text-sev-high">Could not load alert {id}: {error}</p>
  if (!alert) return <p className="text-sm text-muted">Loading alert…</p>

  const ev = alert.evidence
  const top = new Set(ev.top_shap_features)
  const act = async (name, fn) => {
    setBusy(name)
    try { await fn() } catch (e) { setError(e.message) } finally { setBusy('') }
  }
  const sendFeedback = (verdict) => act('feedback', async () => {
    await api.feedback(alert.alert_id, verdict)
    const fresh = await api.alert(alert.alert_id)
    setAlert(fresh); updateAlert(fresh)
  })

  return (
    <div className="space-y-4">
      <Link to="/" className="text-sm text-signal hover:underline">Back to dashboard</Link>
      <div className="rounded-md border border-rule bg-panel p-4">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={alert.severity} />
          <h1 className="font-display text-2xl font-semibold">
            {CLASS_LABEL[alert.threat_class]}
            {alert.attack_subtype ? <span className="ml-2 text-base font-normal text-muted">{humanise(alert.attack_subtype)}</span> : null}
          </h1>
          <span className="ml-auto text-xs text-muted">{alert.alert_id}</span>
        </div>
        <p className="mt-2 text-sm">{mask(alert.flow_id)}</p>
        <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <span className="flex items-center gap-2"><span className="text-muted">Confidence</span>
            <ConfidenceBar value={alert.confidence} threshold={ev.thresholds.alert_threshold} /></span>
          <span><span className="text-muted">Event time</span> {dateTimeOf(alert.timestamp)}</span>
          <span><span className="text-muted">MITRE ATT&amp;CK</span> {alert.mitre_attack}</span>
          <span><span className="text-muted">Detector trust when raised</span> {alert.trace.detector_trust_score ?? 'insufficient data'}</span>
        </div>
        <p className="mt-3 rounded-sm bg-sunk px-3 py-2 text-sm">{alert.recommended_action}</p>
        <div className="mt-4 flex flex-wrap gap-2 text-sm">
          <button disabled={!!busy} onClick={() => sendFeedback('true_positive')}
            className="rounded-sm border border-rule px-3 py-1 hover:bg-sunk disabled:opacity-50">Confirm as real threat</button>
          <button disabled={!!busy} onClick={() => sendFeedback('false_positive')}
            className="rounded-sm border border-rule px-3 py-1 hover:bg-sunk disabled:opacity-50">Mark as false positive</button>
          {alert.feedback ? (
            <span className="self-center text-xs text-muted">
              Analyst verdict: {alert.feedback.verdict === 'false_positive' ? 'false positive' : 'real threat'}
            </span>
          ) : null}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Evidence" aside={`ranked by ${ev.evidence_method === 'shap' ? 'SHAP values' : 'importance × deviation'}`}>
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted">
              <tr><th className="pb-1 font-normal">Feature</th><th className="font-normal text-right">Value</th>
                <th className="font-normal text-right">Gate threshold</th></tr>
            </thead>
            <tbody>
              {Object.entries(ev.features).map(([k, v]) => (
                <tr key={k} className="border-t border-rule">
                  <td className={`py-1 ${top.has(k) ? 'font-semibold' : ''}`}>
                    {humanise(k)}{top.has(k) ? <span className="ml-1.5 text-xs font-normal text-signal">top driver</span> : null}
                  </td>
                  <td className="text-right">{fmtNum(v, 3)}</td>
                  <td className="text-right text-muted">{FEATURE_THRESHOLD[k] && ev.thresholds[FEATURE_THRESHOLD[k]] !== undefined ? ev.thresholds[FEATURE_THRESHOLD[k]] : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-3 text-xs text-muted">Gates passed: {ev.gates_passed.map(humanise).join(', ')}</p>
        </Panel>

        <div className="space-y-4">
          <Panel title="Decision trace" aside="the black box recorder">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <Row k="Model" v={`${alert.model.name} ${alert.model.version}`} />
              <Row k="Config hash" v={alert.trace.config_hash} />
              <Row k="Data window" v={`${dateTimeOf(alert.trace.data_window.start)} to ${dateTimeOf(alert.trace.data_window.end)}`} />
              <Row k="Raw model score" v={fmtNum(alert.trace.raw_score, 4)} />
            </dl>
            <button disabled={!!busy} onClick={() => act('replay', async () => setReplay(await api.replayAlert(alert.alert_id)))}
              className="mt-3 rounded-sm bg-signal px-3 py-1 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50">
              {busy === 'replay' ? 'Replaying…' : 'Replay this decision'}
            </button>
            {replay ? (
              <div className={`mt-3 rounded-sm border-l-4 px-3 py-2 text-sm ${replay.reproduced ? 'border-ok bg-sunk' : 'border-sev-high bg-sunk'}`}>
                <p className="font-semibold">{replay.reproduced ? 'Reproduced: same class, confidence, gates and evidence.' : 'Not reproduced.'}</p>
                {replay.error ? <p className="mt-1 text-xs">{replay.error}</p> : (
                  <ul className="mt-1 grid grid-cols-2 gap-x-4 text-xs">
                    {Object.entries(replay.checks).filter(([, v]) => typeof v === 'boolean').map(([k, v]) => (
                      <li key={k}>{v ? '✓' : '✗'} {humanise(k.replace('_match', ''))}</li>
                    ))}
                  </ul>
                )}
              </div>
            ) : null}
          </Panel>

          <Panel title="Plain-language explanation" aside="optional assistant; redacted input">
            {explanation || alert.ai_explanation ? (
              <p className="text-sm leading-relaxed">{explanation?.text || alert.ai_explanation}</p>
            ) : <p className="text-sm text-muted">Generate a short explanation of this alert for a non-specialist.</p>}
            {explanation?.source ? <p className="mt-2 text-xs text-muted">Source: {humanise(explanation.source)}{explanation.note ? `. ${explanation.note}` : ''}</p> : null}
            <button disabled={!!busy} onClick={() => act('explain', async () => setExplanation(await api.explain(alert.alert_id)))}
              className="mt-3 rounded-sm border border-rule px-3 py-1 text-sm hover:bg-sunk disabled:opacity-50">
              {busy === 'explain' ? 'Writing…' : 'Explain this alert'}
            </button>
          </Panel>

          <Panel title="Context">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              {Object.entries(ev.context).filter(([k]) => !['first_ts', 'last_ts'].includes(k)).map(([k, v]) => (
                <Row key={k} k={humanise(k)} v={mask(Array.isArray(v) ? v.join(', ') : String(v))} />
              ))}
            </dl>
          </Panel>
        </div>
      </div>

      <button onClick={() => setShowJson((s) => !s)} className="text-sm text-signal hover:underline">
        {showJson ? 'Hide raw alert JSON' : 'Show raw alert JSON'}
      </button>
      {showJson ? (
        <pre className="overflow-auto rounded-md border border-rule bg-panel p-4 text-xs">{mask(JSON.stringify(alert, null, 2))}</pre>
      ) : null}
    </div>
  )
}
