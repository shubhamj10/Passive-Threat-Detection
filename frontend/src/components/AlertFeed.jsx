import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { CLASS_LABEL, humanise, timeOf } from '../lib/format'
import { usePseudo } from '../lib/pseudonymise'
import ConfidenceBar from './ConfidenceBar'
import SeverityBadge from './SeverityBadge'

const FILTERS = ['all', 'ddos', 'botnet_c2_beaconing', 'dga_domain', 'dns_tunnelling']

export default function AlertFeed({ alerts }) {
  const [filter, setFilter] = useState('all')
  const { mask } = usePseudo()
  const shown = useMemo(
    () => (filter === 'all' ? alerts : alerts.filter((a) => a.threat_class === filter)).slice(0, 150),
    [alerts, filter],
  )

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-1.5" role="tablist" aria-label="Filter by threat">
        {FILTERS.map((f) => (
          <button
            key={f}
            role="tab"
            aria-selected={filter === f}
            onClick={() => setFilter(f)}
            className={`rounded-sm px-2.5 py-1 text-xs ${filter === f ? 'bg-ink text-panel' : 'bg-sunk text-muted hover:text-ink'}`}
          >
            {f === 'all' ? 'All threats' : CLASS_LABEL[f]}
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted">
          No alerts yet. Simulated attacks appear here as the replay reaches them.
        </p>
      ) : (
        <div className="max-h-[30rem] overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-panel text-left text-xs text-muted">
              <tr>
                <th className="py-1.5 pr-3 font-normal">Event time</th>
                <th className="pr-3 font-normal">Severity</th>
                <th className="pr-3 font-normal">Threat</th>
                <th className="pr-3 font-normal">Where</th>
                <th className="pr-3 font-normal">Confidence</th>
                <th className="font-normal">Trust</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={a.alert_id} className="border-t border-rule hover:bg-sunk">
                  <td className="py-2 pr-3 whitespace-nowrap text-muted">{timeOf(a.timestamp)}</td>
                  <td className="pr-3"><SeverityBadge severity={a.severity} /></td>
                  <td className="pr-3">
                    <Link to={`/alerts/${a.alert_id}`} className="font-medium text-ink underline-offset-2 hover:underline">
                      {CLASS_LABEL[a.threat_class]}
                    </Link>
                    {a.attack_subtype ? <span className="ml-1.5 text-xs text-muted">{humanise(a.attack_subtype)}</span> : null}
                    {a.feedback ? (
                      <span className="ml-1.5 text-xs text-muted">
                        · {a.feedback.verdict === 'false_positive' ? 'marked false positive' : 'confirmed'}
                      </span>
                    ) : null}
                  </td>
                  <td className="max-w-[16rem] truncate pr-3 text-xs" title={mask(a.flow_id)}>{mask(a.entity)}</td>
                  <td className="pr-3"><ConfidenceBar value={a.confidence} threshold={a.evidence?.thresholds?.alert_threshold} /></td>
                  <td className="text-xs text-muted">{a.trace?.detector_trust_score ?? '–'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
