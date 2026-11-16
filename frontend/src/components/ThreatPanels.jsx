import { Link } from 'react-router-dom'
import { CLASS_LABEL, fmtNum, timeOf } from '../lib/format'
import { usePseudo } from '../lib/pseudonymise'

function latest(alerts, cls) {
  return alerts.find((a) => cls.includes(a.threat_class))
}

function Card({ title, explain, alerts, classes, metric }) {
  const { mask } = usePseudo()
  const mine = alerts.filter((a) => classes.includes(a.threat_class))
  const last = latest(alerts, classes)
  return (
    <div className="flex flex-col rounded-md border border-rule bg-panel p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="font-display text-base font-semibold">{title}</h3>
        <span className="font-display text-3xl font-semibold">{mine.length}</span>
      </div>
      <p className="mt-1 text-xs text-muted">{explain}</p>
      <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        {metric(mine).map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className="text-right">{v}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-auto pt-3 text-xs">
        {last ? (
          <Link to={`/alerts/${last.alert_id}`} className="text-signal hover:underline">
            Latest at {timeOf(last.timestamp)}: {mask(last.entity)}
          </Link>
        ) : (
          <span className="text-muted">Nothing detected yet</span>
        )}
      </div>
    </div>
  )
}

export default function ThreatPanels({ alerts }) {
  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card
        title="DDoS"
        explain="Flow rate and source-address entropy per internal destination."
        alerts={alerts}
        classes={['ddos']}
        metric={(m) => [
          ['Peak packets/s', fmtNum(Math.max(0, ...m.map((a) => a.evidence.features.pkts_per_s)), 0)],
          ['Most sources in a window', fmtNum(Math.max(0, ...m.map((a) => a.evidence.features.unique_src)), 0)],
          ['Targets', new Set(m.map((a) => a.entity)).size],
        ]}
      />
      <Card
        title="C2 beaconing"
        explain="Regular check-ins from one internal host to one external server."
        alerts={alerts}
        classes={['botnet_c2_beaconing']}
        metric={(m) => [
          ['Most regular interval (CV)', m.length ? fmtNum(Math.min(...m.map((a) => a.evidence.features.interval_cv)), 3) : '–'],
          ['Hosts involved', new Set(m.map((a) => a.evidence.context.src_ip)).size],
          ['External servers', new Set(m.map((a) => a.evidence.context.dst_ip)).size],
        ]}
      />
      <Card
        title="DNS threats"
        explain="Random-looking names (DGA) and long encoded names (tunnelling)."
        alerts={alerts}
        classes={['dga_domain', 'dns_tunnelling']}
        metric={(m) => [
          [CLASS_LABEL.dga_domain, m.filter((a) => a.threat_class === 'dga_domain').length],
          [CLASS_LABEL.dns_tunnelling, m.filter((a) => a.threat_class === 'dns_tunnelling').length],
          ['Hosts involved', new Set(m.map((a) => a.evidence.context.src_ip)).size],
        ]}
      />
    </div>
  )
}
