import AlertFeed from '../components/AlertFeed'
import AssurancePanel from '../components/AssurancePanel'
import DiodeStrip from '../components/DiodeStrip'
import Panel from '../components/Panel'
import ReplayControls from '../components/ReplayControls'
import ThreatPanels from '../components/ThreatPanels'
import Timeline from '../components/Timeline'
import TopTalkers from '../components/TopTalkers'
import { useLive } from '../hooks/useLiveFeed'

export default function Dashboard() {
  const { alerts, stats, assurance, assuranceAlerts, connection } = useLive()
  return (
    <div className="space-y-4">
      <DiodeStrip stats={stats} connection={connection} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Threat alerts" aside={<ReplayControls status={stats?.replay} compact />}>
          <AlertFeed alerts={alerts} />
        </Panel>
        <Panel title="AI assurance" aside="model health, live">
          <AssurancePanel status={assurance} alerts={assuranceAlerts} />
        </Panel>
      </div>
      <ThreatPanels alerts={alerts} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Panel title="Alerts per minute" aside="event time"><Timeline alerts={alerts} /></Panel>
        <Panel title="Top talkers"><TopTalkers talkers={stats?.top_talkers} /></Panel>
      </div>
    </div>
  )
}
