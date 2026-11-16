import { useMemo } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CLASS_COLOR, CLASS_LABEL } from '../lib/format'

const CLASSES = Object.keys(CLASS_LABEL)

// Alerts per minute of EVENT time over the most recent hour of traffic seen.
export default function Timeline({ alerts }) {
  const data = useMemo(() => {
    if (!alerts.length) return []
    const times = alerts.map((a) => new Date(a.timestamp).getTime())
    const end = Math.max(...times)
    const start = end - 59 * 60000
    const buckets = new Map()
    for (let t = Math.floor(start / 60000) * 60000; t <= end; t += 60000) {
      buckets.set(t, Object.fromEntries([['t', t], ...CLASSES.map((c) => [c, 0])]))
    }
    alerts.forEach((a, i) => {
      const k = Math.floor(times[i] / 60000) * 60000
      const b = buckets.get(k)
      if (b) b[a.threat_class] += 1
    })
    return [...buckets.values()]
  }, [alerts])

  if (!data.length) return <p className="py-10 text-center text-sm text-muted">The timeline fills in as alerts arrive.</p>
  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -24 }}>
          <CartesianGrid stroke="var(--color-rule)" vertical={false} />
          <XAxis
            dataKey="t"
            tickFormatter={(t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            tick={{ fontSize: 11, fill: 'var(--color-muted)' }}
            minTickGap={30}
          />
          <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
          <Tooltip
            labelFormatter={(t) => new Date(t).toLocaleTimeString()}
            contentStyle={{ background: 'var(--color-panel)', border: '1px solid var(--color-rule)', fontSize: 12 }}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} formatter={(v) => CLASS_LABEL[v]} />
          {CLASSES.map((c) => (
            <Bar key={c} dataKey={c} stackId="a" fill={CLASS_COLOR[c]} isAnimationActive={false} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
