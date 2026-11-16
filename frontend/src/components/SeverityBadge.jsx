const STYLE = {
  critical: 'bg-sev-critical text-white',
  high: 'bg-sev-high text-white',
  medium: 'bg-sev-medium text-white',
  low: 'border border-sev-low text-sev-low',
}

export default function SeverityBadge({ severity }) {
  return (
    <span className={`inline-block min-w-16 rounded-sm px-1.5 py-0.5 text-center text-xs font-semibold ${STYLE[severity] || STYLE.low}`}>
      {severity}
    </span>
  )
}
