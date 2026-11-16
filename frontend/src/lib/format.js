export const CLASS_LABEL = {
  ddos: 'DDoS',
  botnet_c2_beaconing: 'C2 beaconing',
  dga_domain: 'DGA domains',
  dns_tunnelling: 'DNS tunnelling',
}

export const DETECTOR_LABEL = {
  ddos_scorer: 'DDoS',
  beacon_scorer: 'Beaconing',
  dns_scorer: 'DNS',
}

export const CLASS_COLOR = {
  ddos: 'var(--color-sev-high)',
  botnet_c2_beaconing: 'var(--color-trust)',
  dga_domain: 'var(--color-sev-medium)',
  dns_tunnelling: 'var(--color-signal)',
}

export function timeOf(iso) {
  if (!iso) return '–'
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function dateTimeOf(iso) {
  if (!iso) return '–'
  return new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' })
}

export function fmtNum(v, digits = 2) {
  if (v === null || v === undefined || Number.isNaN(v)) return '–'
  if (typeof v !== 'number') return String(v)
  if (Math.abs(v) >= 1000) return Math.round(v).toLocaleString()
  if (Number.isInteger(v)) return String(v)
  return v.toFixed(digits)
}

export function fmtBytes(b) {
  if (!b && b !== 0) return '–'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = b
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${units[i]}`
}

export const humanise = (s) => (s || '').replaceAll('_', ' ')
