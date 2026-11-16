import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { api, wsUrl } from '../api/client'

const MAX_ALERTS = 600
const LiveContext = createContext(null)

function upsertAssurance(list, a) {
  const i = list.findIndex((x) => x.assurance_alert_id === a.assurance_alert_id)
  if (i === -1) return [a, ...list]
  const copy = list.slice()
  copy[i] = a
  return copy
}

export function LiveProvider({ children }) {
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [assurance, setAssurance] = useState({})
  const [assuranceAlerts, setAssuranceAlerts] = useState([])
  const [connection, setConnection] = useState('connecting')
  const [error, setError] = useState(null)
  const retry = useRef(0)

  const loadInitial = useCallback(async () => {
    try {
      const [a, s, st, aa] = await Promise.all([
        api.alerts({ limit: 300 }), api.stats(), api.assuranceStatus(), api.assuranceAlerts(),
      ])
      setAlerts(a)
      setStats(s)
      setAssurance(st.detectors || {})
      setAssuranceAlerts(aa)
      setError(null)
    } catch (e) {
      setError(`Backend not reachable (${e.message}). Start it with: python run_all.py --mode demo`)
    }
  }, [])

  useEffect(() => {
    let ws
    let closed = false
    let timer
    const connect = () => {
      setConnection('connecting')
      ws = new WebSocket(wsUrl())
      ws.onopen = () => {
        retry.current = 0
        setConnection('live')
        loadInitial()
      }
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data)
        switch (msg.type) {
          case 'threat_alert':
            setAlerts((prev) => [msg.data, ...prev].slice(0, MAX_ALERTS))
            break
          case 'assurance_alert':
          case 'assurance_update':
          case 'assurance_resolved':
            setAssuranceAlerts((prev) => upsertAssurance(prev, msg.data))
            break
          case 'assurance_status':
            setAssurance((prev) => {
              const d = msg.data
              const old = prev[d.detector]
              const history = [...(old?.history || []), { t: d.event_time, score: d.trust_score }].slice(-240)
              return { ...prev, [d.detector]: { ...d, history } }
            })
            break
          case 'stats':
            setStats(msg.data)
            break
          default:
            break
        }
      }
      ws.onclose = () => {
        if (closed) return
        setConnection('offline')
        const wait = Math.min(10000, 1000 * 2 ** retry.current++)
        timer = setTimeout(connect, wait)
      }
      ws.onerror = () => ws.close()
    }
    loadInitial()
    connect()
    return () => {
      closed = true
      clearTimeout(timer)
      ws?.close()
    }
  }, [loadInitial])

  const updateAlert = useCallback((a) => {
    setAlerts((prev) => prev.map((x) => (x.alert_id === a.alert_id ? { ...x, ...a } : x)))
  }, [])

  const value = { alerts, stats, assurance, assuranceAlerts, connection, error, reload: loadInitial, updateAlert }
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>
}

export const useLive = () => useContext(LiveContext)
