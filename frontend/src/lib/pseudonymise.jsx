import { createContext, useContext, useMemo, useState } from 'react'

// Display-only pseudonymisation: IPs become stable "host-xxxx" labels in this browser.
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g

function fnv1a(str) {
  let h = 0x811c9dc5
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(16).padStart(8, '0').slice(0, 5)
}

const PseudoContext = createContext({ on: false, toggle: () => {}, mask: (s) => s })

export function PseudoProvider({ children }) {
  const [on, setOn] = useState(false)
  const value = useMemo(() => ({
    on,
    toggle: () => setOn((v) => !v),
    mask: (s) => (on && typeof s === 'string' ? s.replace(IP_RE, (ip) => `host-${fnv1a(ip)}`) : s),
  }), [on])
  return <PseudoContext.Provider value={value}>{children}</PseudoContext.Provider>
}

export const usePseudo = () => useContext(PseudoContext)
