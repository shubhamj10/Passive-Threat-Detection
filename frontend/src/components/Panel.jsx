export default function Panel({ title, aside, children, className = '' }) {
  return (
    <section className={`rounded-md border border-rule bg-panel ${className}`}>
      {title ? (
        <header className="flex items-baseline justify-between gap-3 border-b border-rule px-4 py-2.5">
          <h2 className="font-display text-base font-semibold">{title}</h2>
          {aside ? <div className="text-xs text-muted">{aside}</div> : null}
        </header>
      ) : null}
      <div className="p-4">{children}</div>
    </section>
  )
}
