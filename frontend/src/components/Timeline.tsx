import { formatDate, formatNumber } from "../labels";

/** Chronologie en barres empilées (résultats `timeline` du langage de recherche). */
export default function Timeline({ rows, series = false }: { rows: Record<string, unknown>[]; series?: boolean }) {
  const buckets = [...new Set(rows.map((r) => String(r.bucket)))];
  const names = series ? [...new Set(rows.map((r) => String(r.series)))] : ["count"];
  const palette = ["#7c83ff", "#22d3ee", "#f472b6", "#fbbf24", "#34d399", "#f87171", "#a78bfa", "#fb923c"];
  const totals = buckets.map((b) => rows.filter((r) => String(r.bucket) === b).reduce((s, r) => s + Number(r.count), 0));
  const max = Math.max(1, ...totals);
  return (
    <div className="timeline">
      <div className="timeline-bars">
        {buckets.map((b, i) => (
          <div key={b} className="timeline-col" title={`${formatDate(b)} : ${formatNumber(totals[i])}`}>
            <div className="timeline-stack" style={{ height: `${(totals[i] / max) * 100}%` }}>
              {names.map((n, j) => {
                const v = rows.filter((r) => String(r.bucket) === b && (!series || String(r.series) === n)).reduce((s, r) => s + Number(r.count), 0);
                return v ? <div key={n} style={{ flexGrow: v, background: palette[j % palette.length] }} /> : null;
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="timeline-axis muted small">
        <span>{buckets[0] && formatDate(buckets[0])}</span>
        <span>{buckets.length > 1 && formatDate(buckets[buckets.length - 1])}</span>
      </div>
      {series && (
        <div className="timeline-legend small">
          {names.map((n, j) => (
            <span key={n}>
              <i style={{ background: palette[j % palette.length] }} /> {n || "(vide)"}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
