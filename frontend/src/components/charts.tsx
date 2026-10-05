import { useId } from "react";
import { SEVERITIES, SEVERITY_LABEL, formatNumber } from "../labels";
import type { Overview, Severity } from "../types";

const W = 640;
const H = 190;
const PAD = { top: 14, right: 10, bottom: 26, left: 38 };

function niceMax(value: number): number {
  if (value <= 5) return 5;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  return Math.ceil(value / magnitude) * magnitude;
}

/** Barre aux coins supérieurs arrondis (segment du haut d'une pile). */
function topRounded(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, w / 2, h);
  return `M${x},${y + h} V${y + rr} Q${x},${y} ${x + rr},${y} H${x + w - rr} Q${x + w},${y} ${x + w},${y + rr} V${y + h} Z`;
}

function Grid({ max, y }: { max: number; y: (v: number) => number }) {
  return (
    <>
      {[max / 2, max].map((v) => (
        <g key={v}>
          <line x1={PAD.left} x2={W - PAD.right} y1={y(v)} y2={y(v)} className="grid" />
          <text x={PAD.left - 8} y={y(v) + 4} textAnchor="end" className="tick">
            {formatNumber(v)}
          </text>
        </g>
      ))}
      <line x1={PAD.left} x2={W - PAD.right} y1={y(0)} y2={y(0)} className="baseline" />
      <text x={PAD.left - 8} y={y(0) + 4} textAnchor="end" className="tick">
        0
      </text>
    </>
  );
}

/** Alertes créées par jour sur 30 jours, empilées par sévérité. */
export function TrendChart({ trend }: { trend: Overview["trend"] }) {
  const days: string[] = [];
  const byDay = new Map(trend.map((t) => [t.day, t]));
  for (let i = 29; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    days.push(d.toLocaleDateString("sv-SE", { timeZone: "Europe/Paris" }));
  }
  const totals = days.map((d) => SEVERITIES.reduce((s, sev) => s + (byDay.get(d)?.[sev] ?? 0), 0));
  const total = totals.reduce((a, b) => a + b, 0);
  const max = niceMax(Math.max(0, ...totals));
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const band = plotW / days.length;
  const y = (v: number) => PAD.top + plotH - (v / max) * plotH;
  const stackOrder: Severity[] = ["info", "low", "medium", "high", "critical"];

  return (
    <figure className="chart">
      <div className="chart-total">
        <strong>{formatNumber(total)}</strong>
        <span>alertes sur 30 jours</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Alertes créées par jour sur 30 jours">
        <Grid max={max} y={y} />
        {days.map((day, i) => {
          let acc = 0;
          const x = PAD.left + i * band + band * 0.18;
          const w = band * 0.64;
          const present = stackOrder.filter((sev) => (byDay.get(day)?.[sev] ?? 0) > 0);
          return (
            <g key={day}>
              {present.map((sev, idx) => {
                const v = byDay.get(day)?.[sev] ?? 0;
                const top = y(acc + v);
                const h = y(acc) - top;
                acc += v;
                const title = <title>{`${day} · ${SEVERITY_LABEL[sev]} : ${v}`}</title>;
                return idx === present.length - 1 ? (
                  <path key={sev} d={topRounded(x, top, w, h, 3)} className={`fill-${sev}`}>
                    {title}
                  </path>
                ) : (
                  <rect key={sev} x={x} width={w} y={top} height={h} className={`fill-${sev}`}>
                    {title}
                  </rect>
                );
              })}
              {i % 7 === 0 && (
                <text x={x + w / 2} y={H - 6} textAnchor="middle" className="tick">
                  {day.slice(8, 10)}/{day.slice(5, 7)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="legend">
        {SEVERITIES.filter((s) => s !== "info").map((s) => (
          <span key={s}>
            <i className={`swatch fill-${s}`} />
            {SEVERITY_LABEL[s]}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}

/** Échecs d'authentification par heure sur 24 h : courbe et aire en dégradé. */
export function HourlyBars({ points }: { points: Overview["auth_failures_hourly"] }) {
  const gradient = useId().replace(/:/g, "");
  const hours: { label: string; count: number }[] = [];
  const byHour = new Map(points.map((p) => [new Date(p.hour).getTime(), p.count]));
  const now = new Date();
  now.setMinutes(0, 0, 0);
  for (let i = 23; i >= 0; i--) {
    const t = now.getTime() - i * 3600000;
    hours.push({ label: `${new Date(t).getHours()}h`, count: byHour.get(t) ?? 0 });
  }
  const total = hours.reduce((a, h) => a + h.count, 0);
  const peak = hours.reduce((m, h) => (h.count > m.count ? h : m), hours[0]);
  const max = niceMax(Math.max(0, ...hours.map((h) => h.count)));
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const step = plotW / (hours.length - 1);
  const x = (i: number) => PAD.left + i * step;
  const y = (v: number) => PAD.top + plotH - (v / max) * plotH;
  // Courbe lissée (Catmull-Rom → Bézier), sans dépasser l'axe zéro
  const pts = hours.map((h, i) => [x(i), y(h.count)] as const);
  let line = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const [x0, y0] = pts[Math.max(0, i - 1)];
    const [x1, y1] = pts[i];
    const [x2, y2] = pts[i + 1];
    const [x3, y3] = pts[Math.min(pts.length - 1, i + 2)];
    const c1y = Math.min(y(0), y1 + (y2 - y0) / 6);
    const c2y = Math.min(y(0), y2 - (y3 - y1) / 6);
    line += ` C${x1 + (x2 - x0) / 6},${c1y} ${x2 - (x3 - x1) / 6},${c2y} ${x2},${y2}`;
  }
  const area = `${line} L${pts[pts.length - 1][0]},${y(0)} L${pts[0][0]},${y(0)} Z`;

  return (
    <figure className="chart">
      <div className="chart-total">
        <strong>{formatNumber(total)}</strong>
        <span>{total ? `échecs en 24 h · pic à ${peak.label} (${formatNumber(peak.count)})` : "échec en 24 h"}</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Échecs d'authentification par heure sur 24 heures">
        <defs>
          <linearGradient id={gradient} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" className="stop-accent" stopOpacity="0.45" />
            <stop offset="100%" className="stop-accent" stopOpacity="0" />
          </linearGradient>
        </defs>
        <Grid max={max} y={y} />
        <path d={area} fill={`url(#${gradient})`} className="area" />
        <path d={line} className="line" />
        {hours.map((h, i) => (
          <g key={i}>
            {h.count > 0 && h === peak && <circle cx={x(i)} cy={y(h.count)} r={4} className="point" />}
            <rect x={x(i) - step / 2} y={PAD.top} width={step} height={plotH} fill="transparent">
              <title>{`${h.label} : ${formatNumber(h.count)} échecs`}</title>
            </rect>
            {i % 3 === 0 && (
              <text x={x(i)} y={H - 6} textAnchor="middle" className="tick">
                {h.label}
              </text>
            )}
          </g>
        ))}
      </svg>
    </figure>
  );
}
