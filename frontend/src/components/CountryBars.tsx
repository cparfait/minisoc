import { formatNumber } from "../labels";

const names = new Intl.DisplayNames(["fr"], { type: "region" });

export function countryName(code: string): string {
  try {
    return names.of(code) ?? code;
  } catch {
    return code;
  }
}

/** Répartition par pays (barres horizontales proportionnelles). */
export default function CountryBars({ rows, home = ["FR"] }: {
  rows: { country: string; failures: number; ips: number }[];
  home?: string[];
}) {
  const max = Math.max(1, ...rows.map((r) => r.failures));
  return (
    <ul className="country-bars">
      {rows.map((r) => (
        <li key={r.country}>
          <span className="country-name" title={r.country}>
            {countryName(r.country)}
          </span>
          <span className="country-track">
            <span className={`country-fill ${home.includes(r.country) ? "home" : ""}`} style={{ width: `${(r.failures / max) * 100}%` }} />
          </span>
          <span className="num">{formatNumber(r.failures)}</span>
          <span className="muted small num">{r.ips} IP</span>
        </li>
      ))}
    </ul>
  );
}
