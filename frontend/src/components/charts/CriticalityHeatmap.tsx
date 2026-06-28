import { RISK_HEX } from "@/lib/riskBands";
import { cn } from "@/lib/utils";
import type { Asset } from "@/types/api";
import { CRITICALITY_LABELS, RISK_BAND_LABELS } from "@/types/enums";

interface CriticalityHeatmapProps {
  assets: Asset[];
}

const CRITICALITIES = ["SAFETY_CRITICAL", "HIGH", "MEDIUM", "LOW"];
const BANDS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** A grid of asset counts: criticality (rows) × risk band (columns). */
export function CriticalityHeatmap({ assets }: CriticalityHeatmapProps) {
  const counts: Record<string, Record<string, number>> = {};
  let max = 0;
  for (const crit of CRITICALITIES) {
    counts[crit] = {};
    for (const band of BANDS) counts[crit][band] = 0;
  }
  for (const a of assets) {
    const crit = (a.criticality || "LOW").toUpperCase();
    const band = (a.risk_band || "LOW").toUpperCase();
    if (counts[crit] && counts[crit][band] !== undefined) {
      counts[crit][band] += 1;
      max = Math.max(max, counts[crit][band]);
    }
  }

  if (assets.length === 0) {
    return <div className="py-8 text-center text-sm text-muted-foreground">No assets</div>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-separate border-spacing-1 text-center text-xs">
        <thead>
          <tr>
            <th className="p-1 text-left font-medium text-muted-foreground">Criticality \ Risk</th>
            {BANDS.map((band) => (
              <th key={band} className="p-1 font-medium" style={{ color: RISK_HEX[band] }}>
                {RISK_BAND_LABELS[band]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {CRITICALITIES.map((crit) => (
            <tr key={crit}>
              <td className="whitespace-nowrap p-1 text-left text-muted-foreground">
                {CRITICALITY_LABELS[crit]}
              </td>
              {BANDS.map((band) => {
                const value = counts[crit][band];
                const intensity = max > 0 ? value / max : 0;
                return (
                  <td key={band} className="p-0.5">
                    <div
                      className={cn(
                        "flex h-12 items-center justify-center rounded-md border text-sm font-semibold tabular-nums",
                        value === 0 && "text-muted-foreground/40",
                      )}
                      style={{
                        backgroundColor: value === 0 ? "transparent" : RISK_HEX[band],
                        opacity: value === 0 ? 1 : 0.25 + intensity * 0.65,
                        borderColor: "hsl(var(--border))",
                      }}
                    >
                      {value}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
