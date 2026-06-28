import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { RISK_HEX } from "@/lib/riskBands";
import { RISK_BAND_LABELS } from "@/types/enums";
import { tooltipStyle } from "./chartUtils";

interface BandDistributionProps {
  bandCounts: Record<string, number>;
}

const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function BandDistribution({ bandCounts }: BandDistributionProps) {
  const data = ORDER.map((band) => ({
    name: RISK_BAND_LABELS[band] ?? band,
    band,
    value: bandCounts?.[band] ?? 0,
  })).filter((d) => d.value > 0);

  if (data.length === 0) {
    return (
      <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
        No risk data
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          innerRadius={55}
          outerRadius={85}
          paddingAngle={2}
          stroke="hsl(var(--card))"
        >
          {data.map((d) => (
            <Cell key={d.band} fill={RISK_HEX[d.band]} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
        <Legend
          verticalAlign="bottom"
          iconType="circle"
          formatter={(value) => <span className="text-xs text-muted-foreground">{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
