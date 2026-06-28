import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { RISK_HEX } from "@/lib/riskBands";
import { chartColors, tooltipStyle } from "./chartUtils";

export interface FrameworkReadiness {
  name: string;
  readiness_pct: number;
}

function colorFor(pct: number): string {
  if (pct >= 75) return RISK_HEX.LOW;
  if (pct >= 50) return RISK_HEX.MEDIUM;
  if (pct >= 25) return RISK_HEX.HIGH;
  return RISK_HEX.CRITICAL;
}

export function ComplianceReadinessChart({ frameworks }: { frameworks: FrameworkReadiness[] }) {
  if (!frameworks || frameworks.length === 0) {
    return (
      <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
        No frameworks
      </div>
    );
  }
  const height = Math.max(220, frameworks.length * 38);
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={frameworks} layout="vertical" margin={{ top: 4, right: 32, left: 8, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} horizontal={false} />
        <XAxis type="number" domain={[0, 100]} stroke={chartColors.axis} fontSize={11} tickLine={false} axisLine={false} unit="%" />
        <YAxis
          type="category"
          dataKey="name"
          stroke={chartColors.axis}
          fontSize={11}
          tickLine={false}
          axisLine={false}
          width={120}
        />
        <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => [`${v}%`, "Readiness"]} cursor={{ fill: "hsl(var(--muted))", opacity: 0.4 }} />
        <Bar dataKey="readiness_pct" name="Readiness" radius={[0, 4, 4, 0]} barSize={20}>
          {frameworks.map((f, i) => (
            <Cell key={i} fill={colorFor(f.readiness_pct)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
