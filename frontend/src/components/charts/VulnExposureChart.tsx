import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { RISK_HEX } from "@/lib/riskBands";
import { chartColors, tooltipStyle } from "./chartUtils";

interface VulnExposureChartProps {
  bands: Record<string, number>;
}

const ROWS = [
  { key: "critical", label: "Critical (9.0+)", color: RISK_HEX.CRITICAL },
  { key: "high", label: "High (7.0–8.9)", color: RISK_HEX.HIGH },
  { key: "medium", label: "Medium (4.0–6.9)", color: RISK_HEX.MEDIUM },
  { key: "low", label: "Low (0.1–3.9)", color: RISK_HEX.LOW },
];

export function VulnExposureChart({ bands }: VulnExposureChartProps) {
  const data = ROWS.map((r) => ({ label: r.label, count: bands?.[r.key] ?? 0, color: r.color }));
  const hasData = data.some((d) => d.count > 0);
  if (!hasData) {
    return (
      <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
        No vulnerability data
      </div>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} horizontal={false} />
        <XAxis type="number" stroke={chartColors.axis} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="label"
          stroke={chartColors.axis}
          fontSize={11}
          tickLine={false}
          axisLine={false}
          width={110}
        />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "hsl(var(--muted))", opacity: 0.4 }} />
        <Bar dataKey="count" name="Vulnerabilities" radius={[0, 4, 4, 0]} barSize={22}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
