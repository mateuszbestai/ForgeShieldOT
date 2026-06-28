import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { chartColors, tooltipStyle } from "./chartUtils";

export interface AttckRow {
  technique: string;
  count: number;
}

export function AttckIcsCoverageChart({ data }: { data: AttckRow[] }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
        No ATT&CK ICS detections
      </div>
    );
  }
  const top = [...data].sort((a, b) => b.count - a.count).slice(0, 8);
  const height = Math.max(200, top.length * 32);
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={top} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} horizontal={false} />
        <XAxis type="number" stroke={chartColors.axis} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="technique"
          stroke={chartColors.axis}
          fontSize={11}
          tickLine={false}
          axisLine={false}
          width={130}
        />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "hsl(var(--muted))", opacity: 0.4 }} />
        <Bar dataKey="count" name="Detections" fill="hsl(var(--primary))" radius={[0, 4, 4, 0]} barSize={18} />
      </BarChart>
    </ResponsiveContainer>
  );
}
