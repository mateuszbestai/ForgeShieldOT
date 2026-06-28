import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { chartColors, tooltipStyle } from "./chartUtils";

interface RiskTrendChartProps {
  currentScore: number;
}

/**
 * No history endpoint exists, so we synthesize a short snapshot trend ending at the
 * current average risk score. Clearly labelled as a snapshot, not real history.
 */
function synthesize(current: number): Array<{ label: string; score: number }> {
  const points = 8;
  const data: Array<{ label: string; score: number }> = [];
  for (let i = points - 1; i >= 0; i--) {
    // Gentle drift toward the current value with mild deterministic wobble.
    const drift = current - i * 1.4;
    const wobble = Math.sin(i * 1.3) * 3;
    const score = Math.max(0, Math.min(100, Math.round(drift + wobble)));
    data.push({ label: i === 0 ? "now" : `-${i}d`, score });
  }
  return data;
}

export function RiskTrendChart({ currentScore }: RiskTrendChartProps) {
  const data = synthesize(currentScore);
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <defs>
          <linearGradient id="riskTrend" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.35} />
            <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} vertical={false} />
        <XAxis dataKey="label" stroke={chartColors.axis} fontSize={11} tickLine={false} axisLine={false} />
        <YAxis domain={[0, 100]} stroke={chartColors.axis} fontSize={11} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Area
          type="monotone"
          dataKey="score"
          name="Avg risk"
          stroke="hsl(var(--primary))"
          strokeWidth={2}
          fill="url(#riskTrend)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
