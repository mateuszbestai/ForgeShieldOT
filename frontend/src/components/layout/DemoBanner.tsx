import { FlaskConical } from "lucide-react";

export function DemoBanner() {
  return (
    <div className="flex items-center justify-center gap-2 bg-risk-medium/15 px-4 py-1.5 text-center text-xs font-medium text-risk-medium">
      <FlaskConical className="h-3.5 w-3.5 shrink-0" />
      <span>Demonstration environment — all data is simulated / demo. No live OT systems are connected.</span>
    </div>
  );
}
