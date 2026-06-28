import { cn } from "@/lib/utils";

interface StatProps {
  label: string;
  value: React.ReactNode;
  className?: string;
  mono?: boolean;
}

export function Stat({ label, value, className, mono }: StatProps) {
  return (
    <div className={cn("space-y-0.5", className)}>
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className={cn("text-sm font-medium", mono && "font-mono")}>
        {value === null || value === undefined || value === "" ? (
          <span className="text-muted-foreground">—</span>
        ) : (
          value
        )}
      </dd>
    </div>
  );
}
