import {
  Background,
  Controls,
  type Edge,
  type Node,
  MiniMap,
  ReactFlow,
  type NodeProps,
  Handle,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as React from "react";
import { useNavigate } from "react-router-dom";
import { RISK_HEX } from "@/lib/riskBands";
import type { NetworkMap } from "@/types/api";
import { ASSET_TYPE_LABELS } from "@/types/enums";

const LANE_HEIGHT = 150;
const NODE_SPACING_X = 200;
const LANE_LABEL_WIDTH = 150;

const PURDUE_LABELS: Record<number, string> = {
  5: "L5 — Enterprise / Internet",
  4: "L4 — Business / IT (DMZ)",
  3: "L3 — Site operations (SCADA)",
  2: "L2 — Supervisory (HMI)",
  1: "L1 — Control (PLC/RTU)",
  0: "L0 — Process / Field",
};

type AssetNodeData = {
  label: string;
  assetType: string;
  riskBand: string;
  internetReachable: boolean;
};

function AssetNode({ data }: NodeProps) {
  const d = data as AssetNodeData;
  const color = RISK_HEX[(d.riskBand || "LOW").toUpperCase()] ?? RISK_HEX.LOW;
  return (
    <div
      className="rounded-md border-2 bg-card px-3 py-2 text-xs shadow-sm"
      style={{ borderColor: color, minWidth: 130 }}
      title={ASSET_TYPE_LABELS[d.assetType] ?? d.assetType}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="flex items-center gap-1.5">
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />
        <span className="truncate font-mono font-semibold">{d.label}</span>
      </div>
      <div className="mt-0.5 truncate text-[10px] text-muted-foreground">
        {ASSET_TYPE_LABELS[d.assetType] ?? d.assetType}
      </div>
      {d.internetReachable && (
        <div className="mt-0.5 text-[10px] font-medium text-risk-critical">Internet-reachable</div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { asset: AssetNode };

export function PurdueGraph({ map }: { map: NetworkMap }) {
  const navigate = useNavigate();

  const { nodes, edges } = React.useMemo(() => {
    // Group nodes by purdue level, then lay each level out as a horizontal lane.
    const byLevel = new Map<number, typeof map.nodes>();
    for (const n of map.nodes) {
      const lvl = n.purdue_level ?? 0;
      if (!byLevel.has(lvl)) byLevel.set(lvl, []);
      byLevel.get(lvl)!.push(n);
    }
    const levels = Array.from(byLevel.keys()).sort((a, b) => b - a); // top = high level

    const rfNodes: Node[] = [];
    levels.forEach((lvl, laneIndex) => {
      const laneNodes = byLevel.get(lvl)!;
      laneNodes.forEach((n, i) => {
        rfNodes.push({
          id: n.id,
          type: "asset",
          position: {
            x: LANE_LABEL_WIDTH + i * NODE_SPACING_X,
            y: laneIndex * LANE_HEIGHT + 30,
          },
          data: {
            label: n.label,
            assetType: n.asset_type,
            riskBand: n.risk_band,
            internetReachable: n.internet_reachable,
          },
        });
      });
    });

    const rfEdges: Edge[] = map.edges.map((e) => {
      const danger = e.is_internet_path || e.critical;
      const unknown = e.is_unknown;
      let stroke = "hsl(var(--muted-foreground))";
      if (e.is_internet_path) stroke = RISK_HEX.CRITICAL;
      else if (e.critical) stroke = RISK_HEX.HIGH;
      else if (unknown) stroke = RISK_HEX.MEDIUM;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: e.is_internet_path,
        style: {
          stroke,
          strokeWidth: danger ? 2 : 1.5,
          strokeDasharray: unknown || danger ? "6 4" : undefined,
        },
        label: e.protocol ?? undefined,
        labelStyle: { fontSize: 10, fill: "hsl(var(--muted-foreground))" },
        labelBgStyle: { fill: "hsl(var(--card))" },
      };
    });

    return { nodes: rfNodes, edges: rfEdges };
  }, [map]);

  const laneCount = new Set(map.nodes.map((n) => n.purdue_level ?? 0)).size;
  const sortedLevels = Array.from(new Set(map.nodes.map((n) => n.purdue_level ?? 0))).sort(
    (a, b) => b - a,
  );

  return (
    <div className="relative h-[640px] w-full overflow-hidden rounded-lg border bg-muted/20">
      {/* Lane labels overlay */}
      <div className="pointer-events-none absolute inset-0 z-10">
        {sortedLevels.map((lvl, i) => (
          <div
            key={lvl}
            className="absolute left-0 flex items-center border-t border-dashed border-border/60 pl-3 text-[11px] font-medium text-muted-foreground"
            style={{ top: i * LANE_HEIGHT, height: LANE_HEIGHT, width: "100%" }}
          >
            <span className="rounded bg-card/80 px-1.5 py-0.5">{PURDUE_LABELS[lvl] ?? `Level ${lvl}`}</span>
          </div>
        ))}
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.2}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, node) => navigate(`/assets/${node.id}`)}
        nodesDraggable={false}
        nodesConnectable={false}
      >
        <Background gap={20} color="hsl(var(--border))" />
        <Controls showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          nodeColor={(n) => {
            const d = n.data as AssetNodeData;
            return RISK_HEX[(d.riskBand || "LOW").toUpperCase()] ?? RISK_HEX.LOW;
          }}
          maskColor="hsl(var(--background) / 0.6)"
          style={{ backgroundColor: "hsl(var(--card))" }}
        />
      </ReactFlow>

      {laneCount === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
          No assets to map for this scope.
        </div>
      )}
    </div>
  );
}

export function NetworkLegend() {
  const items = [
    { label: "Low risk", color: RISK_HEX.LOW },
    { label: "Medium risk", color: RISK_HEX.MEDIUM },
    { label: "High risk", color: RISK_HEX.HIGH },
    { label: "Critical risk", color: RISK_HEX.CRITICAL },
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
      {items.map((it) => (
        <span key={it.label} className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: it.color }} />
          {it.label}
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-0 w-5 border-t-2 border-dashed" style={{ borderColor: RISK_HEX.CRITICAL }} />
        Internet path
      </span>
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-0 w-5 border-t-2 border-dashed" style={{ borderColor: RISK_HEX.HIGH }} />
        Critical / remote-access link
      </span>
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-0 w-5 border-t-2 border-dashed" style={{ borderColor: RISK_HEX.MEDIUM }} />
        Unknown link
      </span>
    </div>
  );
}
