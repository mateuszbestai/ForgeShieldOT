import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AnswerCard } from "@/components/ai/AnswerCard";
import type { AIAnswer } from "@/types/api";

const answer: AIAnswer = {
  summary: "Two safety-critical PLCs are internet-reachable.",
  findings: ["PLC-01 exposes Modbus to the internet", "No network segmentation on Level 1"],
  citations: [
    { ref: "ASSET:PLC-01", label: "PLC-01 inventory record" },
    { ref: "REL:edge-7", label: "Internet path edge" },
  ],
  confidence: "HIGH",
  assumptions: ["Inventory is current as of the demo seed"],
  safe_ot_actions: ["Review firewall ACLs in a change window", "Engage the asset owner"],
  disclaimer: "Advisory only. Do not action without OT change control.",
  provider_name: "mock",
  model_name: "demo-1",
};

describe("AnswerCard", () => {
  it("renders the confidence badge", () => {
    render(<AnswerCard answer={answer} />);
    expect(screen.getByText(/high confidence/i)).toBeInTheDocument();
  });

  it("renders the summary and findings", () => {
    render(<AnswerCard answer={answer} />);
    expect(screen.getByText(/internet-reachable/i)).toBeInTheDocument();
    expect(screen.getByText(/exposes Modbus/i)).toBeInTheDocument();
  });

  it("renders citation chips with refs and labels", () => {
    render(<AnswerCard answer={answer} />);
    expect(screen.getByText("ASSET:PLC-01")).toBeInTheDocument();
    expect(screen.getByText("PLC-01 inventory record")).toBeInTheDocument();
  });

  it("renders the safe OT actions block", () => {
    render(<AnswerCard answer={answer} />);
    expect(screen.getByText(/safe ot actions only/i)).toBeInTheDocument();
    expect(screen.getByText(/Review firewall ACLs/i)).toBeInTheDocument();
  });

  it("renders the disclaimer", () => {
    render(<AnswerCard answer={answer} />);
    expect(screen.getByText(/advisory only/i)).toBeInTheDocument();
  });
});
