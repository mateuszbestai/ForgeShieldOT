import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RiskBadge } from "@/components/common/RiskBadge";
import { RISK_BAND_LABELS } from "@/types/enums";

describe("RiskBadge", () => {
  it("renders the human label for each band", () => {
    for (const band of ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const) {
      const { unmount } = render(<RiskBadge band={band} />);
      expect(screen.getByText(RISK_BAND_LABELS[band])).toBeInTheDocument();
      unmount();
    }
  });

  it("renders the score when provided", () => {
    render(<RiskBadge band="HIGH" score={72} />);
    expect(screen.getByText("72")).toBeInTheDocument();
  });

  it("applies the band-specific class", () => {
    const { container } = render(<RiskBadge band="CRITICAL" />);
    const badge = container.firstChild as HTMLElement;
    expect(badge.className).toContain("text-risk-critical");
  });

  it("falls back to LOW styling for an unknown band", () => {
    const { container } = render(<RiskBadge band="WEIRD" />);
    const badge = container.firstChild as HTMLElement;
    expect(badge.className).toContain("text-risk-low");
  });
});
