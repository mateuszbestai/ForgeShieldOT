import { describe, expect, it } from "vitest";
import { bandForScore, RISK_BADGE_CLASSES, RISK_HEX } from "@/lib/riskBands";

describe("bandForScore thresholds", () => {
  it("classifies LOW below 35", () => {
    expect(bandForScore(0)).toBe("LOW");
    expect(bandForScore(34)).toBe("LOW");
  });

  it("classifies MEDIUM in [35, 60)", () => {
    expect(bandForScore(35)).toBe("MEDIUM");
    expect(bandForScore(59)).toBe("MEDIUM");
  });

  it("classifies HIGH in [60, 80)", () => {
    expect(bandForScore(60)).toBe("HIGH");
    expect(bandForScore(79)).toBe("HIGH");
  });

  it("classifies CRITICAL at 80+", () => {
    expect(bandForScore(80)).toBe("CRITICAL");
    expect(bandForScore(100)).toBe("CRITICAL");
  });

  it("has a class + hex for every band", () => {
    for (const band of ["LOW", "MEDIUM", "HIGH", "CRITICAL"]) {
      expect(RISK_BADGE_CLASSES[band]).toBeTruthy();
      expect(RISK_HEX[band]).toMatch(/^hsl\(/);
    }
  });
});
