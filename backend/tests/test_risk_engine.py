"""Pure-function tests for the explainable OT risk engine."""
from __future__ import annotations

import uuid

import pytest

from app.core.enums import (
    Criticality,
    ImpactLevel,
    PatchStatus,
    PurdueLevel,
    RiskBand,
    Severity,
    SupportStatus,
)
from app.services.risk_engine import RiskInput, compute_risk


def benign_input(**overrides) -> RiskInput:
    """A fully benign, isolated asset: should score LOW with minimal factors."""
    base = dict(
        asset_id=uuid.uuid4(),
        asset_tag="BENIGN-01",
        criticality=Criticality.LOW,
        safety_impact=ImpactLevel.NONE,
        business_impact=ImpactLevel.NONE,
        purdue_level=int(PurdueLevel.L3),
        internet_reachable=False,
        it_reachable=False,
        remote_access_enabled=False,
        support_status=SupportStatus.SUPPORTED,
        patch_status=PatchStatus.CURRENT,
        backup_available=True,
        has_owner=True,
    )
    base.update(overrides)
    return RiskInput(**base)


def keys(result) -> set[str]:
    return {f.key for f in result.factors}


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #
def test_isolated_benign_asset_is_low():
    result = compute_risk(benign_input())
    assert result.band == RiskBand.LOW
    assert result.score < 35
    # Only the (low) criticality factor should contribute.
    assert keys(result) <= {"criticality"}


# --------------------------------------------------------------------------- #
# Each factor contributes only when its condition holds
# --------------------------------------------------------------------------- #
def test_criticality_factor_contributes():
    low = compute_risk(benign_input(criticality=Criticality.LOW)).score
    high = compute_risk(benign_input(criticality=Criticality.SAFETY_CRITICAL)).score
    assert high > low


def test_safety_impact_factor_contributes():
    r = compute_risk(benign_input(safety_impact=ImpactLevel.HIGH))
    assert "safety_impact" in keys(r)
    assert r.score > compute_risk(benign_input()).score


def test_business_impact_factor_contributes():
    r = compute_risk(benign_input(business_impact=ImpactLevel.HIGH))
    assert "business_impact" in keys(r)


def test_kev_factor_contributes():
    r = compute_risk(benign_input(has_kev_open=True, kev_refs=["vuln:CVE-2024-50004"]))
    assert "known_exploited_vuln" in keys(r)


def test_high_cvss_without_kev_contributes_exposure():
    r = compute_risk(benign_input(max_open_cvss=9.5, cvss_ref="vuln:CVE-9"))
    assert "cvss_exposure" in keys(r)
    # CVSS >= 9 without KEV adds a (smaller) critical-severity vuln factor too.
    assert "known_exploited_vuln" in keys(r)


def test_network_exposure_internet_contributes():
    r = compute_risk(benign_input(internet_reachable=True))
    assert "network_exposure" in keys(r)


def test_network_exposure_prefers_internet_over_it():
    internet = compute_risk(benign_input(internet_reachable=True, it_reachable=True))
    it_only = compute_risk(benign_input(it_reachable=True))
    # internet exposure (12) should outscore IT-only exposure (8).
    assert internet.score > it_only.score


def test_purdue_inversion_contributes():
    r = compute_risk(benign_input(purdue_level=int(PurdueLevel.L1), internet_reachable=True))
    assert "purdue_inversion" in keys(r)


def test_unsupported_platform_contributes():
    r = compute_risk(benign_input(support_status=SupportStatus.UNSUPPORTED))
    assert "unsupported_platform" in keys(r)
    r2 = compute_risk(benign_input(patch_status=PatchStatus.EOL))
    assert "unsupported_platform" in keys(r2)


def test_unauthorized_change_contributes():
    r = compute_risk(
        benign_input(unauthorized_change_open=True, change_refs=["config_change:1"])
    )
    assert "unauthorized_change" in keys(r)


def test_malware_detection_contributes():
    r = compute_risk(
        benign_input(max_malware_severity=Severity.CRITICAL, malware_refs=["detection:1"])
    )
    assert "malware_detection" in keys(r)


def test_missing_backup_contributes():
    r = compute_risk(benign_input(backup_available=False))
    assert "missing_backup" in keys(r)


def test_missing_owner_only_matters_for_important_assets():
    low_no_owner = compute_risk(benign_input(criticality=Criticality.LOW, has_owner=False))
    assert "missing_owner" not in keys(low_no_owner)
    high_no_owner = compute_risk(benign_input(criticality=Criticality.HIGH, has_owner=False))
    assert "missing_owner" in keys(high_no_owner)


def test_compliance_gap_contributes():
    r = compute_risk(benign_input(failed_controls_linked=2, control_refs=["control:SR 5.1"]))
    assert "compliance_gap" in keys(r)


# --------------------------------------------------------------------------- #
# Clamping & bands
# --------------------------------------------------------------------------- #
def test_fully_stacked_input_clamps_to_critical_100():
    result = compute_risk(
        benign_input(
            criticality=Criticality.SAFETY_CRITICAL,
            safety_impact=ImpactLevel.HIGH,
            business_impact=ImpactLevel.HIGH,
            purdue_level=int(PurdueLevel.L1),
            internet_reachable=True,
            it_reachable=True,
            remote_access_enabled=True,
            support_status=SupportStatus.UNSUPPORTED,
            patch_status=PatchStatus.EOL,
            backup_available=False,
            has_owner=False,
            has_kev_open=True,
            max_open_cvss=10.0,
            max_malware_severity=Severity.CRITICAL,
            unauthorized_change_open=True,
            failed_controls_linked=5,
        )
    )
    assert result.score == 100
    assert result.band == RiskBand.CRITICAL


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, RiskBand.LOW),
        (34, RiskBand.LOW),
        (35, RiskBand.MEDIUM),
        (59, RiskBand.MEDIUM),
        (60, RiskBand.HIGH),
        (79, RiskBand.HIGH),
        (80, RiskBand.CRITICAL),
        (100, RiskBand.CRITICAL),
    ],
)
def test_band_thresholds(score, expected):
    from app.services.risk_engine import _band

    assert _band(score) == expected


# --------------------------------------------------------------------------- #
# Recommended action priority: malware > KEV > unauthorized-change > exposure
# --------------------------------------------------------------------------- #
def test_action_malware_takes_priority():
    r = compute_risk(
        benign_input(
            max_malware_severity=Severity.HIGH,
            has_kev_open=True,
            unauthorized_change_open=True,
            internet_reachable=True,
        )
    )
    assert "Isolate the affected endpoint" in r.recommended_action


def test_action_kev_when_no_malware():
    r = compute_risk(
        benign_input(
            has_kev_open=True,
            unauthorized_change_open=True,
            internet_reachable=True,
        )
    )
    assert "known-exploited vulnerability" in r.recommended_action


def test_action_unauthorized_change_when_no_malware_or_kev():
    r = compute_risk(
        benign_input(
            unauthorized_change_open=True,
            internet_reachable=True,
        )
    )
    assert "unauthorized configuration change" in r.recommended_action


def test_action_exposure_when_only_network():
    r = compute_risk(benign_input(internet_reachable=True))
    assert "network segmentation" in r.recommended_action.lower()
