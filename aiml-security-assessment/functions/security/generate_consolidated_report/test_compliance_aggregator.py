"""
Tests for compliance_aggregator.py (Phase 1b).

These tests are pure-Python — no HTML, no boto3 mocks. Validates the data
shape that the report template consumes.

Run from inside generate_consolidated_report/:
    python -m pytest test_compliance_aggregator.py -v
"""

from __future__ import annotations

import pytest

from compliance_aggregator import (
    FRAMEWORK_PLACEHOLDERS,
    OWASP_LLM_CATALOG,
    aggregate_owasp_coverage,
    calculate_owasp_compliance_rate,
    count_total_controls,
    framework_badges_for_finding,
    frameworks_data_attr_for_finding,
)


def _finding(check_id: str, status: str, mappings):
    """Convenience factory — minimal finding dict."""
    return {
        "Check_ID": check_id,
        "Status": status,
        "Compliance_Mappings": mappings,
    }


def _owasp_mapping(control_id: str, coverage_type: str = "full"):
    return {
        "framework": "OWASP-LLM",
        "framework_version": "2025",
        "control_id": control_id,
        "coverage_type": coverage_type,
    }


# ---------------------------------------------------------------------------
# Catalog sanity
# ---------------------------------------------------------------------------

class TestOwaspCatalog:
    def test_has_ten_entries(self):
        assert len(OWASP_LLM_CATALOG) == 10

    def test_control_ids_are_llm01_through_llm10(self):
        expected = {f"LLM{i:02d}" for i in range(1, 11)}
        actual = {e["control_id"] for e in OWASP_LLM_CATALOG}
        assert actual == expected

    def test_every_entry_has_name_and_description(self):
        for entry in OWASP_LLM_CATALOG:
            assert entry["name"], f"Missing name: {entry}"
            assert entry["description"], f"Missing description: {entry}"
            assert entry["aws_controls"], f"Missing aws_controls: {entry}"


class TestFrameworkPlaceholders:
    def test_owasp_is_active(self):
        owasp = next(f for f in FRAMEWORK_PLACEHOLDERS if f["framework_id"] == "OWASP-LLM")
        assert owasp["status"] == "active"

    def test_others_are_planned(self):
        planned = [f for f in FRAMEWORK_PLACEHOLDERS if f["status"] == "planned"]
        assert {f["framework_id"] for f in planned} == {
            "NIST-AI-RMF",
            "MITRE-ATLAS",
            "HIPAA",
        }


# ---------------------------------------------------------------------------
# aggregate_owasp_coverage
# ---------------------------------------------------------------------------

class TestAggregateOwaspCoverage:
    def test_empty_findings_produces_ten_not_assessed(self):
        result = aggregate_owasp_coverage([])
        assert len(result) == 10
        assert all(r["status"] == "not-assessed" for r in result.values())
        assert all(r["total"] == 0 for r in result.values())

    def test_single_passed_finding_marks_compliant(self):
        findings = [_finding("BR-01", "Passed", [_owasp_mapping("LLM06")])]
        result = aggregate_owasp_coverage(findings)
        assert result["LLM06"]["status"] == "compliant"
        assert result["LLM06"]["total"] == 1
        assert result["LLM06"]["passed"] == 1
        assert result["LLM06"]["failed"] == 0

    def test_any_failed_marks_non_compliant(self):
        findings = [
            _finding("BR-05", "Passed", [_owasp_mapping("LLM01")]),
            _finding("BR-10", "Failed", [_owasp_mapping("LLM01")]),
        ]
        result = aggregate_owasp_coverage(findings)
        assert result["LLM01"]["status"] == "non-compliant"
        assert result["LLM01"]["passed"] == 1
        assert result["LLM01"]["failed"] == 1
        assert result["LLM01"]["total"] == 2

    def test_compensating_coverage_caps_at_partial(self):
        """Even if all findings passed, 'compensating' coverage must never
        show 'compliant' — that would mislead customers about LLM05."""
        findings = [
            _finding("BR-05", "Passed", [_owasp_mapping("LLM05", "compensating")]),
            _finding("BR-13", "Passed", [_owasp_mapping("LLM05", "compensating")]),
        ]
        result = aggregate_owasp_coverage(findings)
        assert result["LLM05"]["status"] == "partial"
        assert result["LLM05"]["coverage_type"] == "compensating"

    def test_partial_app_layer_coverage_caps_at_partial(self):
        findings = [
            _finding(
                "SM-08", "Passed",
                [_owasp_mapping("LLM03", "partial-app-layer")],
            ),
        ]
        result = aggregate_owasp_coverage(findings)
        assert result["LLM03"]["status"] == "partial"
        assert result["LLM03"]["coverage_type"] == "partial-app-layer"

    def test_mixed_coverage_types_picks_strictest(self):
        findings = [
            _finding("X-01", "Passed", [_owasp_mapping("LLM03", "full")]),
            _finding(
                "X-02", "Passed", [_owasp_mapping("LLM03", "partial-app-layer")],
            ),
        ]
        result = aggregate_owasp_coverage(findings)
        # partial-app-layer is stricter than full → final should be partial
        assert result["LLM03"]["coverage_type"] == "partial-app-layer"
        assert result["LLM03"]["status"] == "partial"

    def test_only_na_findings_marks_partial(self):
        findings = [_finding("BR-14", "N/A", [_owasp_mapping("LLM06")])]
        result = aggregate_owasp_coverage(findings)
        assert result["LLM06"]["status"] == "partial"
        assert result["LLM06"]["na"] == 1
        assert result["LLM06"]["total"] == 1

    def test_finding_with_multiple_mappings_counts_in_all(self):
        """BR-05 maps to both LLM01 (full) and LLM05 (compensating).
        A single 'Passed' finding should land in both buckets."""
        findings = [
            _finding(
                "BR-05", "Passed",
                [
                    _owasp_mapping("LLM01", "full"),
                    _owasp_mapping("LLM05", "compensating"),
                ],
            ),
        ]
        result = aggregate_owasp_coverage(findings)
        assert result["LLM01"]["status"] == "compliant"
        assert result["LLM05"]["status"] == "partial"

    def test_non_owasp_mappings_are_ignored(self):
        findings = [
            _finding("Y-01", "Failed", [
                {"framework": "NIST-AI-RMF", "framework_version": "1.0",
                 "control_id": "GOVERN 1.1", "coverage_type": "full"},
            ]),
        ]
        result = aggregate_owasp_coverage(findings)
        assert all(r["total"] == 0 for r in result.values())


# ---------------------------------------------------------------------------
# calculate_owasp_compliance_rate
# ---------------------------------------------------------------------------

class TestCalculateOwaspComplianceRate:
    def test_no_findings_produces_zero_rate(self):
        coverage = aggregate_owasp_coverage([])
        c, p, nc, na, rate = calculate_owasp_compliance_rate(coverage)
        assert (c, p, nc, na) == (0, 0, 0, 10)
        assert rate == 0

    def test_half_compliant(self):
        findings = []
        # 5 controls compliant
        for ctrl in ["LLM01", "LLM02", "LLM06", "LLM07", "LLM09"]:
            findings.append(_finding(f"F-{ctrl}", "Passed", [_owasp_mapping(ctrl)]))
        # 5 controls non-compliant
        for ctrl in ["LLM04", "LLM08", "LLM10"]:
            findings.append(_finding(f"F-{ctrl}", "Failed", [_owasp_mapping(ctrl)]))
        coverage = aggregate_owasp_coverage(findings)
        c, p, nc, na, rate = calculate_owasp_compliance_rate(coverage)
        assert c == 5
        assert nc == 3
        assert na == 2  # LLM03 and LLM05 never mapped in this test
        # rate = 5 / (5 + 0 + 3) = 62.5 -> 62 or 63 depending on rounding
        assert rate in {62, 63}

    def test_partial_coverage_excluded_from_compliant_count(self):
        findings = [
            _finding("F1", "Passed", [_owasp_mapping("LLM05", "compensating")]),
        ]
        coverage = aggregate_owasp_coverage(findings)
        c, p, nc, na, rate = calculate_owasp_compliance_rate(coverage)
        assert c == 0
        assert p == 1
        # 0 compliant of 1 assessable = 0%
        assert rate == 0


# ---------------------------------------------------------------------------
# framework_badges & data-attrs for table rows
# ---------------------------------------------------------------------------

class TestFrameworkBadges:
    def test_owasp_mappings_yield_owasp_class(self):
        finding = _finding(
            "BR-05", "Passed",
            [
                _owasp_mapping("LLM01"),
                _owasp_mapping("LLM05", "compensating"),
            ],
        )
        badges = framework_badges_for_finding(finding)
        assert badges == [("owasp", "LLM01"), ("owasp", "LLM05")]

    def test_nist_mapping_yields_nist_class(self):
        finding = {"Compliance_Mappings": [
            {"framework": "NIST-AI-RMF", "framework_version": "1.0",
             "control_id": "GOVERN 1.1", "coverage_type": "full"},
        ]}
        badges = framework_badges_for_finding(finding)
        assert badges == [("nist", "GOVERN 1.1")]

    def test_finding_with_no_mappings_produces_no_badges(self):
        finding = {"Compliance_Mappings": []}
        assert framework_badges_for_finding(finding) == []

    def test_data_frameworks_attr_format(self):
        finding = _finding(
            "BR-05", "Passed",
            [_owasp_mapping("LLM01"), _owasp_mapping("LLM05", "compensating")],
        )
        attr = frameworks_data_attr_for_finding(finding)
        assert attr == "owasp:LLM01 owasp:LLM05"

    def test_data_frameworks_attr_empty_when_no_mappings(self):
        assert frameworks_data_attr_for_finding({"Compliance_Mappings": []}) == ""


class TestCountTotalControls:
    def test_always_returns_ten_for_owasp(self):
        coverage = aggregate_owasp_coverage([])
        assert count_total_controls(coverage) == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
