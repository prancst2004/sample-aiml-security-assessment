"""
Unit tests for the compliance-mappings layer added in Phase 1a.

These tests are location-agnostic — they import `schema` and
`compliance_mappings` from whatever service module they are placed in
(bedrock_assessments, sagemaker_assessments, agentcore_assessments).

Run with:
    cd aiml-security-assessment/functions/security/<module>
    python -m pytest test_compliance_mappings.py -v
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from schema import Finding, SeverityEnum, StatusEnum, create_finding
from compliance_mappings import (
    CHECK_TO_COMPLIANCE_MAPPINGS,
    OWASP_LLM_VERSION,
    get_compliance_mappings,
)


# ---------------------------------------------------------------------------
# 1. Compliance-mapping table sanity
# ---------------------------------------------------------------------------

class TestMappingTable:
    """The central mapping table must be internally consistent."""

    def test_every_mapping_has_required_fields(self):
        for check_id, mappings in CHECK_TO_COMPLIANCE_MAPPINGS.items():
            for mapping in mappings:
                assert "framework" in mapping, (
                    f"{check_id}: mapping missing 'framework' key"
                )
                assert "framework_version" in mapping, (
                    f"{check_id}: mapping missing 'framework_version' key"
                )
                assert "control_id" in mapping, (
                    f"{check_id}: mapping missing 'control_id' key"
                )
                assert "coverage_type" in mapping, (
                    f"{check_id}: mapping missing 'coverage_type' key"
                )

    def test_framework_values_are_known(self):
        allowed = {"OWASP-LLM", "NIST-AI-RMF", "MITRE-ATLAS", "HIPAA", "FSI"}
        for check_id, mappings in CHECK_TO_COMPLIANCE_MAPPINGS.items():
            for m in mappings:
                assert m["framework"] in allowed, (
                    f"{check_id}: unknown framework {m['framework']}"
                )

    def test_coverage_types_are_known(self):
        allowed = {"full", "compensating", "partial-app-layer"}
        for check_id, mappings in CHECK_TO_COMPLIANCE_MAPPINGS.items():
            for m in mappings:
                assert m["coverage_type"] in allowed, (
                    f"{check_id}: unknown coverage_type {m['coverage_type']}"
                )

    def test_owasp_control_ids_are_well_formed(self):
        """OWASP LLM control IDs must match LLM01..LLM10."""
        import re
        pattern = re.compile(r"^LLM(0[1-9]|10)$")
        for check_id, mappings in CHECK_TO_COMPLIANCE_MAPPINGS.items():
            for m in mappings:
                if m["framework"] == "OWASP-LLM":
                    assert pattern.match(m["control_id"]), (
                        f"{check_id}: malformed OWASP control_id {m['control_id']}"
                    )

    def test_owasp_version_is_2025(self):
        assert OWASP_LLM_VERSION == "2025"
        for check_id, mappings in CHECK_TO_COMPLIANCE_MAPPINGS.items():
            for m in mappings:
                if m["framework"] == "OWASP-LLM":
                    assert m["framework_version"] == "2025", (
                        f"{check_id}: wrong OWASP version {m['framework_version']}"
                    )


# ---------------------------------------------------------------------------
# 2. get_compliance_mappings() lookup
# ---------------------------------------------------------------------------

class TestGetComplianceMappings:
    def test_known_check_returns_mappings(self):
        mappings = get_compliance_mappings("BR-05")
        assert len(mappings) >= 1
        assert any(m["framework"] == "OWASP-LLM" for m in mappings)

    def test_unknown_check_returns_empty_list(self):
        """Missing check_id must not raise — it should return []."""
        mappings = get_compliance_mappings("ZZ-99")
        assert mappings == []

    def test_returns_copy_not_reference(self):
        """Mutations by callers must not corrupt the central table."""
        m1 = get_compliance_mappings("BR-05")
        m1.append({"framework": "poison", "framework_version": "x",
                   "control_id": "x", "coverage_type": "full"})
        m2 = get_compliance_mappings("BR-05")
        assert len(m2) == len(m1) - 1, (
            "get_compliance_mappings must return a copy, not the "
            "underlying list reference"
        )


# ---------------------------------------------------------------------------
# 3. create_finding() behaviour
# ---------------------------------------------------------------------------

class TestCreateFinding:
    """create_finding must auto-attach mappings and stay backward-compatible."""

    BASE_KW = dict(
        finding_name="Test Finding",
        finding_details="Details",
        resolution="Fix it",
        reference="https://docs.aws.amazon.com/example.html",
        severity=SeverityEnum.HIGH,
        status=StatusEnum.FAILED,
    )

    def test_auto_attaches_mappings_for_known_check(self):
        f = create_finding(check_id="BR-05", **self.BASE_KW)
        assert "Compliance_Mappings" in f
        assert len(f["Compliance_Mappings"]) >= 1
        # BR-05 is OWASP LLM01 (full) + LLM05 (compensating)
        control_ids = {m["control_id"] for m in f["Compliance_Mappings"]}
        assert "LLM01" in control_ids
        assert "LLM05" in control_ids

    def test_auto_attaches_empty_list_for_unmapped_check(self):
        """Must not crash for checks not in the table."""
        # AC-00 is intentionally unmapped in the table
        f = create_finding(check_id="AC-00", **self.BASE_KW)
        assert f["Compliance_Mappings"] == []

    def test_explicit_mappings_override_auto(self):
        custom = [
            {"framework": "NIST-AI-RMF", "framework_version": "1.0",
             "control_id": "GOVERN 1.1", "coverage_type": "full"}
        ]
        f = create_finding(check_id="BR-05", compliance_mappings=custom,
                           **self.BASE_KW)
        assert f["Compliance_Mappings"] == custom

    def test_backward_compatible_shape(self):
        """All legacy Finding fields still present and typed correctly."""
        f = create_finding(check_id="BR-01", **self.BASE_KW)
        for key in ("Check_ID", "Finding", "Finding_Details", "Resolution",
                    "Reference", "Severity", "Status"):
            assert key in f, f"Missing required field {key}"
        assert f["Check_ID"] == "BR-01"
        assert f["Severity"] == "High"
        assert f["Status"] == "Failed"

    def test_bad_check_id_pattern_rejected(self):
        with pytest.raises(ValidationError):
            create_finding(check_id="not-valid", **self.BASE_KW)

    def test_bad_reference_url_rejected(self):
        with pytest.raises(ValidationError):
            create_finding(
                check_id="BR-01",
                finding_name="n",
                finding_details="d",
                resolution="r",
                reference="http://insecure.example.com",  # not https
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )

    def test_new_check_id_prefix_ow_accepted(self):
        """Phase-2 will add OW-XX checks. The existing regex already
        accepts 2-char prefix + 2 digits, but make that explicit."""
        f = create_finding(check_id="OW-01", **self.BASE_KW)
        assert f["Check_ID"] == "OW-01"


# ---------------------------------------------------------------------------
# 4. Finding model direct instantiation (used by the consolidator)
# ---------------------------------------------------------------------------

class TestFindingModel:
    def test_compliance_mappings_defaults_to_empty_list(self):
        f = Finding(
            Check_ID="BR-01",
            Finding="x",
            Finding_Details="x",
            Resolution="",
            Reference="https://example.com",
            Severity="High",
            Status="Failed",
        )
        assert f.Compliance_Mappings == []

    def test_compliance_mappings_accepts_list_of_dicts(self):
        mappings = [
            {"framework": "OWASP-LLM", "framework_version": "2025",
             "control_id": "LLM01", "coverage_type": "full"}
        ]
        f = Finding(
            Check_ID="BR-05",
            Finding="x",
            Finding_Details="x",
            Resolution="",
            Reference="https://example.com",
            Severity="High",
            Status="Failed",
            Compliance_Mappings=mappings,
        )
        assert len(f.Compliance_Mappings) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
