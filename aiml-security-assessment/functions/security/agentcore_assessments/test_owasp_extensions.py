"""
Tests for agentcore_owasp_extensions (Phase 2a).

Runs from inside agentcore_assessments/:
    python -m pytest test_agentcore_owasp_extensions.py -v
"""

from __future__ import annotations

import pytest

from owasp_extensions import evaluate_ecr_scan_on_push


def _repo(name: str, scan_on_push: bool = True):
    return {
        "repositoryName": name,
        "imageScanningConfiguration": {"scanOnPush": scan_on_push},
    }


def _by_status(findings, status):
    return [f for f in findings if f["Status"] == status]


class TestEcrScanOnPush:
    def test_all_scanned_passes(self):
        out = evaluate_ecr_scan_on_push([
            _repo("agentcore-runtime-1", True),
            _repo("agentcore-runtime-2", True),
        ])
        passed = _by_status(out, "Passed")
        assert len(passed) == 1
        assert passed[0]["Check_ID"] == "OW-16"
        assert "Enabled" in passed[0]["Finding"]

    def test_none_scanned_fails(self):
        out = evaluate_ecr_scan_on_push([
            _repo("agentcore-runtime-1", False),
            _repo("agentcore-runtime-2", False),
        ])
        failed = _by_status(out, "Failed")
        assert len(failed) == 1
        assert failed[0]["Check_ID"] == "OW-16"
        assert "agentcore-runtime-1" in failed[0]["Finding_Details"]
        assert "agentcore-runtime-2" in failed[0]["Finding_Details"]

    def test_mixed_produces_fail_and_partial_pass(self):
        out = evaluate_ecr_scan_on_push([
            _repo("agentcore-good", True),
            _repo("agentcore-bad", False),
        ])
        failed = _by_status(out, "Failed")
        passed = _by_status(out, "Passed")
        assert len(failed) == 1
        assert len(passed) == 1
        assert "agentcore-bad" in failed[0]["Finding_Details"]
        assert "agentcore-good" in passed[0]["Finding_Details"]

    def test_missing_config_treated_as_unscanned(self):
        out = evaluate_ecr_scan_on_push([
            {"repositoryName": "no-config"},  # no imageScanningConfiguration key
        ])
        failed = _by_status(out, "Failed")
        assert len(failed) == 1
        assert "no-config" in failed[0]["Finding_Details"]

    def test_empty_repo_list_returns_na(self):
        out = evaluate_ecr_scan_on_push([])
        assert len(out) == 1
        assert out[0]["Check_ID"] == "OW-16"
        assert out[0]["Status"] == "N/A"

    def test_compliance_mapping_auto_attached(self):
        out = evaluate_ecr_scan_on_push([_repo("agentcore-x", False)])
        failed = _by_status(out, "Failed")
        mappings = failed[0]["Compliance_Mappings"]
        assert any(m["control_id"] == "LLM03" for m in mappings)
        assert mappings[0]["coverage_type"] == "partial-app-layer"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
