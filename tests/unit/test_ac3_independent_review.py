"""
Unit tests for CYBER-14 AC-3 Independent Review Package & Sign-off Validation.
Verifies the 12-section package structure, checklist validation, placeholder rejection,
and the state machine for AC-3 evaluation.
"""

import json
import pytest
from pathlib import Path
from ml.evaluation.acceptance_criteria import (
    generate_independent_review_package,
    validate_reviewer_signoff,
    evaluate_ac3_independent_acceptance_prep,
    REQUIRED_CHECKLIST_ITEMS,
)


def test_independent_review_package_12_sections():
    """Verify that generate_independent_review_package produces all 12 authoritative sections."""
    pkg = generate_independent_review_package()
    
    expected_sections = [
        "project_scope",
        "test_environment",
        "dataset_references",
        "model_references",
        "mitigation_policy",
        "acceptance_criteria",
        "kpi_results",
        "negative_test_results",
        "expected_oracles",
        "evidence_artifact_references",
        "reproduction_instructions",
        "independent_reviewer_signoff"
    ]
    
    for section in expected_sections:
        assert section in pkg, f"Missing required section: {section}"
        assert pkg[section] is not None, f"Section {section} is empty/None"
    
    assert len(pkg) == 12


def test_reviewer_signoff_template_exists_and_matches():
    """Verify the template file exists and has all 12 checklist keys."""
    template_path = Path("evidence/acceptance/reviewer_signoff_template.json")
    assert template_path.exists(), "Template file missing"
    
    data = json.loads(template_path.read_text(encoding="utf-8"))
    checklist = data.get("verification_checklist", {})
    
    for item in REQUIRED_CHECKLIST_ITEMS:
        assert item in checklist, f"Checklist missing item: {item}"
        assert checklist[item] is False, f"Template item {item} must default to False"


def test_missing_signoff_yields_not_executed(tmp_path):
    """Verify that with no sign-off data, AC-3 evaluates to NOT_EXECUTED."""
    res = evaluate_ac3_independent_acceptance_prep(output_dir=tmp_path, reviewer_signoff=None)
    assert res["status"] == "NOT_EXECUTED"
    assert "PENDING" in res["observed_result"]["signoff_status"] or "pending" in res["reasons"][0].lower()


def test_placeholder_signoff_rejected():
    """Verify that placeholder/TBD sign-offs are rejected."""
    placeholder_data = {
        "reviewer_name": "TBD",
        "organization": "Sample Org",
        "signoff_date_utc": "2026-10-01T00:00:00Z",
        "determination": "APPROVED",
        "signature_hash": "placeholder_hash",
        "checklist_verified": {k: True for k in REQUIRED_CHECKLIST_ITEMS}
    }
    
    valid, msg = validate_reviewer_signoff(placeholder_data)
    assert not valid
    assert "placeholder" in msg.lower() or "invalid" in msg.lower() or "signature" in msg.lower() or "name" in msg.lower()


def test_incomplete_checklist_rejected():
    """Verify that if even 1 checklist item is False, sign-off is rejected."""
    incomplete_checklist = {k: True for k in REQUIRED_CHECKLIST_ITEMS}
    incomplete_checklist["secrets_audit_zero_leaks_verified"] = False
    
    data = {
        "reviewer_name": "Dr. Alice Smith",
        "organization": "Independent Cyber Audit Lab",
        "signoff_date_utc": "2026-10-01T12:00:00Z",
        "determination": "APPROVED",
        "signature_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "checklist_verified": incomplete_checklist
    }
    
    valid, msg = validate_reviewer_signoff(data)
    assert not valid
    assert "checklist" in msg.lower() or "secrets_audit_zero_leaks_verified" in msg


def test_valid_human_signoff_evaluates_to_pass(tmp_path):
    """Verify that a genuine complete sign-off transitions AC-3 to PASS."""
    full_checklist = {k: True for k in REQUIRED_CHECKLIST_ITEMS}
    
    valid_data = {
        "reviewer_name": "Dr. Alice Smith",
        "organization": "Independent Cyber Audit Lab",
        "signoff_date_utc": "2026-10-01T12:00:00Z",
        "determination": "APPROVED",
        "signature_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "checklist_verified": full_checklist,
        "comments": "Full independent forensic validation complete. All 12 criteria verified."
    }
    
    res = evaluate_ac3_independent_acceptance_prep(output_dir=tmp_path, reviewer_signoff=valid_data)
    assert res["status"] == "PASS"
    assert res["metrics"]["is_signed"] is True
    assert res["metrics"]["checklist_items_count"] == 12
    assert "approved" in res["reasons"][0].lower()
