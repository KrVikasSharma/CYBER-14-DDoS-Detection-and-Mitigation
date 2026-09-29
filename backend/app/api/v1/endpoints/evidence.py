import json
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.schemas.evidence import EvidenceSummary, EvidenceRun, StatusRecord, AuditRecord
from app.services.detection_service import get_detection_service
from app.services.evidence_service import EvidenceService

router = APIRouter()


def get_evidence_service() -> EvidenceService:
    return EvidenceService()


@router.get("/summary", response_model=EvidenceSummary)
async def evidence_summary(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceSummary:
    return service.summary()


@router.get("/runs", response_model=list[EvidenceRun])
async def evidence_runs(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
    service: EvidenceService = Depends(get_evidence_service),
) -> list[EvidenceRun]:
    return service.runs()


@router.get("/audit", response_model=list[AuditRecord])
async def audit_records(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    decision: Annotated[str | None, Query(max_length=32)] = None,
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
    service: EvidenceService = Depends(get_evidence_service),
) -> list[AuditRecord]:
    try:
        records = get_detection_service()._mitigation.audit.records()
    except Exception:
        records = []
    return service.audit(records, limit, decision)


@router.get("/demo-manifest")
async def get_demo_manifest(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> dict[str, Any]:
    path = Path("evidence/cic_ddos2019_demo_sample_manifest.json")
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo manifest unavailable")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@router.get("/demo-evaluation")
async def get_demo_evaluation(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> dict[str, Any]:
    path = Path("evidence/cic_ddos2019_demo_evaluation.json")
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo evaluation metrics unavailable")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@router.get("/feature-manifest")
async def get_feature_manifest(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> dict[str, Any]:
    path = Path("evidence/cic_ddos2019_feature_manifest.json")
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feature manifest unavailable")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@router.get("/acceptance-dashboard")
async def get_acceptance_dashboard(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
    service: EvidenceService = Depends(get_evidence_service),
) -> dict[str, Any]:
    """Return authoritative compliance status, KPIs, ACs, NTs, Degraded-Mode, Resource, and Limitations data."""
    return service.acceptance_dashboard()
