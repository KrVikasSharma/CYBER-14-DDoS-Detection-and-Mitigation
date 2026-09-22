from fastapi import APIRouter, Depends

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.schemas.evidence import StatusCounts, StatusRecord
from app.services.evidence_service import EvidenceService

router = APIRouter()


def service() -> EvidenceService:
    return EvidenceService()


@router.get("/kpis")
async def kpis(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
    evidence: EvidenceService = Depends(service),
) -> dict[str, object]:
    records = evidence.kpis()
    return {"records": records, "counts": evidence.counts(records)}


@router.get("/acceptance")
async def acceptance(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
    evidence: EvidenceService = Depends(service),
) -> dict[str, object]:
    records = evidence.acceptance()
    return {"records": records, "counts": evidence.counts(records)}


@router.get("/negative-tests")
async def negative_tests(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
    evidence: EvidenceService = Depends(service),
) -> dict[str, object]:
    records = evidence.negative_tests()
    return {"records": records, "counts": evidence.counts(records)}
