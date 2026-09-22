import json
from pathlib import Path
from typing import Any

from app.schemas.evidence import AuditRecord, EvidenceRun, EvidenceSummary, StatusCounts, StatusRecord


VALID_STATUSES = {"PASS", "FAIL", "NOT_EXECUTED", "BLOCKED"}
DISPLAY_STATUSES = {
    *VALID_STATUSES,
    "FIXTURE_ONLY",
    "EXECUTED_NON_OFFICIAL",
    "OFFICIAL_INCOMPLETE",
}


class EvidenceService:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path(__file__).resolve().parents[3]

    def _json(self, path: Path) -> dict[str, Any] | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def runs(self) -> list[EvidenceRun]:
        runs: list[EvidenceRun] = []
        for base, run_type in (("evidence/acceptance/runs", "acceptance"), ("evidence/negative_tests/runs", "negative_tests")):
            directory = self.root / base
            if not directory.exists():
                continue
            for run_dir in sorted((item for item in directory.iterdir() if item.is_dir()), reverse=True):
                result = self._json(run_dir / "result.json") or {}
                manifest = self._json(run_dir / "evidence_manifest.json") or {}
                status = str(result.get("status", manifest.get("status", "NOT_AVAILABLE")))
                if status not in VALID_STATUSES and status != "NOT_AVAILABLE":
                    status = "NOT_AVAILABLE"
                records = result.get("kpis") or result.get("tests") or {}
                runs.append(EvidenceRun(
                    run_id=str(result.get("run_id", run_dir.name)),
                    run_type=str(result.get("run_type", run_type)),
                    created_at=result.get("recorded_at_utc"),
                    framework_version=None,
                    configuration_hash=result.get("configuration_hash", manifest.get("configuration_hash")),
                    fixture_only=bool(result.get("fixture_only", manifest.get("fixture_only", False))),
                    official_result=bool(result.get("official_cyber14_kpi_result", False) or result.get("official_cyber14_negative_test_result", False)),
                    status=status,
                    artifact_names=sorted(path.name for path in run_dir.iterdir() if path.is_file()),
                    record_counts={run_type: len(records) if isinstance(records, dict) else 0},
                ))
        return runs

    def _latest_result(self, run_type: str) -> tuple[dict[str, Any], dict[str, Any], str | None, Path | None]:
        candidates = [run for run in self.runs() if run.run_type == run_type]
        if not candidates:
            return {}, {}, None, None
        run = candidates[0]
        run_dir = self.root / "evidence" / ("acceptance" if run_type == "acceptance" else "negative_tests") / "runs" / run.run_id
        result = self._json(run_dir / "result.json") or {}
        manifest = self._json(run_dir / "evidence_manifest.json") or {}
        return result, manifest, run.run_id, run_dir

    def kpis(self) -> list[StatusRecord]:
        result, manifest, run_id, run_dir = self._latest_result("acceptance")
        records = result.get("kpis", {})
        return [self._status_record(kpi_id, records.get(kpi_id), result, manifest, run_id, run_dir) for kpi_id in [f"KPI-{index}" for index in range(1, 7)]]

    def acceptance(self) -> list[StatusRecord]:
        result, manifest, run_id, run_dir = self._latest_result("acceptance")
        records = result.get("acceptance_conditions", {})
        return [self._status_record(item, records.get(item), result, manifest, run_id, run_dir) for item in [f"AC-{index}" for index in range(1, 5)]]

    def negative_tests(self) -> list[StatusRecord]:
        result, manifest, run_id, run_dir = self._latest_result("negative_tests")
        records = result.get("tests", {})
        return [self._status_record(item, records.get(item), result, manifest, run_id, run_dir) for item in [f"NT-{index}" for index in range(1, 6)]]

    def _evidence_references_exist(self, evidence: Any, run_dir: Path | None) -> bool:
        if not evidence:
            return False
        if run_dir is None:
            return False
        references: list[str] = []
        values = evidence if isinstance(evidence, list) else [evidence]
        for value in values:
            if isinstance(value, str):
                references.append(value)
            elif isinstance(value, dict):
                reference = value.get("path") or value.get("reference") or value.get("file")
                if reference:
                    references.append(str(reference))
        return all((run_dir / reference).exists() for reference in references) if references else True

    def _official_evidence_complete(
        self,
        record: dict[str, Any],
        result: dict[str, Any],
        manifest: dict[str, Any],
        run_dir: Path | None,
    ) -> bool:
        run_type = str(result.get("run_type", manifest.get("run_type", "")))
        official_flag = (
            result.get("official_cyber14_negative_test_result", False)
            if run_type == "negative_tests"
            else result.get("official_cyber14_kpi_result", False)
        )
        fixture_only = bool(result.get("fixture_only", manifest.get("fixture_only", False)))
        run_fields_present = all(
            (
                result.get("configuration_hash") or manifest.get("configuration_hash"),
                result.get("configuration_reference") or manifest.get("configuration_reference"),
                result.get("input_references") or manifest.get("input_references"),
                result.get("output_references") or manifest.get("output_references"),
            )
        )
        if run_type == "acceptance":
            run_fields_present = run_fields_present and bool(result.get("dataset_reference"))
        trial_count = record.get("trials", record.get("trial_count"))
        oracle = record.get("oracle", record.get("expected_safe_behavior"))
        return bool(
            official_flag
            and not fixture_only
            and run_fields_present
            and self._evidence_references_exist(record.get("evidence"), run_dir)
            and record.get("threshold") is not None
            and isinstance(trial_count, int)
            and trial_count > 0
            and oracle
        )

    def _status_record(
        self,
        identifier: str,
        record: dict[str, Any] | None,
        result: dict[str, Any],
        manifest: dict[str, Any],
        run_id: str | None,
        run_dir: Path | None,
    ) -> StatusRecord:
        record = record or {}
        raw_status = record.get("status", "NOT_EXECUTED")
        if raw_status not in VALID_STATUSES:
            raw_status = "NOT_EXECUTED"
        fixture_only = bool(record.get("fixture_only", result.get("fixture_only", manifest.get("fixture_only", False))))
        official_complete = self._official_evidence_complete(record, result, manifest, run_dir)
        if raw_status in {"NOT_EXECUTED", "BLOCKED"}:
            status = raw_status
        elif fixture_only:
            status = "FIXTURE_ONLY"
        elif not bool(record.get("official_result", False)):
            status = "EXECUTED_NON_OFFICIAL"
        elif not official_complete:
            status = "OFFICIAL_INCOMPLETE"
        else:
            status = raw_status
        reason = record.get("reason")
        if status == "OFFICIAL_INCOMPLETE" and not reason:
            reason = "Stored result lacks complete authoritative evidence."
        official_result = bool(record.get("official_result", False)) and official_complete
        return StatusRecord(
            id=identifier,
            name=str(record.get("description", identifier)),
            status=status,
            description=record.get("description"),
            measured_value=record.get("observed"),
            threshold=record.get("threshold"),
            trials=record.get("trials", record.get("trial_count")),
            condition=record.get("condition"),
            evidence_available=self._evidence_references_exist(record.get("evidence"), run_dir),
            official_result=official_result,
            fixture_only=fixture_only,
            reason=reason,
            run_id=run_id,
        )

    @staticmethod
    def counts(records: list[StatusRecord]) -> StatusCounts:
        return StatusCounts(
            total=len(records),
            passed=sum(record.status == "PASS" for record in records),
            failed=sum(record.status == "FAIL" for record in records),
            not_executed=sum(record.status == "NOT_EXECUTED" for record in records),
            blocked=sum(record.status == "BLOCKED" for record in records),
        )

    def summary(self) -> EvidenceSummary:
        runs = self.runs()
        kpis = self.kpis()
        acceptance = self.acceptance()
        negative = self.negative_tests()
        fixture = bool(runs) and all(run.fixture_only for run in runs)
        evidence_complete = bool(runs) and all(
            record.status in {"PASS", "FAIL"} and record.official_result
            for record in [*kpis, *acceptance, *negative]
        )
        state = (
            "NOT_AVAILABLE"
            if not runs
            else "FIXTURE_ONLY"
            if fixture
            else "OFFICIAL_COMPLETE"
            if evidence_complete
            else "PARTIAL"
        )
        return EvidenceSummary(
            state=state,
            available_runs=len(runs),
            latest_run_id=runs[0].run_id if runs else None,
            fixture_only=fixture,
            official_result_eligible=any(run.official_result and not run.fixture_only for run in runs),
            evidence_complete=evidence_complete,
            generated_at=runs[0].created_at if runs else None,
            counts={"kpis": len(kpis), "acceptance_conditions": len(acceptance), "negative_tests": len(negative), "audit_records": 0},
        )

    def audit(self, records: list[dict[str, Any]], limit: int, decision: str | None = None) -> list[AuditRecord]:
        filtered = records if not decision else [record for record in records if record.get("action") == decision]
        return [AuditRecord.model_validate(record) for record in filtered[-limit:][::-1]]
