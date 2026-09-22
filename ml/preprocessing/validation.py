from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from ml.data.config import DatasetPipelineConfig
from ml.preprocessing.labels import build_label_mapping, normalize_label


@dataclass
class ValidationIssue:
    code: str
    message: str
    severity: str = "error"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class ValidationReport:
    issues: list[ValidationIssue] = field(default_factory=list)
    excluded_columns: list[str] = field(default_factory=list)
    excluded_records: dict[str, int] = field(default_factory=dict)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def passed(self) -> bool:
        return not self.errors

    def add_error(self, code: str, message: str, **details: Any) -> None:
        self.issues.append(ValidationIssue(code, message, "error", details))

    def add_warning(self, code: str, message: str, **details: Any) -> None:
        self.issues.append(ValidationIssue(code, message, "warning", details))

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "issues": [issue.to_dict() for issue in self.issues],
            "excluded_columns": self.excluded_columns,
            "excluded_records": self.excluded_records,
        }


class ValidationError(RuntimeError):
    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        messages = "; ".join(issue.message for issue in report.errors)
        super().__init__(messages or "Dataset validation failed.")


class DatasetValidator:
    def __init__(self, config: DatasetPipelineConfig) -> None:
        self.config = config

    def validate(self, dataset: pd.DataFrame) -> ValidationReport:
        report = ValidationReport()
        self._validate_non_empty(dataset, report)
        self._validate_required_columns(dataset, report)

        if self.config.label_column in dataset.columns:
            self._validate_labels(dataset, report)

        numeric_columns = self._numeric_feature_columns(dataset)
        report.excluded_columns = self._excluded_columns(dataset)
        self._validate_numeric_features(dataset, numeric_columns, report)
        self._validate_duplicates(dataset, report)
        self._validate_protocol_consistency(dataset, report)
        return report

    def assert_valid(self, dataset: pd.DataFrame) -> ValidationReport:
        report = self.validate(dataset)
        if not report.passed:
            raise ValidationError(report)
        return report

    def _validate_non_empty(self, dataset: pd.DataFrame, report: ValidationReport) -> None:
        if dataset.empty:
            report.add_error("empty_dataset", "Dataset contains no records.")
        if len(dataset.columns) == 0:
            report.add_error("empty_schema", "Dataset contains no columns.")

    def _validate_required_columns(self, dataset: pd.DataFrame, report: ValidationReport) -> None:
        missing = [column for column in self.config.required_columns if column not in dataset.columns]
        if missing:
            report.add_error(
                "missing_required_columns",
                "Dataset is missing required columns.",
                columns=missing,
            )

    def _validate_labels(self, dataset: pd.DataFrame, report: ValidationReport) -> None:
        label_column = self.config.label_column
        missing_count = int(dataset[label_column].isna().sum())
        if missing_count:
            report.add_error(
                "missing_labels",
                "Label column contains missing values.",
                column=label_column,
                missing_count=missing_count,
            )

        normalized = dataset[label_column].dropna().map(normalize_label)
        if normalized.empty:
            report.add_error("no_labels", "No usable labels were found.")
            return

        mapping = build_label_mapping(self.config.normal_labels, self.config.ddos_labels)
        unique_labels = sorted(set(normalized))
        unmapped = [label for label in unique_labels if label not in mapping]
        if unmapped:
            report.add_error(
                "unmapped_labels",
                "Some labels cannot be mapped to the documented O2 binary interpretation.",
                labels=unmapped,
                documented_normal_labels=list(self.config.normal_labels),
                documented_ddos_labels=list(self.config.ddos_labels),
            )

    def _numeric_feature_columns(self, dataset: pd.DataFrame) -> list[str]:
        excluded = set(self.config.excluded_columns) | {self.config.label_column}
        return [
            column
            for column in dataset.columns
            if column not in excluded and pd.api.types.is_numeric_dtype(dataset[column])
        ]

    def _excluded_columns(self, dataset: pd.DataFrame) -> list[str]:
        excluded = set(self.config.excluded_columns)
        excluded.add(self.config.label_column)
        return [column for column in dataset.columns if column in excluded]

    def _validate_numeric_features(
        self,
        dataset: pd.DataFrame,
        numeric_columns: list[str],
        report: ValidationReport,
    ) -> None:
        if not numeric_columns:
            report.add_error(
                "no_numeric_features",
                "No numeric feature columns are available after excluding identifiers and labels.",
            )
            return

        numeric = dataset[numeric_columns]
        missing_by_column = numeric.isna().sum()
        missing = {
            column: int(count)
            for column, count in missing_by_column.items()
            if int(count) > 0
        }
        if missing:
            report.add_warning(
                "missing_numeric_values",
                "Numeric feature columns contain missing values that preprocessing will impute.",
                columns=missing,
            )

        infinite_counts = np.isinf(numeric.to_numpy(dtype=float, copy=True)).sum(axis=0)
        infinite = {
            column: int(count)
            for column, count in zip(numeric_columns, infinite_counts)
            if int(count) > 0
        }
        if infinite:
            if getattr(self.config, "allow_infinite_numeric", False):
                report.add_warning(
                    "infinite_numeric_values",
                    "Numeric feature columns contain infinite values that preprocessing will replace and impute.",
                    columns=infinite,
                )
            else:
                report.add_error(
                    "infinite_numeric_values",
                    "Numeric feature columns contain infinite values.",
                    columns=infinite,
                )

    def _validate_duplicates(self, dataset: pd.DataFrame, report: ValidationReport) -> None:
        duplicate_count = int(dataset.duplicated().sum())
        report.excluded_records["duplicate_rows"] = (
            duplicate_count if self.config.drop_duplicate_rows else 0
        )
        if duplicate_count:
            report.add_warning(
                "duplicate_rows",
                "Dataset contains duplicate rows.",
                duplicate_count=duplicate_count,
                drop_duplicate_rows=self.config.drop_duplicate_rows,
            )

    def _validate_protocol_consistency(
        self,
        dataset: pd.DataFrame,
        report: ValidationReport,
    ) -> None:
        protocol_column = next(
            (column for column in ("Protocol", "ProtocolName") if column in dataset.columns),
            None,
        )
        if protocol_column is None:
            return

        missing_count = int(dataset[protocol_column].isna().sum())
        if missing_count:
            report.add_warning(
                "missing_protocol_values",
                "Protocol column contains missing values.",
                column=protocol_column,
                missing_count=missing_count,
            )

        if pd.api.types.is_numeric_dtype(dataset[protocol_column]):
            invalid = dataset[
                (dataset[protocol_column] < 0) | (dataset[protocol_column] > 255)
            ]
            if not invalid.empty:
                report.add_error(
                    "invalid_protocol_values",
                    "Numeric protocol values must be in the range 0 to 255.",
                    column=protocol_column,
                    invalid_count=int(len(invalid)),
                )
