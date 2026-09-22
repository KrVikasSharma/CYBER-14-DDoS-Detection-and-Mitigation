import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from ml.data.config import DatasetPipelineConfig
from ml.preprocessing.validation import ValidationReport


def build_schema_information(dataset: pd.DataFrame) -> dict[str, Any]:
    return {
        "row_count": int(len(dataset)),
        "column_count": int(len(dataset.columns)),
        "columns": [
            {
                "name": str(column),
                "dtype": str(dataset[column].dtype),
                "missing_count": int(dataset[column].isna().sum()),
            }
            for column in dataset.columns
        ],
    }


def build_provenance_record(
    config: DatasetPipelineConfig,
    files: list[Path],
    raw_dataset: pd.DataFrame,
    processed_dataset: pd.DataFrame,
    validation_report: ValidationReport,
) -> dict[str, Any]:
    return {
        "dataset_name": config.dataset_name,
        "source_reference": config.source_reference,
        "local_path": str(config.input_path),
        "access_download_date": config.access_download_date,
        "dataset_version": config.dataset_version,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_names": [str(file) for file in files],
        "schema_information": build_schema_information(raw_dataset),
        "processed_schema_information": build_schema_information(processed_dataset),
        "preprocessing_transformations": list(config.transformations),
        "excluded_columns": validation_report.excluded_columns,
        "excluded_records": validation_report.excluded_records,
        "configuration_used": config.to_metadata(),
        "validation_summary": validation_report.to_dict(),
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
