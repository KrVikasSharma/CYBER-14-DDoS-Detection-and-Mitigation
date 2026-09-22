import numpy as np
import pandas as pd
import pytest

from ml.data.config import DatasetPipelineConfig
from ml.preprocessing.validation import DatasetValidator, ValidationError


def config(tmp_path, **overrides):
    values = {
        "input_path": tmp_path,
        "output_dir": tmp_path / "processed",
    }
    values.update(overrides)
    return DatasetPipelineConfig(**values)


def valid_frame():
    return pd.DataFrame(
        {
            "Flow Duration": [10.0, 20.0, 30.0],
            "Total Fwd Packets": [1, 2, 3],
            "Protocol": [6, 17, 6],
            "Label": ["BENIGN", "DrDoS_DNS", "Syn"],
        }
    )


def test_schema_validation_passes_for_minimal_valid_dataset(workspace_tmp_path):
    report = DatasetValidator(config(workspace_tmp_path)).assert_valid(valid_frame())

    assert report.passed
    assert report.errors == []


def test_schema_validation_fails_when_label_column_is_missing(workspace_tmp_path):
    dataset = valid_frame().drop(columns=["Label"])

    with pytest.raises(ValidationError) as exc:
        DatasetValidator(config(workspace_tmp_path)).assert_valid(dataset)

    assert any(issue.code == "missing_required_columns" for issue in exc.value.report.errors)


def test_missing_numeric_values_are_reported_for_imputation(workspace_tmp_path):
    dataset = valid_frame()
    dataset.loc[1, "Flow Duration"] = np.nan

    report = DatasetValidator(config(workspace_tmp_path)).assert_valid(dataset)

    assert report.passed
    assert any(issue.code == "missing_numeric_values" for issue in report.warnings)


def test_infinite_numeric_values_fail_quality_gate(workspace_tmp_path):
    dataset = valid_frame()
    dataset.loc[1, "Flow Duration"] = np.inf

    with pytest.raises(ValidationError) as exc:
        DatasetValidator(config(workspace_tmp_path)).assert_valid(dataset)

    assert any(issue.code == "infinite_numeric_values" for issue in exc.value.report.errors)


def test_unmapped_labels_fail_instead_of_guessing_ddos(workspace_tmp_path):
    dataset = valid_frame()
    dataset.loc[1, "Label"] = "UnknownAttack"

    with pytest.raises(ValidationError) as exc:
        DatasetValidator(config(workspace_tmp_path)).assert_valid(dataset)

    assert any(issue.code == "unmapped_labels" for issue in exc.value.report.errors)


def test_invalid_numeric_protocol_values_fail_quality_gate(workspace_tmp_path):
    dataset = valid_frame()
    dataset.loc[1, "Protocol"] = 999

    with pytest.raises(ValidationError) as exc:
        DatasetValidator(config(workspace_tmp_path)).assert_valid(dataset)

    assert any(issue.code == "invalid_protocol_values" for issue in exc.value.report.errors)
