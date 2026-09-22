import json

import pandas as pd
import pytest

from ml.data.config import DatasetPipelineConfig
from ml.data.ingestion import DatasetIngestor, DatasetUnavailableError
from ml.preprocessing.pipeline import CICDDoS2019Pipeline


def test_missing_dataset_path_reports_unavailable_without_substitution(workspace_tmp_path):
    missing_path = workspace_tmp_path / "not_present"

    with pytest.raises(DatasetUnavailableError) as exc:
        DatasetIngestor(missing_path).load()

    assert "does not download datasets or substitute synthetic data" in str(exc.value)


def test_pipeline_writes_processed_outputs_and_metadata(workspace_tmp_path):
    raw_dir = workspace_tmp_path / "raw"
    output_dir = workspace_tmp_path / "processed"
    raw_dir.mkdir()
    dataset_path = raw_dir / "sample.csv"
    pd.DataFrame(
        {
            "Flow Duration": [10.0, 20.0, 30.0, 40.0],
            "Total Fwd Packets": [1, 2, 3, 4],
            "Protocol": [6, 17, 6, 17],
            "Label": ["BENIGN", "DrDoS_DNS", "Syn", "TFTP"],
        }
    ).to_csv(dataset_path, index=False)

    result = CICDDoS2019Pipeline(
        DatasetPipelineConfig(
            input_path=raw_dir,
            output_dir=output_dir,
            random_seed=7,
            test_size=0.25,
            access_download_date="2026-09-20",
            dataset_version="test-metadata",
        )
    ).run()

    assert result.processed_path.exists()
    assert result.train_path.exists()
    assert result.test_path.exists()
    assert result.validation_report_path.exists()
    assert result.provenance_path.exists()
    assert result.preprocessing_metadata_path.exists()

    provenance = json.loads(result.provenance_path.read_text(encoding="utf-8"))
    validation = json.loads(result.validation_report_path.read_text(encoding="utf-8"))

    assert provenance["dataset_name"] == "CIC-DDoS2019"
    assert provenance["access_download_date"] == "2026-09-20"
    assert provenance["dataset_version"] == "test-metadata"
    assert str(dataset_path) in provenance["file_names"]
    assert validation["passed"] is True
    assert provenance["preprocessing_metadata"]["imputation_parameters_fit"] == "FIT_ON_TRAIN_ONLY"
    assert provenance["preprocessing_metadata"]["training_rows"] == len(pd.read_csv(result.train_path))
    assert provenance["preprocessing_metadata"]["test_rows"] == len(pd.read_csv(result.test_path))
