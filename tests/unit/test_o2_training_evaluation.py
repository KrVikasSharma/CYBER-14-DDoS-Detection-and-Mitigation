import json

import pandas as pd
import pytest

from ml.o2.artifacts import O2ArtifactError
from ml.o2.config import O2ModelConfig
from ml.o2.evaluate import evaluate_model, evaluate_predictions, measure_prediction_latency
from ml.o2.features import O2FeatureContractError
from ml.o2.predict import load_o2_artifact, predict_o2
from ml.o2.train import read_processed_dataset, train_o2_reference_detector


def processed_frame():
    return pd.DataFrame(
        {
            "Flow Duration": [10, 11, 12, 50, 51, 52, 13, 53],
            "Total Fwd Packets": [1, 1, 2, 20, 21, 22, 2, 23],
            "Protocol": [6, 6, 17, 17, 17, 6, 6, 17],
            "label_original": [
                "BENIGN",
                "BENIGN",
                "BENIGN",
                "DrDoS_DNS",
                "Syn",
                "TFTP",
                "BENIGN",
                "UDP-lag",
            ],
            "label_normalized": [
                "BENIGN",
                "BENIGN",
                "BENIGN",
                "DRDOS_DNS",
                "SYN",
                "TFTP",
                "BENIGN",
                "UDP-LAG",
            ],
            "label_binary": [0, 0, 0, 1, 1, 1, 0, 1],
        }
    )


def train_fixture_model(workspace_tmp_path):
    config = O2ModelConfig(
        artifact_dir=workspace_tmp_path / "artifacts",
        random_seed=7,
        test_size=0.25,
        n_estimators=10,
        max_depth=4,
    )
    return train_o2_reference_detector(processed_frame(), config, "fixture-only")


def test_o2_training_saves_artifacts_and_metadata(workspace_tmp_path):
    result = train_fixture_model(workspace_tmp_path)

    assert result.model_path.exists()
    assert result.feature_metadata_path.exists()
    assert result.training_metadata_path.exists()
    assert result.reference_record_path.exists()

    feature_metadata = json.loads(result.feature_metadata_path.read_text(encoding="utf-8"))
    training_metadata = json.loads(result.training_metadata_path.read_text(encoding="utf-8"))

    assert feature_metadata["feature_columns"] == [
        "Flow Duration",
        "Total Fwd Packets",
        "Protocol",
    ]
    assert training_metadata["random_seed"] == 7
    assert training_metadata["dataset_reference"] == "fixture-only"


def test_o2_artifact_can_be_loaded_and_predicts_expected_shape(workspace_tmp_path):
    result = train_fixture_model(workspace_tmp_path)
    model, feature_columns, _ = load_o2_artifact(result.model_path)

    predictions = predict_o2(model, processed_frame(), feature_columns)

    assert len(predictions) == len(processed_frame())
    assert set(predictions.unique()).issubset({0, 1})


def test_o2_training_is_deterministic_for_fixed_configuration(workspace_tmp_path):
    first_dir = workspace_tmp_path / "first"
    second_dir = workspace_tmp_path / "second"
    first = train_o2_reference_detector(
        processed_frame(),
        O2ModelConfig(artifact_dir=first_dir, random_seed=99, n_estimators=10, max_depth=4),
    )
    second = train_o2_reference_detector(
        processed_frame(),
        O2ModelConfig(artifact_dir=second_dir, random_seed=99, n_estimators=10, max_depth=4),
    )
    first_model, first_features, _ = load_o2_artifact(first.model_path)
    second_model, second_features, _ = load_o2_artifact(second.model_path)

    pd.testing.assert_series_equal(
        predict_o2(first_model, processed_frame(), first_features),
        predict_o2(second_model, processed_frame(), second_features),
    )


def test_o2_evaluation_metric_calculation_and_confusion_matrix():
    result = evaluate_predictions(
        pd.Series([0, 0, 1, 1]),
        pd.Series([0, 1, 1, 0]),
    ).to_dict()

    assert result["metrics"]["accuracy"] == 0.5
    assert result["metrics"]["precision"] == 0.5
    assert result["metrics"]["recall"] == 0.5
    assert result["metrics"]["f1_score"] == 0.5
    assert result["metrics"]["false_positive_rate"] == 0.5
    assert result["metrics"]["false_negative_rate"] == 0.5
    assert result["confusion_matrix"] == {
        "true_negative": 1,
        "false_positive": 1,
        "false_negative": 1,
        "true_positive": 1,
    }


def test_o2_model_evaluation_and_latency_measurement(workspace_tmp_path):
    result = train_fixture_model(workspace_tmp_path)
    model, feature_columns, _ = load_o2_artifact(result.model_path)

    evaluation = evaluate_model(model, processed_frame(), feature_columns).to_dict()
    latency = measure_prediction_latency(model, processed_frame(), feature_columns, trials=5)

    assert evaluation["sample_summary"]["sample_count"] == 8
    assert evaluation["sample_summary"]["attack_count"] == 4
    assert evaluation["sample_summary"]["legitimate_count"] == 4
    assert latency["trials"] == 5
    assert latency["official_acceptance_result"] is False
    assert latency["max_ms"] >= latency["min_ms"]


def test_missing_model_handling(workspace_tmp_path):
    with pytest.raises(O2ArtifactError):
        load_o2_artifact(workspace_tmp_path / "missing.joblib")


def test_missing_dataset_handling(workspace_tmp_path):
    with pytest.raises(FileNotFoundError):
        read_processed_dataset(workspace_tmp_path / "missing.csv")


def test_prediction_rejects_missing_feature_columns(workspace_tmp_path):
    result = train_fixture_model(workspace_tmp_path)
    model, feature_columns, _ = load_o2_artifact(result.model_path)

    with pytest.raises(O2FeatureContractError):
        predict_o2(model, processed_frame().drop(columns=[feature_columns[0]]), feature_columns)

