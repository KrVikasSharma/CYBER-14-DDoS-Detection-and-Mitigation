import json
from pathlib import Path

import pandas as pd
import pytest

from ml.o3.artifacts import O3ArtifactError
from ml.o3.config import O3ModelConfig
from ml.o3.evaluate import evaluate_model, evaluate_predictions, measure_prediction_latency
from ml.o3.features import O3FeatureContractError, select_o3_feature_columns, validate_o3_dataset
from ml.o3.predict import load_o3_artifact, predict_o3
from ml.o3.train import read_processed_dataset, train_o3_reference_classifier


def processed_frame() -> pd.DataFrame:
    return pd.read_csv(Path("data/fixtures/o3_tiny_processed_fixture.csv"))


def train_fixture_model(workspace_tmp_path):
    return train_o3_reference_classifier(
        processed_frame(),
        O3ModelConfig(
            artifact_dir=workspace_tmp_path / "artifacts",
            random_seed=7,
            test_size=0.25,
            n_estimators=10,
            max_depth=3,
        ),
        dataset_reference="o3-tiny-fixture",
        fixture_only=True,
    )


def test_o3_feature_selection_excludes_targets_identifiers_and_leakage():
    frame = processed_frame().assign(
        **{"Flow ID": ["flow"] * 16, "mitigation_action": [0] * 16}
    )
    with pytest.raises(O3FeatureContractError, match="post-decision"):
        select_o3_feature_columns(frame)
    frame = frame.drop(columns=["mitigation_action"])
    assert select_o3_feature_columns(frame) == ["Flow Duration", "Total Fwd Packets", "Protocol"]


def test_o3_target_and_label_contract():
    contract = validate_o3_dataset(processed_frame())
    assert contract.target_column == "label_normalized"
    assert contract.available_classes == ["BENIGN", "DRDOS_DNS", "SYN", "TFTP"]
    invalid = processed_frame().assign(label_normalized="not-a-known-class")
    with pytest.raises(O3FeatureContractError, match="outside"):
        validate_o3_dataset(invalid)
    unnormalized = processed_frame().assign(label_normalized="benign")
    with pytest.raises(O3FeatureContractError, match="normalized"):
        validate_o3_dataset(unnormalized)


def test_o3_training_persists_contract_and_classes(workspace_tmp_path):
    result = train_fixture_model(workspace_tmp_path)
    assert result.model_path.exists()
    assert result.class_metadata_path.exists()
    feature_metadata = json.loads(result.feature_metadata_path.read_text(encoding="utf-8"))
    class_metadata = json.loads(result.class_metadata_path.read_text(encoding="utf-8"))
    training_metadata = json.loads(result.training_metadata_path.read_text(encoding="utf-8"))
    assert feature_metadata["target_column"] == "label_normalized"
    assert feature_metadata["feature_columns"] == ["Flow Duration", "Total Fwd Packets", "Protocol"]
    assert class_metadata["available_classes"] == ["BENIGN", "DRDOS_DNS", "SYN", "TFTP"]
    assert training_metadata["random_seed"] == 7
    assert training_metadata["fixture_only"] is True


def test_o3_artifact_load_prediction_and_probabilities(workspace_tmp_path):
    result = train_fixture_model(workspace_tmp_path)
    model, feature_columns, feature_metadata, class_metadata = load_o3_artifact(result.model_path)
    prediction = predict_o3(model, processed_frame(), feature_columns, feature_metadata)
    assert len(prediction["predictions"]) == len(processed_frame())
    assert set(prediction["predictions"]).issubset(set(class_metadata["available_classes"]))
    assert len(prediction["probabilities"]) == len(processed_frame())
    assert set(prediction["probabilities"][0]) == set(class_metadata["available_classes"])


def test_o3_training_is_deterministic(workspace_tmp_path):
    first = train_o3_reference_classifier(
        processed_frame(), O3ModelConfig(artifact_dir=workspace_tmp_path / "first", random_seed=9, n_estimators=10)
    )
    second = train_o3_reference_classifier(
        processed_frame(), O3ModelConfig(artifact_dir=workspace_tmp_path / "second", random_seed=9, n_estimators=10)
    )
    first_model, first_features, first_metadata, _ = load_o3_artifact(first.model_path)
    second_model, second_features, second_metadata, _ = load_o3_artifact(second.model_path)
    assert predict_o3(first_model, processed_frame(), first_features, first_metadata)["predictions"] == predict_o3(
        second_model, processed_frame(), second_features, second_metadata
    )["predictions"]


def test_o3_metrics_confusion_and_per_class_values():
    result = evaluate_predictions(
        ["BENIGN", "BENIGN", "SYN", "SYN"],
        ["BENIGN", "SYN", "SYN", "BENIGN"],
        ["BENIGN", "SYN"],
    ).to_dict()
    assert result["metrics"]["accuracy"] == 0.5
    assert result["metrics"]["macro_f1"] == 0.5
    assert result["confusion_matrix"] == {"labels": ["BENIGN", "SYN"], "matrix": [[1, 1], [1, 1]]}
    assert result["per_class"]["SYN"]["support"] == 2
    assert result["sample_summary"] == {
        "total_samples": 4,
        "number_of_classes": 2,
        "class_distribution": {"BENIGN": 2, "SYN": 2},
    }


def test_o3_model_evaluation_latency_and_failure_paths(workspace_tmp_path):
    result = train_fixture_model(workspace_tmp_path)
    model, feature_columns, feature_metadata, class_metadata = load_o3_artifact(result.model_path)
    evaluation = evaluate_model(model, processed_frame(), feature_columns, class_metadata["available_classes"])
    latency = measure_prediction_latency(model, processed_frame(), feature_columns, trials=7)
    assert evaluation.sample_summary["number_of_classes"] == 4
    assert latency["trials"] == 7
    assert latency["official_acceptance_result"] is False
    assert latency["max_ms"] >= latency["min_ms"]
    with pytest.raises(O3ArtifactError):
        load_o3_artifact(workspace_tmp_path / "missing" / "model.joblib")
    with pytest.raises(O3FeatureContractError, match="missing"):
        predict_o3(model, processed_frame().drop(columns=[feature_columns[0]]), feature_columns, feature_metadata)
    with pytest.raises(O3FeatureContractError, match="unknown"):
        evaluate_model(model, processed_frame().assign(label_normalized="UNKNOWN"), feature_columns)


def test_o3_missing_dataset_handling(workspace_tmp_path):
    with pytest.raises(FileNotFoundError):
        read_processed_dataset(workspace_tmp_path / "missing.csv")
