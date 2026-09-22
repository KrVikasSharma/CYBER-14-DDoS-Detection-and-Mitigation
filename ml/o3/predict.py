from pathlib import Path
from typing import Any

import pandas as pd

from ml.o3.artifacts import load_model, read_json
from ml.o3.features import O3FeatureContractError, validate_inference_features


def load_o3_artifact(model_path: Path) -> tuple[object, list[str], dict[str, Any], dict[str, Any]]:
    artifact_dir = model_path.parent
    model = load_model(model_path)
    feature_metadata = read_json(artifact_dir / "feature_metadata.json")
    class_metadata = read_json(artifact_dir / "class_metadata.json")
    feature_columns = feature_metadata.get("feature_columns")
    if not isinstance(feature_columns, list) or not feature_columns:
        raise O3FeatureContractError("O3 feature metadata does not contain a usable feature list.")
    if feature_metadata.get("target_column") != "label_normalized":
        raise O3FeatureContractError("O3 artifact target must be label_normalized.")
    artifact_classes = class_metadata.get("available_classes")
    model_classes = [str(label) for label in getattr(model, "classes_", [])]
    if not isinstance(artifact_classes, list) or not artifact_classes:
        raise O3FeatureContractError("O3 class metadata does not contain available classes.")
    if model_classes and model_classes != [str(label) for label in artifact_classes]:
        raise O3FeatureContractError("O3 model classes do not match class metadata.")
    return model, [str(column) for column in feature_columns], feature_metadata, class_metadata


def predict_o3(
    model: object,
    dataset: pd.DataFrame,
    feature_columns: list[str],
    feature_metadata: dict[str, Any],
) -> dict[str, Any]:
    validate_inference_features(dataset, feature_columns)
    features = dataset[feature_columns]
    predicted = pd.Series(model.predict(features), name="prediction_label").astype(str)

    probabilities: list[dict[str, float]] | None = None
    classes: list[str] = [str(label) for label in getattr(model, "classes_", [])]
    if hasattr(model, "predict_proba"):
        probability_values = model.predict_proba(features)
        probabilities = [
            {classes[index]: float(value) for index, value in enumerate(row)}
            for row in probability_values
        ]

    if not set(predicted).issubset(set(classes)):
        raise O3FeatureContractError("O3 model produced a class outside its class metadata.")

    return {
        "predictions": predicted.tolist(),
        "probabilities": probabilities,
        "model_identifier": feature_metadata.get("model_identifier"),
        "model_version": feature_metadata.get("model_version"),
        "feature_columns": feature_columns,
    }

