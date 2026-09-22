from pathlib import Path

import pandas as pd

from ml.o2.artifacts import load_model, read_json
from ml.o2.features import O2FeatureContractError


def load_o2_artifact(model_path: Path) -> tuple[object, list[str], dict[str, object]]:
    artifact_dir = model_path.parent
    model = load_model(model_path)
    feature_metadata = read_json(artifact_dir / "feature_metadata.json")
    feature_columns = feature_metadata.get("feature_columns")
    if not isinstance(feature_columns, list) or not feature_columns:
        raise O2FeatureContractError("O2 feature metadata does not contain a usable feature list.")
    return model, [str(column) for column in feature_columns], feature_metadata


def predict_o2(model: object, dataset: pd.DataFrame, feature_columns: list[str]) -> pd.Series:
    missing = [column for column in feature_columns if column not in dataset.columns]
    if missing:
        raise O2FeatureContractError(f"Prediction dataset is missing O2 features: {missing}")
    predictions = model.predict(dataset[feature_columns])
    return pd.Series(predictions, name="prediction_binary").astype(int)

