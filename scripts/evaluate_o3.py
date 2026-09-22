import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.o3.artifacts import O3ArtifactError, read_json, write_json
from ml.o3.config import O3_MODEL_IDENTIFIER, O3_MODEL_VERSION
from ml.o3.evaluate import evaluate_model, measure_prediction_latency
from ml.o3.features import O3FeatureContractError
from ml.o3.predict import load_o3_artifact

logger = logging.getLogger("cyber14.evaluate_o3")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the CYBER-14 O3 multi-class classifier.")
    parser.add_argument("--model", required=True, help="Path to O3 model.joblib artifact.")
    parser.add_argument("--test", required=True, help="Processed test CSV containing label_normalized.")
    parser.add_argument("--output", required=True, help="Evaluation JSON output path.")
    parser.add_argument("--latency-trials", type=int, default=100)
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = parse_args()
    try:
        test_path = Path(args.test)
        if not test_path.exists():
            raise FileNotFoundError(f"O3 evaluation test CSV is missing: {test_path}")
        model_path = Path(args.model)
        model, feature_columns, feature_metadata, class_metadata = load_o3_artifact(model_path)
        dataset = pd.read_csv(test_path)
        evaluation = evaluate_model(model, dataset, feature_columns, class_metadata["available_classes"])
        latency = measure_prediction_latency(model, dataset, feature_columns, args.latency_trials)
        training_metadata_path = model_path.parent / "training_metadata.json"
        training_metadata = read_json(training_metadata_path) if training_metadata_path.exists() else None
        payload = {
            "model_identifier": feature_metadata.get("model_identifier", O3_MODEL_IDENTIFIER),
            "model_version": feature_metadata.get("model_version", O3_MODEL_VERSION),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "evaluation_scope": "o3_reference_fixture_or_local_measurement_not_formal_cyber14_acceptance",
            "model_path": str(model_path),
            "test_dataset": str(test_path),
            "fixture_only": bool(training_metadata.get("fixture_only", False)) if training_metadata else False,
            "feature_contract": feature_metadata,
            "class_metadata": class_metadata,
            "dataset_reference": training_metadata.get("dataset_reference") if training_metadata else None,
            "training_configuration": training_metadata,
            "evaluation_configuration": {
                "latency_trials": args.latency_trials,
                "metrics": [
                    "accuracy", "macro_precision", "macro_recall", "macro_f1",
                    "weighted_precision", "weighted_recall", "weighted_f1",
                    "confusion_matrix", "per_class", "sample_summary",
                ],
            },
            "measured_metrics": evaluation.to_dict(),
            "latency_measurements": latency,
            "official_cyber14_kpi_result": False,
        }
        write_json(Path(args.output), payload)
    except (FileNotFoundError, ValueError, O3ArtifactError, O3FeatureContractError, json.JSONDecodeError, KeyError) as exc:
        logger.error("%s", exc)
        return 2
    except Exception:
        logger.exception("Unexpected O3 evaluation failure.")
        return 1

    logger.info("O3 evaluation JSON written to %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
