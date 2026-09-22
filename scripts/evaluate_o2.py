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

from ml.o2.artifacts import O2ArtifactError, read_json, write_json
from ml.o2.config import O2_MODEL_IDENTIFIER, O2_MODEL_VERSION
from ml.o2.evaluate import evaluate_model, measure_prediction_latency
from ml.o2.features import O2FeatureContractError
from ml.o2.predict import load_o2_artifact


logger = logging.getLogger("cyber14.evaluate_o2")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the CYBER-14 O2 binary reference detector.")
    parser.add_argument("--model", required=True, help="Path to O2 model.joblib artifact.")
    parser.add_argument("--test", required=True, help="Processed test CSV containing label_binary.")
    parser.add_argument("--output", required=True, help="Evaluation JSON output path.")
    parser.add_argument("--latency-trials", type=int, default=100)
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = parse_args()

    try:
        test_path = Path(args.test)
        if not test_path.exists():
            raise FileNotFoundError(f"O2 evaluation test CSV is missing: {test_path}")
        model_path = Path(args.model)
        model, feature_columns, feature_metadata = load_o2_artifact(model_path)
        dataset = pd.read_csv(test_path)
        evaluation = evaluate_model(model, dataset, feature_columns)
        latency = measure_prediction_latency(model, dataset, feature_columns, args.latency_trials)

        training_metadata_path = model_path.parent / "training_metadata.json"
        training_metadata = (
            read_json(training_metadata_path) if training_metadata_path.exists() else None
        )
        payload = {
            "model_identifier": feature_metadata.get("model_identifier", O2_MODEL_IDENTIFIER),
            "model_version": feature_metadata.get("model_version", O2_MODEL_VERSION),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "evaluation_scope": "o2_reference_measurement_not_formal_cyber14_acceptance",
            "model_path": str(model_path),
            "test_dataset": str(test_path),
            "feature_contract": feature_metadata,
            "dataset_provenance_identifier": (
                training_metadata.get("dataset_reference") if training_metadata else None
            ),
            "training_configuration": training_metadata,
            "evaluation_configuration": {
                "latency_trials": args.latency_trials,
                "metrics": [
                    "accuracy",
                    "precision",
                    "recall",
                    "f1_score",
                    "confusion_matrix",
                    "false_positive_rate",
                    "false_negative_rate",
                ],
            },
            "measured_metrics": evaluation.to_dict(),
            "latency_measurements": latency,
            "resource_measurements": None,
            "official_cyber14_kpi_result": False,
        }
        write_json(Path(args.output), payload)
    except (FileNotFoundError, ValueError, O2ArtifactError, O2FeatureContractError, json.JSONDecodeError) as exc:
        logger.error("%s", exc)
        return 2
    except Exception:
        logger.exception("Unexpected O2 evaluation failure.")
        return 1

    logger.info("O2 evaluation JSON written to %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

