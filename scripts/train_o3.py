import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.o3.config import O3ModelConfig
from ml.o3.features import O3FeatureContractError
from ml.o3.train import read_processed_dataset, train_o3_reference_classifier

logger = logging.getLogger("cyber14.train_o3")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the CYBER-14 O3 multi-class classifier.")
    parser.add_argument("--input", required=True, help="Processed CSV containing label_normalized.")
    parser.add_argument("--output", default="ml/artifacts/o3", help="O3 artifact directory.")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--dataset-reference", default=None)
    parser.add_argument("--fixture-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = parse_args()
    try:
        dataset = read_processed_dataset(Path(args.input))
        config = O3ModelConfig(
            artifact_dir=Path(args.output),
            random_seed=args.random_seed,
            test_size=args.test_size,
            n_estimators=args.n_estimators,
            learning_rate=args.learning_rate,
            max_depth=args.max_depth,
        )
        result = train_o3_reference_classifier(
            dataset,
            config,
            dataset_reference=args.dataset_reference,
            fixture_only=args.fixture_only,
        )
    except (FileNotFoundError, ValueError, O3FeatureContractError) as exc:
        logger.error("%s", exc)
        return 2
    except Exception:
        logger.exception("Unexpected O3 training failure.")
        return 1

    logger.info("O3 model artifact written to %s", result.model_path)
    logger.info("O3 feature metadata written to %s", result.feature_metadata_path)
    logger.info("O3 training metadata written to %s", result.training_metadata_path)
    logger.info("O3 reference record written to %s", result.reference_record_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
