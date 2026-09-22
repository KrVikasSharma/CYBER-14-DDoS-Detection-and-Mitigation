import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.o2.config import O2ModelConfig
from ml.o2.features import O2FeatureContractError
from ml.o2.train import read_processed_dataset, train_o2_reference_detector


logger = logging.getLogger("cyber14.train_o2")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the CYBER-14 O2 binary reference detector.")
    parser.add_argument("--input", required=True, help="Processed CSV produced by scripts/prepare_data.py.")
    parser.add_argument("--output", default="ml/artifacts/o2", help="O2 artifact directory.")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--n-estimators", type=int, default=50)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--min-samples-leaf", type=int, default=1)
    parser.add_argument("--dataset-reference", default=None)
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = parse_args()
    try:
        dataset = read_processed_dataset(Path(args.input))
        config = O2ModelConfig(
            artifact_dir=Path(args.output),
            random_seed=args.random_seed,
            test_size=args.test_size,
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            min_samples_leaf=args.min_samples_leaf,
        )
        result = train_o2_reference_detector(
            dataset,
            config,
            dataset_reference=args.dataset_reference,
        )
    except (FileNotFoundError, ValueError, O2FeatureContractError) as exc:
        logger.error("%s", exc)
        return 2
    except Exception:
        logger.exception("Unexpected O2 training failure.")
        return 1

    logger.info("O2 model artifact written to %s", result.model_path)
    logger.info("O2 feature metadata written to %s", result.feature_metadata_path)
    logger.info("O2 training metadata written to %s", result.training_metadata_path)
    logger.info("O2 reference record written to %s", result.reference_record_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

