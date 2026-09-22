import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.data.config import DatasetPipelineConfig
from ml.data.ingestion import DatasetUnavailableError
from ml.preprocessing.pipeline import CICDDoS2019Pipeline
from ml.preprocessing.validation import ValidationError


logger = logging.getLogger("cyber14.prepare_data")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and preprocess a local CIC-DDoS2019 dataset."
    )
    parser.add_argument("--input", required=True, help="Local CIC-DDoS2019 CSV file or directory.")
    parser.add_argument(
        "--output",
        default="data/processed/cic_ddos2019",
        help="Directory for processed outputs and metadata.",
    )
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--access-download-date", default=None)
    parser.add_argument("--dataset-version", default=None)
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = parse_args()

    config = DatasetPipelineConfig(
        input_path=Path(args.input),
        output_dir=Path(args.output),
        random_seed=args.random_seed,
        test_size=args.test_size,
        access_download_date=args.access_download_date,
        dataset_version=args.dataset_version,
    )

    try:
        result = CICDDoS2019Pipeline(config).run()
    except DatasetUnavailableError as exc:
        logger.error("%s", exc)
        return 2
    except ValidationError as exc:
        logger.error("Dataset validation failed: %s", exc)
        for issue in exc.report.errors:
            logger.error("%s: %s %s", issue.code, issue.message, issue.details)
        return 3
    except Exception:
        logger.exception("Unexpected data preparation failure.")
        return 1

    logger.info("Processed dataset written to %s", result.processed_path)
    logger.info("Train split written to %s", result.train_path)
    logger.info("Test split written to %s", result.test_path)
    logger.info("Provenance written to %s", result.provenance_path)
    logger.info("Validation report written to %s", result.validation_report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
