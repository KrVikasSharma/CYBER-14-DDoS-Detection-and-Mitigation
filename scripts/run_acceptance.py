import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.evaluation.acceptance import load_config, run_acceptance


def main() -> int:
    parser = argparse.ArgumentParser(description="Run controlled CYBER-14 acceptance measurements.")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--fixture-only", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = run_acceptance(load_config(args.config), fixture_only=args.fixture_only)
    except (FileNotFoundError, ValueError) as exc:
        logging.error("%s", exc)
        return 2
    logging.info("Acceptance run %s completed with official status NOT_EXECUTED", result["run_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
