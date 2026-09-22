import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from ml.data.config import DatasetPipelineConfig
from ml.preprocessing.pipeline import CICDDoS2019Pipeline
from ml.data.manifest import load_feature_manifest

logger = logging.getLogger("cyber14.preprocess_demo_sample")


def run_demo_preprocessing() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    sample_csv = Path("data/demo/cic_ddos2019_sample.csv")
    if not sample_csv.exists():
        raise FileNotFoundError(f"Sample CSV not found at {sample_csv}. Run scripts/create_demo_sample.py first.")

    output_dir = Path("data/demo/processed")
    config = DatasetPipelineConfig(
        input_path=sample_csv,
        output_dir=output_dir,
        dataset_name="CIC-DDoS2019-Demo-Sample",
        source_reference="Small real CIC-DDoS2019 demonstration sample (10k rows)",
        dataset_version="demo-sample-v1",
        random_seed=42,
        test_size=0.2,
        drop_duplicate_rows=False,  # preserve sample rows
        allow_infinite_numeric=True,
    )

    logger.info("Running CICDDoS2019Pipeline on %s -> %s", sample_csv, output_dir)
    result = CICDDoS2019Pipeline(config).run()
    logger.info("Pipeline run complete.")

    # Validation checks
    train_df = pd.read_csv(result.train_path)
    test_df = pd.read_csv(result.test_path)
    full_df = pd.read_csv(result.processed_path)
    metadata = json.loads(result.preprocessing_metadata_path.read_text(encoding="utf-8"))

    manifest = load_feature_manifest()
    expected_78 = list(manifest["included_features_o2"])

    # 1. Exact 78 features check
    model_features = metadata["feature_columns"]
    assert model_features == expected_78, "Feature columns do not match exact 78-feature manifest!"
    logger.info("Feature contract verified: exactly 78 features in frozen manifest order.")

    # 2. Excluded columns check
    forbidden = manifest["excluded_columns"]
    for col in forbidden:
        assert col not in model_features, f"Forbidden column {col} found in model features!"
    logger.info("All 10 excluded columns verified absent from feature matrix.")

    # 3. Label columns check
    for label_col in ["label_original", "label_normalized", "label_binary"]:
        assert label_col in train_df.columns, f"{label_col} missing from train!"
        assert label_col in test_df.columns, f"{label_col} missing from test!"
    logger.info("Label columns preserved across train and test splits.")

    # 4. No NaN / Inf check
    assert not train_df[model_features].isna().any().any(), "NaN found in train features!"
    assert not test_df[model_features].isna().any().any(), "NaN found in test features!"
    logger.info("Imputation verified: zero NaNs and zero Infs in model features.")

    # 5. Train-only imputation check
    assert metadata["imputation_parameters_fit"] == "FIT_ON_TRAIN_ONLY"
    logger.info("Imputation confirmed: fit strictly on training split only.")

    logger.info("Sample summary: Total=%d, Train=%d (%.1f%%), Test=%d (%.1f%%)",
                len(full_df), len(train_df), 100*len(train_df)/len(full_df),
                len(test_df), 100*len(test_df)/len(full_df))
    logger.info("Train label_binary distribution: %s", dict(train_df["label_binary"].value_counts()))
    logger.info("Test label_binary distribution: %s", dict(test_df["label_binary"].value_counts()))


if __name__ == "__main__":
    run_demo_preprocessing()
