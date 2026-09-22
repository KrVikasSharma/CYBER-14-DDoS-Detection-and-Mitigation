import json
from pathlib import Path
import pandas as pd
import pytest

from app.core.config import Settings
from app.services.detection_service import DetectionService
from app.services.system_service import SystemService
from ml.data.manifest import load_feature_manifest
from ml.mitigation.engine import MitigationEngine
from ml.mitigation.models import DecisionAction, DetectionResult
from ml.o2.predict import load_o2_artifact
from ml.o3.predict import load_o3_artifact


def test_demo_sample_files_and_manifest_exist():
    sample_csv = Path("data/demo/cic_ddos2019_sample.csv")
    manifest_json = Path("evidence/cic_ddos2019_demo_sample_manifest.json")
    manifest_md = Path("evidence/cic_ddos2019_demo_sample_manifest.md")

    assert sample_csv.exists(), "Demo sample CSV must exist."
    assert manifest_json.exists(), "Demo sample manifest JSON must exist."
    assert manifest_md.exists(), "Demo sample manifest MD must exist."

    df = pd.read_csv(sample_csv)
    assert 9000 <= len(df) <= 11000, f"Expected ~10,000 rows, found {len(df)}"
    assert len(df.columns) == 88, f"Expected 88 raw columns, found {len(df.columns)}"

    manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
    assert manifest["official_acceptance_data"] is False
    assert "BENIGN" in manifest["label_distribution"]
    assert manifest["total_sampled_rows"] == len(df)


def test_processed_splits_match_78_feature_manifest():
    train_csv = Path("data/demo/processed/train.csv")
    test_csv = Path("data/demo/processed/test.csv")
    meta_json = Path("data/demo/processed/preprocessing_metadata.json")

    assert train_csv.exists()
    assert test_csv.exists()
    assert meta_json.exists()

    manifest = load_feature_manifest()
    expected_78 = manifest["included_features_o2"]

    train_df = pd.read_csv(train_csv)
    test_df = pd.read_csv(test_csv)
    meta = json.loads(meta_json.read_text(encoding="utf-8"))

    assert meta["feature_columns"] == expected_78
    assert meta["imputation_parameters_fit"] == "FIT_ON_TRAIN_ONLY"

    for forbidden_col in manifest["excluded_columns"]:
        assert forbidden_col not in meta["feature_columns"]

    assert not train_df[expected_78].isna().any().any()
    assert not test_df[expected_78].isna().any().any()


def test_demo_model_artifacts_and_contracts():
    o2_path = Path("data/demo/models/o2/model.joblib")
    o3_path = Path("data/demo/models/o3/model.joblib")

    assert o2_path.exists()
    assert o3_path.exists()

    manifest = load_feature_manifest()
    expected_78 = manifest["included_features_o2"]

    o2_model, o2_cols, o2_meta = load_o2_artifact(o2_path)
    assert o2_cols == expected_78
    assert o2_meta["target_column"] == "label_binary"

    o3_model, o3_cols, o3_feat_meta, o3_class_meta = load_o3_artifact(o3_path)
    assert o3_cols == expected_78
    assert o3_feat_meta["target_column"] == "label_normalized"
    assert len(o3_class_meta["available_classes"]) >= 10


def test_demo_mode_backend_integration():
    settings = Settings(
        demo_mode=True,
        demo_o2_model_path=Path("data/demo/models/o2/model.joblib"),
        demo_o3_model_path=Path("data/demo/models/o3/model.joblib"),
        o2_model_path=None,
        o3_model_path=None,
    )
    service = DetectionService(settings)
    system = SystemService(settings)

    status = system.get_status()
    assert status.ml_status == "ready_demo_sample"

    # Test an inference pass
    test_csv = Path("data/demo/processed/test.csv")
    test_df = pd.read_csv(test_csv)
    manifest = load_feature_manifest()
    features = manifest["included_features_o2"]

    sample_row = {col: float(test_df[col].iloc[0]) for col in features}
    res = service.analyze({"source_identifier": "192.168.1.100", "features": sample_row})

    assert res.artifact_scope["demo_mode"] is True
    assert "REAL CIC-DDoS2019 SAMPLE" in res.artifact_scope["dataset_note"]
    assert res.mitigation.decision in {"ALLOW", "BLOCK", "RATE_LIMIT"}


def test_mitigation_engine_policy_compliance():
    from ml.mitigation.config import MitigationConfig
    engine = MitigationEngine(config=MitigationConfig())

    # Benign -> ALLOW
    d1 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.95))
    assert d1.decision is DecisionAction.ALLOW

    # Flash-crowd -> RATE_LIMIT
    d2 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.95, traffic_rate=1500.0))
    assert d2.decision is DecisionAction.RATE_LIMIT

    # High-confidence attack -> BLOCK
    d3 = engine.analyze_detection(DetectionResult(attack_type="SYN", confidence=0.99))
    assert d3.decision is DecisionAction.BLOCK

    # Newly added attack types -> BLOCK or RATE_LIMIT
    d4 = engine.analyze_detection(DetectionResult(attack_type="MSSQL", confidence=0.90))
    assert d4.decision is DecisionAction.BLOCK
