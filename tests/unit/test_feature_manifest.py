import pandas as pd
import pytest

from ml.data.manifest import (
    DEFAULT_MANIFEST_PATH,
    FeatureManifestError,
    load_feature_manifest,
    validate_manifest_structure,
)
from ml.o2.config import O2_TARGET_COLUMN
from ml.o2.features import (
    O2FeatureContractError,
    validate_o2_dataset_against_manifest,
)
from ml.o3.config import O3_TARGET_COLUMN
from ml.o3.features import (
    O3FeatureContractError,
    validate_o3_dataset_against_manifest,
)


@pytest.fixture
def manifest():
    return load_feature_manifest(DEFAULT_MANIFEST_PATH)


@pytest.fixture
def full_manifest_o2_frame(manifest):
    data = {feature: [1.0, 2.0] for feature in manifest["included_features_o2"]}
    data[O2_TARGET_COLUMN] = [0, 1]
    return pd.DataFrame(data)


@pytest.fixture
def full_manifest_o3_frame(manifest):
    data = {feature: [1.0, 2.0] for feature in manifest["included_features_o3"]}
    data["label_binary"] = [0, 1]
    data["label_original"] = ["BENIGN", "DrDoS_DNS"]
    data[O3_TARGET_COLUMN] = ["BENIGN", "DRDOS_DNS"]
    return pd.DataFrame(data)


def test_manifest_loading_and_structure(manifest):
    assert manifest["manifest_version"] == "1.0.0"
    assert manifest["source_schema_column_count"] == 88
    assert len(manifest["included_features_o2"]) == 78
    assert len(manifest["included_features_o3"]) == 78
    assert len(manifest["excluded_columns"]) == 10
    assert len(manifest["feature_metadata"]) == 78
    assert len(manifest["feature_list_sha256"]) == 64


def test_o2_o3_feature_contract_consistency(manifest):
    o2 = manifest["included_features_o2"]
    o3 = manifest["included_features_o3"]
    assert o2 == o3
    assert len(o2) == 78
    assert len(set(o2)) == 78  # No duplicate feature names


def test_exact_feature_ordering(full_manifest_o2_frame, full_manifest_o3_frame):
    # Valid order passes
    contract_o2 = validate_o2_dataset_against_manifest(full_manifest_o2_frame)
    assert len(contract_o2.feature_columns) == 78
    assert contract_o2.manifest_fingerprint is not None

    contract_o3 = validate_o3_dataset_against_manifest(full_manifest_o3_frame)
    assert len(contract_o3.feature_columns) == 78

    # Swap two features to test fail-closed ordering enforcement
    cols = list(full_manifest_o2_frame.columns)
    # Swap first two feature columns (index 0 and 1)
    cols[0], cols[1] = cols[1], cols[0]
    shuffled_o2 = full_manifest_o2_frame[cols]

    with pytest.raises(O2FeatureContractError, match="feature ordering does not match"):
        validate_o2_dataset_against_manifest(shuffled_o2)

    shuffled_o3 = full_manifest_o3_frame[[c for c in cols if c in full_manifest_o3_frame.columns] + ["label_binary", "label_original", O3_TARGET_COLUMN]]
    with pytest.raises(O3FeatureContractError, match="feature ordering does not match"):
        validate_o3_dataset_against_manifest(shuffled_o3)


def test_required_feature_missing_failure(full_manifest_o2_frame, full_manifest_o3_frame):
    # Drop one required manifest feature
    missing_o2 = full_manifest_o2_frame.drop(columns=["Flow Duration"])
    with pytest.raises(O2FeatureContractError, match="missing required manifest features"):
        validate_o2_dataset_against_manifest(missing_o2)

    missing_o3 = full_manifest_o3_frame.drop(columns=["Protocol"])
    with pytest.raises(O3FeatureContractError, match="missing required manifest features"):
        validate_o3_dataset_against_manifest(missing_o3)


def test_unexpected_schema_feature_mismatch_failure(full_manifest_o2_frame, full_manifest_o3_frame):
    # Add an unexpected extra numeric column not in manifest
    unexpected_o2 = full_manifest_o2_frame.copy()
    unexpected_o2["Extraneous_Column"] = [100.0, 200.0]

    with pytest.raises(O2FeatureContractError, match="unexpected feature columns not defined in manifest"):
        validate_o2_dataset_against_manifest(unexpected_o2)

    unexpected_o3 = full_manifest_o3_frame.copy()
    unexpected_o3["Synthetic_Feature"] = [1.0, 2.0]
    with pytest.raises(O3FeatureContractError, match="unexpected feature columns not defined in manifest"):
        validate_o3_dataset_against_manifest(unexpected_o3)


def test_excluded_identifier_ip_port_timestamp_columns_cannot_enter_model(manifest, full_manifest_o2_frame):
    excluded_names = {item["normalized_name"] for item in manifest["excluded_columns"]}
    raw_excluded_names = {item["raw_name"] for item in manifest["excluded_columns"]}
    
    # 1. Ensure none of the 10 excluded columns are in the manifest's included features
    for col in excluded_names:
        assert col not in manifest["included_features_o2"]
        assert col not in manifest["included_features_o3"]
    for col in raw_excluded_names:
        assert col not in manifest["included_features_o2"]
        assert col not in manifest["included_features_o3"]

    # 2. Add excluded columns to dataset and verify they are flagged in forbidden_columns_present
    dataset_with_forbidden = full_manifest_o2_frame.copy()
    dataset_with_forbidden["Source IP"] = ["192.168.1.1", "192.168.1.2"]
    dataset_with_forbidden["Destination Port"] = [80, 443]
    dataset_with_forbidden["Timestamp"] = ["2019-01-12 11:00:00", "2019-01-12 11:00:01"]
    dataset_with_forbidden["Inbound"] = [1, 1]
    dataset_with_forbidden["Unnamed: 0"] = [0, 1]

    contract = validate_o2_dataset_against_manifest(dataset_with_forbidden)
    # Check that feature columns do NOT contain any of the forbidden columns
    for forbidden in ["Source IP", "Destination Port", "Timestamp", "Inbound", "Unnamed: 0"]:
        assert forbidden not in contract.feature_columns
        assert forbidden in contract.forbidden_columns_present


def test_manifest_validation_rejects_corrupted_manifests():
    with pytest.raises(FeatureManifestError, match="missing required root keys"):
        validate_manifest_structure({"manifest_version": "1.0.0"})

    with pytest.raises(FeatureManifestError, match="Expected exactly 78 O2 features"):
        validate_manifest_structure({
            "manifest_version": "1.0.0",
            "dataset_identifier": "cic-ddos2019",
            "source_schema_column_count": 88,
            "included_features_o2": ["Flow Duration"],
            "included_features_o3": ["Flow Duration"],
            "excluded_columns": [],
            "feature_metadata": [],
            "feature_list_sha256": "x" * 64,
        })
