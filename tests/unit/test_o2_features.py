import pandas as pd
import pytest

from ml.o2.config import O2_TARGET_COLUMN
from ml.o2.features import O2FeatureContractError, select_o2_feature_columns, validate_o2_dataset


def processed_frame():
    return pd.DataFrame(
        {
            "Flow Duration": [10.0, 20.0, 30.0, 40.0],
            "Total Fwd Packets": [1, 2, 3, 4],
            "Protocol": [6, 17, 6, 17],
            "label_original": ["BENIGN", "DrDoS_DNS", "BENIGN", "Syn"],
            "label_normalized": ["BENIGN", "DRDOS_DNS", "BENIGN", "SYN"],
            O2_TARGET_COLUMN: [0, 1, 0, 1],
        }
    )


def test_o2_feature_selection_excludes_target_and_multiclass_labels():
    features = select_o2_feature_columns(processed_frame())

    assert features == ["Flow Duration", "Total Fwd Packets", "Protocol"]
    assert O2_TARGET_COLUMN not in features
    assert "label_original" not in features
    assert "label_normalized" not in features


def test_o2_contract_uses_label_binary_as_target():
    contract = validate_o2_dataset(processed_frame())

    assert contract.target_column == "label_binary"
    assert contract.feature_columns == ["Flow Duration", "Total Fwd Packets", "Protocol"]


def test_o2_contract_rejects_obvious_target_leakage_columns():
    dataset = processed_frame()
    dataset["mitigation_blocked"] = [0, 1, 0, 1]

    with pytest.raises(O2FeatureContractError):
        validate_o2_dataset(dataset)


def test_o2_contract_rejects_missing_target():
    with pytest.raises(O2FeatureContractError):
        validate_o2_dataset(processed_frame().drop(columns=[O2_TARGET_COLUMN]))


def test_o2_contract_rejects_single_class_data():
    dataset = processed_frame()
    dataset[O2_TARGET_COLUMN] = 0

    with pytest.raises(O2FeatureContractError):
        validate_o2_dataset(dataset)

