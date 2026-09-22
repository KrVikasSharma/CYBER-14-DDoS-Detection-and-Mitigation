import pandas as pd
import pytest

from ml.data.config import DatasetPipelineConfig
from ml.preprocessing.labels import build_label_mapping, map_o2_binary_label, normalize_label
from ml.preprocessing.preprocessor import CICDDoS2019Preprocessor, deterministic_train_test_split


def config(tmp_path, **overrides):
    values = {
        "input_path": tmp_path,
        "output_dir": tmp_path / "processed",
        "random_seed": 123,
        "test_size": 0.4,
    }
    values.update(overrides)
    return DatasetPipelineConfig(**values)


def valid_frame():
    return pd.DataFrame(
        {
            "Flow ID": ["a", "b", "c", "d", "e"],
            "Flow Duration": [10.0, None, 30.0, 40.0, 50.0],
            "Total Fwd Packets": [1, 2, 3, 4, 5],
            "Protocol": [6, 17, 6, 17, 6],
            "Label": ["BENIGN", "DrDoS_DNS", "Syn", "TFTP", "UDP-lag"],
        }
    )


def test_label_mapping_preserves_multiclass_and_adds_documented_binary(workspace_tmp_path):
    processed = CICDDoS2019Preprocessor(config(workspace_tmp_path)).preprocess(valid_frame())

    assert "label_original" in processed.full.columns
    assert "label_normalized" in processed.full.columns
    assert "label_binary" in processed.full.columns
    assert set(processed.full["label_original"]) == {"BENIGN", "DrDoS_DNS", "Syn", "TFTP", "UDP-lag"}
    assert processed.full.loc[processed.full["label_normalized"] == "BENIGN", "label_binary"].iloc[0] == 0
    assert processed.full.loc[processed.full["label_normalized"] == "DRDOS_DNS", "label_binary"].iloc[0] == 1


def test_preprocessing_selects_numeric_features_and_imputes_missing_values(workspace_tmp_path):
    processed = CICDDoS2019Preprocessor(config(workspace_tmp_path)).preprocess(valid_frame())

    assert "Flow ID" not in processed.feature_columns
    assert "Flow Duration" in processed.feature_columns
    assert not processed.full[processed.feature_columns].isna().any().any()


def test_deterministic_train_test_split(workspace_tmp_path):
    first = CICDDoS2019Preprocessor(config(workspace_tmp_path)).preprocess(valid_frame())
    second = CICDDoS2019Preprocessor(config(workspace_tmp_path)).preprocess(valid_frame())

    pd.testing.assert_frame_equal(first.train, second.train)
    pd.testing.assert_frame_equal(first.test, second.test)


def test_o2_mapping_is_explicit_not_non_normal_guessing():
    mapping = build_label_mapping(("BENIGN",), ("DrDoS_DNS",))

    assert normalize_label(" udp-lag ") == "UDP-LAG"
    assert map_o2_binary_label("BENIGN", mapping) == 0
    assert map_o2_binary_label("DrDoS_DNS", mapping) == 1
    assert map_o2_binary_label("SomeOtherAttack", mapping) is None


def _seed_with_extreme_test_row(frame):
    for seed in range(100):
        _, test = deterministic_train_test_split(frame, test_size=0.25, random_seed=seed)
        if test["Flow Duration"].tolist() == [1000.0]:
            return seed, test.index[0]
    raise AssertionError("Could not find deterministic split for leakage fixture")


def test_imputation_is_fit_on_training_rows_only(workspace_tmp_path):
    frame = pd.DataFrame(
        {
            "Flow Duration": [10.0, 20.0, 30.0, 1000.0],
            "Total Fwd Packets": [1, 2, 3, 4],
            "Protocol": [6, 6, 17, 17],
            "Label": ["BENIGN", "BENIGN", "Syn", "Syn"],
        }
    )
    seed, test_index = _seed_with_extreme_test_row(frame)
    processed = CICDDoS2019Preprocessor(
        config(workspace_tmp_path, random_seed=seed, test_size=0.25)
    ).preprocess(frame)

    assert processed.preprocessing_metadata["imputation_parameters"]["Flow Duration"] == 20.0
    assert processed.preprocessing_metadata["imputation_parameters_fit"] == "FIT_ON_TRAIN_ONLY"
    assert processed.test["Flow Duration"].iloc[0] == 1000.0
    assert test_index not in processed.train.index


def test_changing_test_values_does_not_change_training_imputation(workspace_tmp_path):
    frame = pd.DataFrame(
        {
            "Flow Duration": [10.0, 20.0, 30.0, 1000.0],
            "Total Fwd Packets": [1, 2, 3, 4],
            "Protocol": [6, 6, 17, 17],
            "Label": ["BENIGN", "BENIGN", "Syn", "Syn"],
        }
    )
    seed, test_index = _seed_with_extreme_test_row(frame)
    changed = frame.copy()
    changed.loc[test_index, "Flow Duration"] = 999999.0
    first = CICDDoS2019Preprocessor(config(workspace_tmp_path, random_seed=seed, test_size=0.25)).preprocess(frame)
    second = CICDDoS2019Preprocessor(config(workspace_tmp_path, random_seed=seed, test_size=0.25)).preprocess(changed)

    assert first.preprocessing_metadata["imputation_parameters"] == second.preprocessing_metadata["imputation_parameters"]


@pytest.mark.parametrize("missing_location", ["training", "test", "both"])
def test_missing_values_use_training_medians(workspace_tmp_path, missing_location):
    frame = pd.DataFrame(
        {
            "Flow Duration": [10.0, 20.0, 30.0, 1000.0],
            "Total Fwd Packets": [1, 2, 3, 4],
            "Protocol": [6, 6, 17, 17],
            "Label": ["BENIGN", "BENIGN", "Syn", "Syn"],
        }
    )
    seed, test_index = _seed_with_extreme_test_row(frame)
    if missing_location in {"training", "both"}:
        frame.loc[[0, 1], "Flow Duration"] = None
    if missing_location in {"test", "both"}:
        frame.loc[test_index, "Flow Duration"] = None

    processed = CICDDoS2019Preprocessor(config(workspace_tmp_path, random_seed=seed, test_size=0.25)).preprocess(frame)
    assert not processed.train[processed.feature_columns].isna().any().any()
    assert not processed.test[processed.feature_columns].isna().any().any()
    expected_median = 20.0 if missing_location == "test" else 30.0
    assert processed.preprocessing_metadata["imputation_parameters"]["Flow Duration"] == expected_median


def test_all_training_values_missing_fails_safely(workspace_tmp_path):
    frame = pd.DataFrame(
        {
            "Flow Duration": [None, None, None, 1000.0],
            "Total Fwd Packets": [1, 2, 3, 4],
            "Protocol": [6, 6, 17, 17],
            "Label": ["BENIGN", "BENIGN", "Syn", "Syn"],
        }
    )
    seed, _ = _seed_with_extreme_test_row(frame.fillna(100.0))
    with pytest.raises(ValueError, match="no valid training values"):
        CICDDoS2019Preprocessor(config(workspace_tmp_path, random_seed=seed, test_size=0.25)).preprocess(frame)


def test_preprocessing_metadata_records_counts_and_fingerprint(workspace_tmp_path):
    processed = CICDDoS2019Preprocessor(config(workspace_tmp_path)).preprocess(valid_frame())
    metadata = processed.preprocessing_metadata
    assert metadata["training_rows"] == len(processed.train)
    assert metadata["test_rows"] == len(processed.test)
    assert metadata["feature_columns"] == processed.feature_columns
    assert metadata["imputation_strategy"] == "median"
    assert metadata["configuration_fingerprint"]


def test_labels_are_never_imputed(workspace_tmp_path):
    processed = CICDDoS2019Preprocessor(config(workspace_tmp_path)).preprocess(valid_frame())
    assert processed.train["label_original"].notna().all()
    assert processed.train["label_normalized"].notna().all()
    assert processed.train["label_binary"].notna().all()
