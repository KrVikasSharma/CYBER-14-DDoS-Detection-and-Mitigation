from sklearn.ensemble import RandomForestClassifier

from ml.o2.config import O2ModelConfig


def build_o2_model(config: O2ModelConfig) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=config.n_estimators,
        max_depth=config.max_depth,
        min_samples_leaf=config.min_samples_leaf,
        random_state=config.random_seed,
        n_jobs=config.n_jobs,
        class_weight="balanced",
    )

