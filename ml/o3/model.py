from sklearn.ensemble import GradientBoostingClassifier

from ml.o3.config import O3ModelConfig


def build_o3_model(config: O3ModelConfig) -> GradientBoostingClassifier:
    return GradientBoostingClassifier(
        n_estimators=config.n_estimators,
        learning_rate=config.learning_rate,
        max_depth=config.max_depth,
        random_state=config.random_seed,
    )

