from dataclasses import asdict, dataclass
from pathlib import Path

from ml.data.config import DEFAULT_DDOS_LABELS, DEFAULT_NORMAL_LABELS
from ml.preprocessing.labels import normalize_label

O3_MODEL_IDENTIFIER = "cyber14-o3-gradient-boosting-reference"
O3_MODEL_VERSION = "0.1.0"
O3_TARGET_COLUMN = "label_normalized"
O3_LABEL_COLUMNS = ("label_binary", "label_original", "label_normalized")
O3_FORBIDDEN_PREFIXES = (
    "mitigation_",
    "decision_",
    "acceptance_",
    "kpi_",
    "latency_",
    "result_",
)
O3_FORBIDDEN_COLUMNS = (
    "Unnamed: 0",
    "Label",
    "Flow ID",
    "Source IP",
    "Src IP",
    "Destination IP",
    "Dst IP",
    "Source Port",
    "Src Port",
    "Destination Port",
    "Dst Port",
    "Timestamp",
    "SimillarHTTP",
    "Inbound",
)


def known_o3_labels() -> tuple[str, ...]:
    labels = {normalize_label(label) for label in DEFAULT_NORMAL_LABELS + DEFAULT_DDOS_LABELS}
    return tuple(sorted(labels))


@dataclass(frozen=True)
class O3ModelConfig:
    model_identifier: str = O3_MODEL_IDENTIFIER
    model_version: str = O3_MODEL_VERSION
    target_column: str = O3_TARGET_COLUMN
    random_seed: int = 42
    test_size: float = 0.2
    n_estimators: int = 100
    learning_rate: float = 0.1
    max_depth: int = 3
    artifact_dir: Path = Path("ml/artifacts/o3")
    manifest_path: Path | None = None

    def to_metadata(self) -> dict[str, object]:
        metadata = asdict(self)
        metadata["artifact_dir"] = str(self.artifact_dir)
        metadata["known_labels"] = list(known_o3_labels())
        metadata["manifest_path"] = str(self.manifest_path) if self.manifest_path else None
        return metadata


@dataclass(frozen=True)
class O3ArtifactPaths:
    artifact_dir: Path
    model_path: Path
    feature_metadata_path: Path
    training_metadata_path: Path
    class_metadata_path: Path
    reference_record_path: Path


def build_artifact_paths(artifact_dir: Path) -> O3ArtifactPaths:
    return O3ArtifactPaths(
        artifact_dir=artifact_dir,
        model_path=artifact_dir / "model.joblib",
        feature_metadata_path=artifact_dir / "feature_metadata.json",
        training_metadata_path=artifact_dir / "training_metadata.json",
        class_metadata_path=artifact_dir / "class_metadata.json",
        reference_record_path=artifact_dir / "o3_reference_record.json",
    )

