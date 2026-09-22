from dataclasses import asdict, dataclass
from pathlib import Path

O2_MODEL_IDENTIFIER = "cyber14-o2-random-forest-reference"
O2_MODEL_VERSION = "0.1.0"
O2_TARGET_COLUMN = "label_binary"
O2_LABEL_COLUMNS = ("label_binary", "label_original", "label_normalized")
O2_FORBIDDEN_PREFIXES = ("mitigation_", "decision_", "acceptance_", "kpi_", "latency_")
O2_FORBIDDEN_COLUMNS = (
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


@dataclass(frozen=True)
class O2ModelConfig:
    model_identifier: str = O2_MODEL_IDENTIFIER
    model_version: str = O2_MODEL_VERSION
    target_column: str = O2_TARGET_COLUMN
    random_seed: int = 42
    test_size: float = 0.2
    n_estimators: int = 50
    max_depth: int | None = 8
    min_samples_leaf: int = 1
    n_jobs: int = 1
    artifact_dir: Path = Path("ml/artifacts/o2")
    manifest_path: Path | None = None

    def to_metadata(self) -> dict[str, object]:
        metadata = asdict(self)
        metadata["artifact_dir"] = str(self.artifact_dir)
        metadata["manifest_path"] = str(self.manifest_path) if self.manifest_path else None
        return metadata


@dataclass(frozen=True)
class O2ArtifactPaths:
    artifact_dir: Path
    model_path: Path
    feature_metadata_path: Path
    training_metadata_path: Path
    reference_record_path: Path


def build_artifact_paths(artifact_dir: Path) -> O2ArtifactPaths:
    return O2ArtifactPaths(
        artifact_dir=artifact_dir,
        model_path=artifact_dir / "model.joblib",
        feature_metadata_path=artifact_dir / "feature_metadata.json",
        training_metadata_path=artifact_dir / "training_metadata.json",
        reference_record_path=artifact_dir / "o2_reference_record.json",
    )

