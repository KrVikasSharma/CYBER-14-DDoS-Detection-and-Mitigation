from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_NORMAL_LABELS = ("BENIGN", "NORMAL", "LEGITIMATE")

DEFAULT_DDOS_LABELS = (
    "DDOS",
    "DRDOS_DNS",
    "DRDOS_LDAP",
    "DRDOS_MSSQL",
    "DRDOS_NETBIOS",
    "DRDOS_NTP",
    "DRDOS_SNMP",
    "DRDOS_SSDP",
    "DRDOS_UDP",
    "SYN",
    "TFTP",
    "UDP-LAG",
    "UDPLAG",
    "WEB-DDOS",
    "WEBDDOS",
    "PORTMAP",
    "LDAP",
    "MSSQL",
    "NETBIOS",
    "UDP",
)

DEFAULT_EXCLUDED_COLUMNS = (
    "Unnamed: 0",
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
class DatasetPipelineConfig:
    input_path: Path
    output_dir: Path = Path("data/processed/cic_ddos2019")
    dataset_name: str = "CIC-DDoS2019"
    source_reference: str = "Canadian Institute for Cybersecurity CIC-DDoS2019 dataset"
    access_download_date: str | None = None
    dataset_version: str | None = None
    label_column: str = "Label"
    required_columns: tuple[str, ...] = ("Label",)
    excluded_columns: tuple[str, ...] = DEFAULT_EXCLUDED_COLUMNS
    normal_labels: tuple[str, ...] = DEFAULT_NORMAL_LABELS
    ddos_labels: tuple[str, ...] = DEFAULT_DDOS_LABELS
    random_seed: int = 42
    test_size: float = 0.2
    drop_duplicate_rows: bool = True
    missing_numeric_strategy: str = "median"
    allow_infinite_numeric: bool = False
    output_format: str = "csv"
    transformations: tuple[str, ...] = field(
        default=(
            "load_csv_files",
            "validate_schema_and_quality_gates",
            "preserve_original_labels",
            "normalize_labels",
            "map_documented_o2_binary_labels",
            "select_numeric_features",
            "replace_infinite_values",
            "impute_missing_numeric_values",
            "drop_duplicate_rows_when_configured",
            "deterministic_train_test_split",
        )
    )

    def to_metadata(self) -> dict[str, object]:
        metadata = asdict(self)
        metadata["input_path"] = str(self.input_path)
        metadata["output_dir"] = str(self.output_dir)
        return metadata
