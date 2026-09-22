import re


def normalize_label(label: object) -> str:
    value = str(label).strip().upper()
    value = re.sub(r"\s+", "_", value)
    value = value.replace("__", "_")
    return value


def build_label_mapping(
    normal_labels: tuple[str, ...],
    ddos_labels: tuple[str, ...],
) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for label in normal_labels:
        mapping[normalize_label(label)] = 0
    for label in ddos_labels:
        mapping[normalize_label(label)] = 1
    return mapping


def map_o2_binary_label(label: object, mapping: dict[str, int]) -> int | None:
    return mapping.get(normalize_label(label))
