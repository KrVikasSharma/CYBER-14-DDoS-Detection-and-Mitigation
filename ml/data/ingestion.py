from pathlib import Path

import pandas as pd


class DatasetUnavailableError(FileNotFoundError):
    """Raised when the requested local dataset cannot be found."""


class DatasetIngestor:
    def __init__(self, input_path: Path) -> None:
        self.input_path = input_path

    def discover_csv_files(self) -> list[Path]:
        if not self.input_path.exists():
            raise DatasetUnavailableError(
                f"Dataset path does not exist: {self.input_path}. "
                "Provide a local CIC-DDoS2019 file or directory; the pipeline does not "
                "download datasets or substitute synthetic data."
            )

        if self.input_path.is_file():
            if self.input_path.suffix.lower() != ".csv":
                raise DatasetUnavailableError(f"Dataset file is not a CSV: {self.input_path}")
            return [self.input_path]

        csv_files = sorted(self.input_path.rglob("*.csv"))
        if not csv_files:
            raise DatasetUnavailableError(f"No CSV files found under dataset path: {self.input_path}")
        return csv_files

    def load(self) -> tuple[pd.DataFrame, list[Path]]:
        csv_files = self.discover_csv_files()
        frames = []
        for csv_file in csv_files:
            df = pd.read_csv(csv_file, low_memory=False)
            df.columns = [col.strip() for col in df.columns]
            frames.append(df)
        dataset = pd.concat(frames, ignore_index=True) if len(frames) > 1 else frames[0]
        return dataset, csv_files
