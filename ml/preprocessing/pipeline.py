from dataclasses import dataclass
from pathlib import Path

from ml.data.config import DatasetPipelineConfig
from ml.data.ingestion import DatasetIngestor
from ml.data.provenance import build_provenance_record, write_json
from ml.preprocessing.preprocessor import CICDDoS2019Preprocessor
from ml.preprocessing.validation import DatasetValidator


@dataclass
class PipelineResult:
    output_dir: Path
    processed_path: Path
    train_path: Path
    test_path: Path
    provenance_path: Path
    validation_report_path: Path
    preprocessing_metadata_path: Path


class CICDDoS2019Pipeline:
    def __init__(self, config: DatasetPipelineConfig) -> None:
        self.config = config

    def run(self) -> PipelineResult:
        ingestor = DatasetIngestor(self.config.input_path)
        raw_dataset, files = ingestor.load()

        validator = DatasetValidator(self.config)
        validation_report = validator.assert_valid(raw_dataset)

        preprocessor = CICDDoS2019Preprocessor(self.config)
        processed = preprocessor.preprocess(raw_dataset)

        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        processed_path = output_dir / "processed_dataset.csv"
        train_path = output_dir / "train.csv"
        test_path = output_dir / "test.csv"
        validation_report_path = output_dir / "validation_report.json"
        provenance_path = output_dir / "provenance.json"
        preprocessing_metadata_path = output_dir / "preprocessing_metadata.json"

        processed.full.to_csv(processed_path, index=False)
        processed.train.to_csv(train_path, index=False)
        processed.test.to_csv(test_path, index=False)

        write_json(validation_report_path, validation_report.to_dict())
        provenance = build_provenance_record(
            self.config,
            files,
            raw_dataset,
            processed.full,
            validation_report,
        )
        provenance["feature_columns"] = processed.feature_columns
        provenance["preprocessing_metadata"] = processed.preprocessing_metadata
        write_json(provenance_path, provenance)
        write_json(preprocessing_metadata_path, processed.preprocessing_metadata)

        return PipelineResult(
            output_dir=output_dir,
            processed_path=processed_path,
            train_path=train_path,
            test_path=test_path,
            provenance_path=provenance_path,
            validation_report_path=validation_report_path,
            preprocessing_metadata_path=preprocessing_metadata_path,
        )
