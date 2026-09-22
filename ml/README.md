# ML Workspace

This area will hold the reproducible machine-learning work for CYBER-14.

- `preprocessing/`: CIC-DDoS2019 cleaning and feature preparation.
- `o2/`: O2 binary attack-vs-legitimate reference detector.
- `baseline/`: Future baseline experiments that are not the O2 reference implementation.
- `o3/`: O3 multi-class attack classification reference implementation.
- `classifier/`: Future O4 attack-type classifier experiments and training code.
- `evaluation/`: O5 accuracy, latency, acceptance, negative, and KPI evaluation.
- `data/`: ML manifests and small versionable metadata, not large raw datasets.

Do not place ML training or inference logic directly inside FastAPI route handlers.

## CIC-DDoS2019 Ingestion and Preprocessing

The current ML implementation provides data ingestion, preprocessing, the O2
binary reference detector, and the O3 multi-class reference classifier. It does
not implement mitigation or KPI/acceptance calculations.

Run:

```bash
python scripts/prepare_data.py --input <dataset_path>
```

`<dataset_path>` must point to a local CIC-DDoS2019 CSV file or a directory of
CSV files. Large datasets are not downloaded automatically and are not committed
to Git.

Pipeline modules:

- `ml/data/config.py`: deterministic pipeline configuration.
- `ml/data/ingestion.py`: local CSV discovery and loading.
- `ml/data/provenance.py`: provenance and schema metadata.
- `ml/preprocessing/validation.py`: schema and quality gates.
- `ml/preprocessing/labels.py`: documented O2 label mapping.
- `ml/preprocessing/preprocessor.py`: reusable preprocessing functions.
- `ml/preprocessing/pipeline.py`: orchestration and output writing.

Expected schema:

- Required: `Label`.
- Required after exclusions: at least one numeric feature column.
- Optional: `Protocol`; numeric values must be between `0` and `255`.

Quality gates:

- Missing dataset path fails.
- Missing required columns fail.
- Missing labels fail.
- Infinite numeric values fail.
- Invalid numeric protocol values fail.
- Unknown labels that cannot be mapped to the documented O2 binary label fail.

Preprocessing:

- Original labels are preserved as `label_original`.
- Multi-class normalized labels are preserved as `label_normalized`.
- O2 binary labels are written as `label_binary`.
- Numeric missing values are imputed with medians.
- Duplicate rows are dropped when configured.
- Train/test output is deterministic for a fixed random seed.

Synthetic fixtures may support tests, but they are not CIC-DDoS2019 evidence.
Do not use fixtures to make claims about capstone accuracy, latency, KPIs, or
acceptance results.

## O2 Reference Detector

O2 provides a reproducible binary reference detector:

- `0`: normal/legitimate traffic as produced by `label_binary`.
- `1`: documented DDoS attack traffic as produced by `label_binary`.

O2 does not classify attack types. O3 uses preserved `label_normalized` values
for multi-class classification.

Modules:

- `ml/o2/config.py`: model and artifact configuration.
- `ml/o2/features.py`: input contract, feature selection, and leakage guards.
- `ml/o2/model.py`: RandomForest reference model factory.
- `ml/o2/train.py`: reproducible training and artifact metadata.
- `ml/o2/predict.py`: artifact loading and prediction helpers.
- `ml/o2/evaluate.py`: metrics and latency measurement.

Input contract:

- Input must be a processed CSV from the CIC-DDoS2019 preprocessing pipeline.
- Target column must be `label_binary`.
- Features are numeric columns in processed CSV order after exclusions.
- Excluded columns include `label_binary`, `label_original`, `label_normalized`,
  raw identifiers, timestamps, source/destination fields, and post-decision or
  evaluation columns.
- The exact feature list used for a trained artifact is stored in
  `feature_metadata.json`.

Training:

```bash
python scripts/train_o2.py --input <processed_dataset.csv> --output ml/artifacts/o2
```

Evaluation:

```bash
python scripts/evaluate_o2.py \
  --model ml/artifacts/o2/model.joblib \
  --test <test.csv> \
  --output <evaluation.json>
```

Artifact location:

```text
ml/artifacts/o2/
```

Reproducibility controls:

- Configurable random seed.
- Deterministic train/test split.
- Configurable RandomForest parameters.
- Saved feature metadata.
- Saved training metadata with package versions.
- Machine-readable O2 reference record.

Limitations:

- The current O2 model is a reference baseline, not a final optimized detector.
- Fixture metrics and latency are test mechanics only.
- Real CIC-DDoS2019 O2 performance cannot be claimed until the real dataset is
  supplied, processed, trained, and evaluated.

## O3 Multi-Class Classifier

O3 is separate from O2 and predicts the normalized multi-class target
`label_normalized`. It does not use `label_binary` or `label_original` as a
target. Its deterministic numeric feature contract excludes labels, raw
identifiers, timestamps, and mitigation/decision/evaluation fields, and the
exact feature list is saved with the model.

Modules:

- `ml/o3/config.py`: model, target, label, and artifact configuration.
- `ml/o3/features.py`: numeric feature selection and leakage guards.
- `ml/o3/model.py`: reproducible `GradientBoostingClassifier` factory.
- `ml/o3/train.py`: training and metadata artifact generation.
- `ml/o3/predict.py`: artifact loading, class prediction, and probabilities.
- `ml/o3/evaluate.py`: multi-class metrics, confusion matrix, and local latency.

Train and evaluate:

```bash
python scripts/train_o3.py --input <processed_dataset.csv> --output ml/artifacts/o3
python scripts/evaluate_o3.py --model ml/artifacts/o3/model.joblib --test <test.csv> --output <evaluation.json>
```

`data/fixtures/o3_tiny_processed_fixture.csv` is a deterministic multi-class
fixture only. Its metrics and latency are not real CIC-DDoS2019 measurements,
CYBER-14 KPI results, or acceptance results.

## Mitigation Decision Engine

`ml/mitigation` is a separate internal service boundary that consumes validated
detection/classification results; it does not retrain or modify O2/O3 models.
Its configurable policy produces:

- `ALLOW` for trusted legitimate traffic below the flash-crowd threshold.
- `RATE_LIMIT` for trusted high-volume traffic and uncertain known attacks.
- `BLOCK` for known attacks meeting the confirmed-confidence threshold.

The engine stores temporary state in memory, records expiry and explicit revoke
recovery, and emits structured machine-readable audit events containing the
decision ID, policy version, input classification, action, state transition,
executor, and outcome. Invalid inputs, unknown classes, missing policy, invalid
confidence, and malformed identifiers fail securely rather than defaulting to
allow.

`SimulatedMitigationExecutor` is the only executor currently provided. It only
records `ALLOW`, `RATE_LIMIT`, and `BLOCK` locally; it performs no real network,
firewall, router, or cloud infrastructure changes. The evidence template is
`evidence/mitigation_record_template.json`.

The design leaves room for future NT-1 through NT-5 tests to inspect containment,
classification diversity, timing/accuracy tradeoffs, authorization boundaries,
and expiry/revocation propagation. Those official negative and acceptance tests
are not implemented or claimed.

## Measurement and Acceptance

`ml/evaluation` contains reusable calculations for binary accuracy and false
positive rate, attack-path detection rate, multi-class confusion, repeated
latency percentiles, threshold comparison, explicit ground-truth oracles,
trial execution, and evidence manifests. The framework does not hard-code KPI
thresholds or measured values.

`scripts/run_acceptance.py` and `scripts/run_negative_tests.py` consume the
versioned `evidence/acceptance/acceptance_config.json` configuration. Fixture
mode generates evidence files while preserving `NOT_EXECUTED` and `BLOCKED`
statuses. Official PASS requires real supplied data, frozen official criteria,
authorized conditions, and evidence; fixture outputs are never CIC-DDoS2019,
KPI, or acceptance evidence.

## Authentication Boundary

`backend/app/auth` provides local development authentication using bcrypt,
short-lived signed tokens, environment-provided secrets, a bootstrap account,
and `viewer`, `analyst`, `operator`, and `admin` roles. Detection requires
analyst+ access; simulator and stream actions require operator+ access. Health
remains public. Set `AUTH_ENABLED=true`, `AUTH_SECRET_KEY`, and
`AUTH_BOOTSTRAP_PASSWORD` only through a local environment or secret manager.
With auth disabled, the system reports `local_development` mode and preserves
existing workflows. This is not production IAM or an official acceptance result.
