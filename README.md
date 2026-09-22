# CYBER-14: DDoS Detection and Mitigation

KL University capstone project for the Cybersecurity and Blockchain Systems domain.

This repository is organized so the API, ML pipeline, mitigation subsystem, telemetry, tests, evidence, and reports can evolve independently. The current state is an architecture and configuration foundation only. It does not implement the ML model, final dashboard, KPI results, or completed capstone evaluation yet.

## Architecture

```text
backend/
  app/
    main.py              FastAPI application factory and app instance
    config.py            Environment-based compatibility settings import
    api/                 API routers, versioned under /api/v1
    core/                Configuration, logging, and error handling
    services/            Business/service layer used by API handlers
    models/              API/domain model placeholders, not trained ML artifacts
    schemas/             Pydantic request and response schemas
    streaming/           Future streaming and WebSocket pipeline modules
    mitigation/          Future rate limiting, blocking, and response actions
    detection/           Future detector orchestration, separated from routes
    telemetry/           Future metrics and observability collectors

ml/
  data/                  ML-only dataset references and manifests
  preprocessing/         CIC-DDoS2019 preprocessing code
  o2/                    O2 binary attack-vs-legitimate reference detector
  baseline/              Future baseline experiments that are not the O2 reference implementation
  classifier/            Future O4 attack classification work
  o3/                    O3 multi-class attack classification reference model
  evaluation/            O5 metrics, latency, KPI, and acceptance evaluation

data/
  raw/                   Local raw datasets, excluded from Git except .gitkeep
  processed/             Local processed datasets, excluded from Git except .gitkeep
  fixtures/              Small versionable test fixtures

tests/
  unit/                  Unit tests
  integration/           API and subsystem integration tests
  negative/              NT-1 to NT-5 negative tests

dashboard/
  frontend/              Future dashboard application

scripts/                 Developer and reproducibility scripts
evidence/                Versionable evidence artifacts
reports/                 Capstone reports and generated summaries
docs/                    Architecture and implementation documentation
```

## Capstone Separation

- O2 belongs primarily in `ml/o2`, `ml/preprocessing`, `data/fixtures`, `evidence`, and `reports`.
- O3 belongs in `ml/o3` and remains separate from mitigation policy execution.
- Mitigation belongs in `ml/mitigation` as a simulation-only defensive decision engine.
- O4 belongs primarily in `backend/app/streaming`, `backend/app/detection`, `backend/app/telemetry`, and `dashboard/frontend`.
- O5 belongs primarily in `ml/evaluation`, `tests/integration`, `tests/negative`, `evidence`, and `reports`.

## Configuration

Configuration is loaded from environment variables with `pydantic-settings`.

1. Copy `.env.example` to `.env` for local development.
2. Put real secrets only in local environment variables or `.env`.
3. Do not commit `.env` or credentials.

Important variables:

- `APP_NAME`
- `APP_ENV`
- `API_V1_PREFIX`
- `LOG_LEVEL`
- `CORS_ORIGINS`
- `SECRET_KEY`

## CIC-DDoS2019 Data Preparation

The project expects the real CIC-DDoS2019 dataset to be provided locally. The
pipeline does not download the dataset automatically, and it must not substitute
synthetic data when CIC-DDoS2019 is missing.

Prepare data with:

```bash
python scripts/prepare_data.py --input <dataset_path>
```

`<dataset_path>` may be a CSV file or a directory containing CIC-DDoS2019 CSV
files. By default, processed outputs are written to:

```text
data/processed/cic_ddos2019/
```

The command writes:

- `processed_dataset.csv`
- `train.csv`
- `test.csv`
- `validation_report.json`
- `provenance.json`

The command returns a non-zero exit code when the local dataset is unavailable
or mandatory validation fails.

Expected minimum schema:

- `Label`: required attack/benign label column.
- At least one numeric feature column after identifier columns are excluded.
- `Protocol` is optional, but when numeric it must be in the range `0..255`.

Validation checks include required columns, label availability, missing numeric
values, duplicate rows, infinite values, protocol consistency, and documented
O2 label mapping.

Preprocessing steps:

- Preserve the original attack label in `label_original`.
- Normalize the label into `label_normalized`.
- Add the O2 binary interpretation in `label_binary`.
- Select numeric features only.
- Replace infinite values during preprocessing, although validation fails first
  when infinite values are present.
- Impute missing numeric values with medians.
- Drop duplicate rows when configured.
- Create deterministic train/test splits using a configurable random seed.

O2 binary label interpretation:

- Normal/legitimate labels such as `BENIGN`, `NORMAL`, and `LEGITIMATE` map to `0`.
- Documented CIC-DDoS2019 DDoS labels such as `DrDoS_DNS`, `DrDoS_LDAP`,
  `DrDoS_MSSQL`, `DrDoS_NTP`, `Syn`, `TFTP`, `UDP-lag`, and related configured
  DDoS labels map to `1`.
- Unknown non-normal labels fail validation. The pipeline does not assume every
  non-normal label is a DDoS attack.

O3 compatibility:

- Multi-class labels are preserved through `label_original` and
  `label_normalized` so O3 can distinguish attack types.

O3 multi-class classifier:

- O3 targets `label_normalized`; it does not use `label_binary` or
  `label_original` as a target.
- O3 saves its exact numeric feature list and class metadata under
  `ml/artifacts/o3/`.
- Train with `python scripts/train_o3.py --input <processed_dataset.csv>
  --output ml/artifacts/o3` and evaluate with
  `python scripts/evaluate_o3.py --model ml/artifacts/o3/model.joblib
  --test <test.csv> --output <evaluation.json>`.
- Fixture-only O3 results are mechanics checks, not CIC-DDoS2019 measurements
  or CYBER-14 KPI/acceptance results.

Synthetic fixtures:

- Small fixtures under `data/fixtures` may be used for tests only.
- Synthetic fixtures must never be presented as CIC-DDoS2019 evidence.
- Real dataset evidence should be recorded with generated provenance metadata
  and the template in `evidence/dataset_manifest_template.json`.

## Backend

Install dependencies:

```bash
pip install -r requirements-dev.txt
```

Run the API:

```bash
uvicorn app.main:app --app-dir backend --reload
```

Initial endpoints:

- `GET /health`
- `GET /api/v1/system/status`

## Detection API

The backend detection boundary is available at `POST /api/v1/detection/analyze`.
Requests contain `source_identifier`, optional `traffic_rate`, and a numeric
`features` object whose keys must match the explicitly configured O2/O3 artifact
feature contracts. Missing, non-numeric, non-finite, or unexpected malformed
inputs are rejected; the API never fills model inputs with fabricated values.

The service runs `request -> O2 binary detection -> O3 classification when
attack -> simulation-only mitigation -> audit event -> response`. Responses
include O2 detection, optional O3 probabilities, mitigation decision and policy
version, audit event ID, model versions, correlation ID, and measured local
stage/total latency. These latency values are operational telemetry only, not
CYBER-14 KPI measurements.

Configure artifacts explicitly with `O2_MODEL_PATH` and `O3_MODEL_PATH`.
`O2_FIXTURE_ONLY` and `O3_FIXTURE_ONLY` identify fixture-backed artifacts in the
response. Missing or incompatible artifacts fail clearly; fixture artifacts are
not real CIC-DDoS2019 evidence or production readiness claims.

## Streaming API

The controlled streaming endpoint is `WS /ws/traffic`. Each JSON message uses
the same `source_identifier`, optional `traffic_rate`, and numeric `features`
contract as the analyze API. Results use the same O2, O3, mitigation, audit, and
latency response data wrapped as `type: detection_result`; malformed messages
return structured `type: error` responses without crashing the connection.

The development-only simulator is `POST /api/v1/stream/simulate` with one of
`benign`, `flash_crowd`, or `attack_fixture`. It creates only deterministic
application-level observations and labels them `controlled_simulator`; it does
not create packets, floods, sockets, or real DDoS traffic. The simulator is
disabled by default and requires `STREAM_SIMULATOR_ENABLED=true`.

Streaming limits are configurable with `WEBSOCKET_MAX_MESSAGE_BYTES`,
`WEBSOCKET_MAX_MESSAGES_PER_SECOND`, and `WEBSOCKET_IDLE_TIMEOUT_SECONDS`.
Oversized or rate-excessive connections receive structured errors and close
safely. WebSocket streaming is operational plumbing only and does not claim
KPI, acceptance, or real-dataset performance results.

## O2 Reference Detector

O2 is the binary attack-vs-legitimate reference detector. It is separate from
O3, which will later classify attack types.

The O2 detector consumes only processed CSVs produced by the preprocessing
pipeline. Its target is:

```text
label_binary
```

Feature contract:

- Include numeric feature columns from the processed CSV in column order.
- Exclude `label_binary`, `label_original`, and `label_normalized`.
- Exclude raw identifiers such as flow IDs, IP addresses, ports, timestamps, and
  similar source/destination identity fields.
- Reject obvious leakage columns prefixed with `mitigation_`, `decision_`,
  `acceptance_`, `kpi_`, or `latency_`.
- Save the exact trained feature list in `feature_metadata.json`.

The current reference model is:

```text
sklearn.ensemble.RandomForestClassifier
```

It is intentionally simple and reproducible, using configurable random seed,
tree count, depth, split size, and artifact directory. It does not implement the
future O3 multi-class classifier.

Train:

```bash
python scripts/train_o2.py --input <processed_dataset.csv> --output ml/artifacts/o2
```

Evaluate:

```bash
python scripts/evaluate_o2.py --model ml/artifacts/o2/model.joblib --test <test.csv> --output <evaluation.json>
```

Artifacts:

- `ml/artifacts/o2/model.joblib`
- `ml/artifacts/o2/feature_metadata.json`
- `ml/artifacts/o2/training_metadata.json`
- `ml/artifacts/o2/o2_reference_record.json`

Evaluation calculates actual accuracy, precision, recall, F1-score, confusion
matrix, false-positive rate, false-negative rate, sample count, attack count,
and legitimate count from the supplied test data. Latency measurement is local
O2 reference inference timing only; it is not a formal CYBER-14 acceptance/KPI
result.

Real O2 performance cannot be claimed until the actual CIC-DDoS2019 dataset is
supplied, processed, trained, and evaluated. The fixture
`data/fixtures/o2_tiny_processed_fixture.csv` exists only for deterministic test
and CLI mechanics.

## Current Scope

Implemented now:

- Project architecture
- Environment-based configuration
- FastAPI app foundation
- Versioned API router
- CORS setup
- Structured exception handlers
- Logging setup
- Pydantic response schemas
- Service boundary for system status
- CIC-DDoS2019 local ingestion/preprocessing foundation
- Dataset validation, provenance, and metadata generation
- Unit tests for data validation and preprocessing
- O2 binary reference detector foundation
- O2 training/evaluation CLI and fixture-only tests
- O3 multi-class reference classifier, CLI, artifacts, and fixture-only tests
- Simulation-only mitigation policy, state recovery, and audit subsystem
- Measurement, evidence, and acceptance-status framework

Not implemented yet:

- WebSocket streaming
- Dashboard frontend
- Formal KPI, acceptance, and real CIC-DDoS2019 performance results

## Measurement and Acceptance Framework

The measurement layer lives under `ml/evaluation` and provides actual metric,
confusion, latency, comparison, oracle, trial, and evidence helpers. The
acceptance and negative-test CLIs write machine-readable run directories under
`evidence/acceptance/runs/` and `evidence/negative_tests/runs/`.

Run the controlled fixture-mode harnesses with:

```bash
python scripts/run_acceptance.py --config evidence/acceptance/acceptance_config.json --fixture-only
python scripts/run_negative_tests.py --config evidence/acceptance/acceptance_config.json --fixture-only
```

Fixture mode verifies harness mechanics only. It marks official KPI-1 through
KPI-6 and AC-1 through AC-4 as `NOT_EXECUTED`, and NT-1 through NT-5 as
`BLOCKED`; it sets `official_cyber14_kpi_result` to `false`. No threshold,
reviewer, provenance, or real CIC-DDoS2019 result is invented.

## Mitigation Subsystem

`ml/mitigation` consumes validated O2/O3 detection results and produces one of
`ALLOW`, `RATE_LIMIT`, or `BLOCK`. Trusted classifications below the configured
traffic threshold are allowed. Trusted high-volume traffic is rate-limited as
flash-crowd containment, while known attacks above the configured confidence
threshold are temporarily blocked. Known attacks below that threshold receive
temporary rate limiting instead of an unverified permanent block.

The policy version, confidence thresholds, traffic threshold, rate-limit
parameters, block duration, and state expiry are configurable. Temporary states
expire automatically or can be explicitly revoked; both paths record recovery
events. Invalid or unknown detection results fail securely and are never silently
converted to `ALLOW`.

The current `SimulatedMitigationExecutor` records actions in memory only. It
does not call iptables, nftables, cloud firewalls, routers, or any other network
infrastructure. A future FastAPI/streaming boundary may call the Python engine
after detection and classification are available. Official NT-1 through NT-5,
KPI, and acceptance testing are not implemented or claimed.

## Local Authentication Boundary

The backend provides `POST /api/v1/auth/login`, `GET /api/v1/auth/me`, and
`POST /api/v1/auth/logout`. With `AUTH_ENABLED=false` (the default), existing
development workflows use an explicitly labeled `local_development` identity.
With auth enabled, `AUTH_SECRET_KEY` and `AUTH_BOOTSTRAP_PASSWORD` are required;
missing configuration fails closed. Passwords are verified with bcrypt and
never returned. Short-lived signed tokens are used; logout clears the client
token and stateless tokens remain valid only until expiry.

Roles are least-privilege scoped: `viewer` reads protected data, `analyst` may
run detection, `operator` may run the controlled simulator and simulated
mitigation workflows, and `admin` has all local permissions. Backend checks
enforce these roles independently of frontend visibility. This is local/demo
authentication, not production IAM.
