# Architecture Notes

CYBER-14 is separated into API, ML, mitigation, telemetry, dashboard, tests, evidence, and reporting areas.

## Backend Boundary

The FastAPI backend exposes health and versioned API endpoints. Route handlers should validate inputs and delegate behavior to services. Detection, classification, mitigation, telemetry, and streaming logic should live in their own packages under `backend/app`.

## ML Boundary

ML code belongs under `ml`. The API may later call inference services or model adapters, but training, evaluation, preprocessing, and model artifact management should remain outside route handlers and outside dashboard code.

The CIC-DDoS2019 ingestion and preprocessing pipeline is split across:

- `ml/data`: configuration, local dataset ingestion, and provenance metadata.
- `ml/preprocessing`: validation, label handling, numeric preprocessing, and deterministic train/test preparation.
- `data/raw`: local raw dataset placement, excluded from Git except `.gitkeep`.
- `data/processed`: generated processed outputs, excluded from Git except `.gitkeep`.
- `data/fixtures`: small test fixtures only.

The pipeline accepts a configurable local dataset path. It never downloads large
datasets automatically and never substitutes synthetic data for CIC-DDoS2019.
When the dataset is unavailable, the CLI fails with a non-zero exit code and a
clear message.

O2 label handling is explicit: documented normal/legitimate labels map to `0`,
documented CIC-DDoS2019 DDoS labels map to `1`, and unknown labels fail
validation instead of being guessed. O3 compatibility is preserved by retaining
original and normalized multi-class labels.

## O2 Boundary

The O2 reference detector lives under `ml/o2`. It consumes the processed output
from `ml/preprocessing`; it does not read raw CIC-DDoS2019 files directly and it
does not live in FastAPI route handlers.

O2 input/output contract:

- Input: processed CSV containing numeric features plus `label_binary`,
  `label_original`, and `label_normalized`.
- Target: `label_binary`.
- Features: numeric columns in processed CSV order after excluding labels,
  identifiers, timestamps, source/destination identity fields, and post-decision
  or evaluation fields.
- Output artifacts: `ml/artifacts/o2/model.joblib`,
  `feature_metadata.json`, `training_metadata.json`, and
  `o2_reference_record.json`.

The O2 model type is currently `RandomForestClassifier`, configured with fixed
random seed support and deterministic splits. O2 evaluation calculates metrics
from supplied data and latency from local prediction calls. These measurements
are reference measurements only until a formal O5 acceptance harness is added.

O2 remains separate from O3: it predicts only attack-vs-legitimate binary
labels. O3 is implemented separately under `ml/o3` and predicts the normalized
multi-class `label_normalized` target for attack-type classification. O3 excludes
all label columns from features, rejects post-decision/evaluation leakage, and
saves the exact numeric feature list with its artifact. O3 fixture metrics and
local latency are not real CIC-DDoS2019 measurements or CYBER-14 KPI/acceptance
results.

## Mitigation Boundary

The controlled mitigation decision engine lives under `ml/mitigation` and
consumes detection/classification results from the O2/O3 boundary. It does not
retrain or modify either model. Its configurable policy distinguishes trusted
classification, confidence, and traffic rate: normal traffic is allowed,
trusted high-volume traffic is rate-limited as flash-crowd containment, and
known attacks meeting the confirmed threshold are temporarily blocked. Known
attacks below that threshold receive configured temporary containment instead of
an unverified permanent block.

`MitigationEngine` returns a structured decision and sends it only to the
`SimulatedMitigationExecutor`. The executor records actions in memory and never
executes iptables, nftables, cloud firewall, router, or other network changes.
Temporary rate-limit/block states have bounded expiry, active-state lookup,
explicit revoke/reset, recovery records, and structured audit events. Invalid
or incomplete inputs fail securely rather than defaulting to `ALLOW`.

This package is an internal Python service boundary for a future flow of
detection result -> O3 classification -> mitigation policy -> decision -> audit
event. The backend API and WebSocket integration are intentionally deferred.

The mitigation design preserves enough structured state for future NT-1 through
NT-5 tests to verify flash-crowd containment and recovery, attack-type diversity,
timing/accuracy conditions, authorization boundaries, and expiry/revocation
propagation. Those official negative and acceptance tests are not implemented
or claimed.

## Detection API Boundary

The FastAPI service exposes `POST /api/v1/detection/analyze`. It accepts a
validated source identifier, optional traffic rate, and numeric feature mapping.
The mapping must contain the features required by the explicitly configured O2
and O3 artifacts; the service does not invent missing model inputs or accept an
artifact path from the request.

The orchestration is request -> O2 binary attack-vs-legitimate detection -> O3
multi-class classification for attack results -> existing mitigation policy and
`SimulatedMitigationExecutor` -> audit event -> structured response. Models are
loaded once by a cached service, metadata and target contracts are checked, and
missing/incompatible artifacts fail clearly. O2 and O3 fixture-only status is
explicitly returned when configured.

The response reports actual local feature-preparation, O2, O3, mitigation, and
total processing latency. These are operational telemetry only, not KPI or
acceptance measurements. Real network blocking, dashboard, WebSocket streaming,
and acceptance harnesses remain deferred.

## Streaming Boundary

The streaming pipeline exposes `WS /ws/traffic` and reuses the existing
`DetectionService`; it does not duplicate O2, O3, or mitigation logic. Each
message is validated against the same model feature contract as
`POST /api/v1/detection/analyze`, then follows validation -> O2 -> O3 when the
binary result is an attack -> mitigation -> audit -> structured stream result.
Malformed JSON, invalid observations, missing/extra features, oversized
messages, and per-connection rate violations produce sanitized structured errors
and do not crash the server.

`POST /api/v1/stream/simulate` is a development-only controlled source with
allowlisted `benign`, `flash_crowd`, and `attack_fixture` scenarios. It sends
deterministic application-level observations through the same detection service
and marks their source as `controlled_simulator`. It never generates packets,
network floods, sockets, or real DDoS traffic. The simulator is disabled by
default.

The configurable limits are maximum message bytes, messages per second, and
idle timeout. Active connections are removed on disconnect or timeout. Streaming
latency and results are operational telemetry only; no KPI, acceptance, or
production-readiness claim is made.

## Evidence and Reports

Versionable capstone evidence should go in `evidence`. Written reports and generated summaries should go in `reports`. Large datasets and generated model binaries should not be committed unless explicitly required and approved.

`evidence/dataset_manifest_template.json` is a template for future real dataset
evidence. Unknown metadata should remain null or empty until verified from the
actual dataset source or local files. Synthetic fixtures must not be presented as
real CIC-DDoS2019 evidence.

`evidence/o2_reference_record_template.json` documents the machine-readable O2
record shape. It must contain only real measured metrics when produced by
training/evaluation runs; null values in the template are not results.

`evidence/mitigation_record_template.json` documents the mitigation input,
policy decision, simulated action, expiry/recovery, and audit record shape. It is
a template only and contains no acceptance evidence.

## Measurement Boundary

The measurement layer under `ml/evaluation` calculates supplied observations; it
does not manufacture data or infer ground truth from model predictions. It
supports KPI-1 through KPI-6 metric primitives, repeated latency trials with a
30-trial minimum for official latency runs, explicit threshold comparisons,
frozen configuration hashes, deterministic fixture oracles, and evidence
manifests.

`scripts/run_acceptance.py` emits KPI-1 through KPI-6 and AC-1 through AC-4
records. `scripts/run_negative_tests.py` emits structured NT-1 through NT-5
records. The checked-in configuration uses fixture-only references and no
official thresholds, so those runs remain `NOT_EXECUTED` or `BLOCKED` rather
than PASS. Real CIC-DDoS2019 data, independent authorized acceptance conditions,
reviewer evidence, and official KPI definitions/thresholds remain unavailable.

## Security Boundary

`backend/app/auth` provides local development authentication with bcrypt password
verification, short-lived signed access tokens, environment-provided secrets,
generic login failures, login throttling, and structured security events. The
least-privilege roles are `viewer`, `analyst`, `operator`, and `admin`.

Health remains public. Detection requires analyst or higher; controlled
simulation and WebSocket streaming require operator or admin. With
`AUTH_ENABLED=false`, the service uses an explicit `local_development` identity
to preserve existing workflows. With auth enabled, missing secret or bootstrap
password configuration fails closed. This is not production IAM and no security
acceptance result is claimed.
