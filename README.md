# FlowLab

A local intrusion detection research workbench: train classifiers, inspect flow
predictions, process PCAPs, compare random and burst packet loss, and connect an
isolated VM lab for measured live traffic and connection enforcement.

## Start

```bash
cd /home/sirnike/MIT/InfoSecProject
./start.sh
```

The browser opens at **http://127.0.0.1:8765**. Use `./start.sh --no-browser` for
headless startup. Use `--port 8766` if the default port is occupied. The app binds
only to loopback and rejects cross-origin writes.

The current workspace already has corrected CICIDS2017 data, prepared splits,
and 84 trained artifacts, including CICIDS baselines and tuned models, real VM
completed and prefix models, and clearly marked synthetic fixtures. The four KVM guests
are provisioned and verified. The startup script starts this project’s existing
guests if they are shut off, then opens the local dashboard. Runtime data and models are excluded
from source control; retain this workspace or regenerate them as described below.

## What works without administrator access

- Python FastAPI backend with durable SQLite job, decision and experiment history.
- Dark browser dashboard with selectable peers, scenarios, models and loss rates.
- PCAP and PCAPNG import, flow extraction and flow CSV export.
- Logistic Regression, Random Forest, XGBoost, Extra Trees, MLP and TabM training.
- Separate train, validation and held-out test partitions with group isolation.
- Per-class results, confusion matrices, dataset fingerprints and artifact metadata.
- CSV inference using an exact feature-name contract, with predictions export.
- TreeSHAP explanations where supported; measured median-replacement sensitivity
  otherwise. The UI names the method and does not claim a causal explanation.
- Random and burst capture loss at 0%, 1%, 5% and 10%, repeated corruption seeds,
  observed/entirely missing flow counts, and conditional versus end-to-end recall.
- Reusable packet and early-prefix models from a labelled PCAP manifest.
- Functional packet fixtures with explicit synthetic provenance.

## Live lab status and research limits

All four KVM guests and authenticated sensors are running. Benign VM traffic,
NetEm loss and connection-specific nftables enforcement passed real acceptance
tests. The repository includes reproducible provisioning, 24 labelled real VM
capture sessions, completed and prefix models, and 576 held-out capture-loss
comparisons. See [measured results](docs/RESULTS.md) for actual scores and limits.

The default live model is trained on controlled real VM captures. The synthetic
fixture models remain explicitly labelled and separate. Corrected CICIDS models now classify completed VM captures through the pinned
authors’ 80-feature exporter. The held-out transfer test exposes substantial
domain shift; matching features does not guarantee recognition. CICIDS models
observe completed captures and do not offer early blocking. The extended lab
also includes three-source DDoS and real HTTP credential verification; it does
not reproduce SSH/FTP exploits. See the extended study below.

Host tooling is already installed here. On a fresh machine, follow
[lab/README.md](lab/README.md). No host administrator password is stored or
requested by the application.

## Dashboard workflow

1. **Network lab:** select a source peer and destination. Choose a scenario,
   packet-compatible model, loss percentage, pattern and seed. Click Analyze.
2. **Decision stream:** inspect predictions, thresholds, feature contributions,
   measured values and whether an action was actually enforced. Offline analysis
   displays “would block”; it never claims that packets were blocked.
3. **Models & training:** select a dataset, inspect per-class test results or
   retrain the six algorithms. Upload a matching CSV for batch inference.
4. **Loss experiments:** choose a scenario or imported homogeneous capture and
   model set. Run both loss patterns and all four rates across seeds 41–43.
   Read class recall and individual-run measured loss; export full JSON.
5. **Data & captures:** inspect provenance, split support and known limitations.
   Import a PCAP. Label it only if every flow has the same ground truth. Mixed
   captures can be classified but do not receive invented evaluation labels.

## Reproduce installation and training

Requires Python 3.12, [uv](https://docs.astral.sh/uv/) and a browser. The startup
script creates a project-local virtual environment when needed. PyTorch is
installed from its CPU package index; TabM requires that optional dependency.

```bash
# Prepare functional packet corpora and train all six models.
.venv/bin/flowlab setup

# Also download the corrected 328 MiB CICIDS2017 archive and train its models.
./start.sh --setup --no-browser

# Prepare a capped corrected CSV dataset and train independently.
.venv/bin/flowlab prepare-cic --per-class 4000
.venv/bin/flowlab train cicids2017

# Run a complete six-model packet-loss matrix from the CLI.
.venv/bin/flowlab experiment --scenario PortScan
```

The default corrected dataset sample caps each original label at 4,000 rows using
seeded priority sampling. Exact duplicate feature rows are removed globally.
This includes removal of conflicting duplicate feature rows, retaining the first
label; this is an explicit preprocessing decision, not a label repair guarantee.
Host-pair/two-minute groups are split approximately 60/20/20 with seed 42 before
fitting preprocessing. This is not a held-out attack-campaign study. Several rare
classes lack support in particular splits, and two classes are absent from the
training partition. The UI reports that limitation rather than moving examples
to make the scores look better.

The original six baseline architectures use fixed, modest hyperparameters.
The new `--study` mode compares three candidates per model, then calibrates on
a separate validation-group subset; this is equal candidate count, not equal CPU time. MLP and TabM use fixed iteration
budgets; a convergence warning is retained in metadata if applicable. Validation
sets choose an empirical attack-score threshold from benign scores; probabilities
are **not calibrated**, and threshold selection does not guarantee production FPR.

`requirements-lock.txt` records the installed versions on this Linux x86_64 host.
It includes a CPU-specific torch build; use the PyTorch CPU index when recreating
that environment. `pyproject.toml` describes portable dependency ranges. This is
not a promise that binary model artifacts work with other dependency versions.

## Train the deployment extractor on real packet data

Copy and edit [lab/manifest.example.json](lab/manifest.example.json). Each capture
must be homogeneous and have a label, traffic-group ID and explicit split. Paths
are resolved relative to the manifest. Provide multiple independent capture
sessions for each attack and benign background in all three partitions.

```bash
.venv/bin/flowlab prepare-pcaps /absolute/path/manifest.json --name lab_completed
.venv/bin/flowlab train lab_completed
.venv/bin/flowlab prepare-pcaps /absolute/path/manifest.json --name lab_prefix10 --prefix 10
.venv/bin/flowlab train lab_prefix10
```

A group cannot cross splits, and identical capture content cannot cross splits.
Do not put variants of the same capture into different splits. The manifest path
is used by the local CLI, not accepted as arbitrary filesystem access by the web
API. Prepared PCAP models automatically appear in the dashboard after refresh.

## Flow definition

`flowlab-payload-v1` uses bidirectional TCP/UDP tuples over unfragmented IPv4/IPv6,
with forward direction assigned to the first observed packet. It uses a 30-second
idle timeout and a 120-second active timeout. RST closes a flow; mutual FIN followed by the final ACK closes a graceful
TCP session. EOF emits remaining flows. IP fragments and unsupported protocols are
counted as skipped. Capture timestamps are sorted for offline processing.

Lengths are **transport payload bytes**. Time and IAT units are seconds. All
observed packets, including retransmissions, are counted. The 21-feature schema
includes direction counts/bytes, size statistics, IATs, rates and TCP flag counts.
Rates of zero-duration flows are defined as zero. No IPs, ports, timestamps or
scenario labels enter this model. These measurements are not asserted to match
CICFlowMeter columns. The benchmark retains the corrected exporter's separate
feature names and units.

Early models see the first 10 observed packets, or shorter closed/expired flows.
They emit one decision per flow segment. Final-flow models wait for completion
and cannot retroactively prevent already delivered traffic. Packets are grouped
again after loss, so changing direction/expiration is part of the measured effect.

## Evaluation interpretation

The loss matrix removes packets before re-extracting features. This measures
**capture loss**, not endpoint reactions. It is separate from the live VM NetEm
experiment. The burst process starts in its stationary state, has mean bad-state
length four packets, and drops every bad-state packet. Record achieved loss as
well as requested loss, especially for small captures. Seeds repeat corruption of
one trace; they are not independent attack campaigns or statistical confidence
intervals across networks. The matrix also measures prediction changes and
top-five explanation overlap for up to two same-prediction matched flows per
condition; this is a small-sample diagnostic.

End-to-end recall counts completely invisible original flows as missed. Conditional
classification metrics include only emitted observed flow records. When loss
splits an original flow, end-to-end recall counts the original once if at least
one observation detects it. Unlabelled or mixed captures have no recall score.
No experiment fabricates missing metrics or packet-delivery counts.

The original proposal also includes cross-dataset transfer, robust training on
real loss variants, calibration studies, broad attack coverage, larger explanation
stability studies, and high-throughput IPS benchmarking.
Those broader studies remain outside the current controlled-lab evidence.
The real VM corpus and enforcement path are already implemented and exercised.

## Tests and acceptance

```bash
.venv/bin/python -m pytest -q
node --check flowlab/static/app.js
bash -n start.sh lab/*.sh
```

Tests cover extraction, units, expiry, deterministic loss, invisible flows, group
isolation, provenance, model schema refusal, capture import, CSV inference,
cross-origin protections and repeat-run record identities. Browser QA uses
agent-browser; screenshots are local QA evidence. Live acceptance was also
executed separately; unit tests alone cannot verify a virtual switch or firewall.

## Project layout

| Path | Purpose |
| --- | --- |
| `flowlab/packets.py` | Decoder, flow meter, loss models |
| `flowlab/datasets.py` | Sampling, grouping, manifests, fingerprints |
| `flowlab/ml.py` | Six algorithms, metrics, persistence, explanations |
| `flowlab/experiments.py` | Scenario analysis and loss matrices |
| `flowlab/live.py` | Authenticated VM control and inference |
| `flowlab/app.py` | Local API and asynchronous jobs |
| `flowlab/static/` | Dashboard, dark theme and local fonts |
| `lab/` | KVM guests, agent and reviewed setup scripts |
| `data/`, `models/`, `results/` | Local generated artifacts and history |
| `docs/` | Literature review, design and measured results |

Dataset source: [Liu et al. corrected CICIDS2017](https://intrusion-detection.distrinet-research.be/CNS2022/).
CICIDS2017 attribution: [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html).
Retain the dataset's original terms and attribution when redistributing derived data.

## Extended research study

The completed study adds 40 longer and varied VM sessions, rotating sources and
receivers, three-source DDoS, and actual HTTP password verification. Ten new
held-out captures test CICIDS transfer. Eighty fresh NetEm sessions cover five
scenarios, both loss patterns, all four rates and two repeats. Each trace is
shared by six tuned prefix models, producing 480 model evaluations.

The dashboard’s **Loss experiments → Extended research study** shows live-study
and CICIDS transfer results, including failed detection. Network controls now
include duration and traffic rate. CICIDS completed-capture mode disables blocking.
Tuned models show their calibration and resource metadata separately from baselines.

```bash
# Linux local build of the authors’ exact July 2022 corrected exporter.
.venv/bin/python scripts/setup_cicflowmeter.py

# Recollect and train extended captures; completed sessions are checkpointed.
.venv/bin/python scripts/collect_extended.py

# Tune/calibrate, evaluate transfer, then run the 80-session live matrix.
.venv/bin/python scripts/research_study.py

# Independent-process CPU, memory, single-flow latency and batch throughput.
.venv/bin/python scripts/benchmark_models.py
.venv/bin/python scripts/summarize_research.py
```

Run collection and the live study sequentially; they control the same VMs.
Do not treat seed requests as applied on guests whose `tc` lacks seed support.
The study records actual loss and keeps classification separate from enforcement.
The current flow-only models have no count of coordinated source machines;
DoS versus DDoS confusion is part of the reported results.

Outputs: [final report](docs/FlowLab_Final_Report.docx),
[presentation](docs/FlowLab_Project_Presentation.pptx),
[compact measured summary](docs/STUDY_SUMMARY.json).
The original [literature review](docs/IDS_Literature_Review_and_Project_Plan.docx)
remains available. Full captures, model artifacts and run JSON stay local in
`data`, `models` and `results`; they are not committed to GitHub.


## Context and shared-prefix refinement

The latest implementation adds 1-second and 5-second causal destination context,
an independent binary gate and attack-type estimator, explicit uncertain results,
and binary-stage explanations. It is evaluated on 80 labelled VM sessions,
74 original CICIDS packet windows, 112 fresh live-loss sessions (1,344 paired
model comparisons), and 256 seeded sensor-loss conditions (3,072 comparisons).

CICIDS-only, lab-only and combined models now use the **same 35-feature packet
prefix extractor**. This closes the completed-CSV versus early-inference mismatch.
The original 80-feature completed-CICIDS benchmark remains available separately.

The recommended combined model is `mixed_prefix_context--tabm_hier`, selected
using validation binary macro F1 with a validation benign block-eligibility
constraint. This is a recommendation for the measured lab configuration.
CICIDS-only transfer still performs poorly on several lab cases; those failures
remain in the dashboard and report. Visible source counts cannot recover
identities concealed by NAT. Packet statistics do not establish malicious intent.

The new context models observe 35 measurements, including the original 21 flow
features. Raw addresses, absolute timestamps, scenario names, label provenance
and dataset identities are excluded from model inputs. Prefixes are matched to
corrected labels by tuple and start time; ambiguous and truncated records are
excluded. Successful and attempted DoS/HTTP-guessing records share family labels.
Public password-guessing support is small: 18 training, 5 validation and 11 test
prefixes. Source hashes and the exclusions are documented.

Run these commands from the repository root to reproduce. Downloading the three
PCAP days needs about 30 GB, plus temporary range chunks. The mirror's published
SHA256 values are checked; this verifies mirror content, not official ownership.

```bash
.venv/bin/python -m scripts.download_cic_pcaps
.venv/bin/python -m scripts.prepare_cic_prefix
.venv/bin/python -m scripts.collect_refined
.venv/bin/python -m scripts.augment_refined
.venv/bin/python -m scripts.evaluate_refinement
.venv/bin/python -m scripts.evaluate_refined_capture_loss
.venv/bin/python -m scripts.train_shared_prefix
.venv/bin/python scripts/benchmark_models.py --datasets refined_context cic_prefix_context mixed_prefix_context --suffix _hier --output refinement-performance.json
.venv/bin/python -m scripts.finalize_refinement_measurements
```

The live evaluation and final acceptance control the same VM lab and must run
sequentially. CPU-only dataset preparation, capture-loss analysis and training can
run independently. Checkpoints refuse to mix results with different model hashes.
The preparation/training scripts reuse completed matching capture groups.

The updated [report](docs/FlowLab_Final_Report.docx),
[presentation](docs/FlowLab_Project_Presentation.pptx) and
[refinement summary](docs/REFINEMENT_SUMMARY.json) contain the measured results.
The original `STUDY_SUMMARY.json` preserves the earlier baseline study.
