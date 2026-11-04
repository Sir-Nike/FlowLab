# FlowLab measured results

4 November 2026

The first sections preserve the initial baseline study. The extended study below
supersedes its earlier feature-bridge and scenario limitations.

The software, four real KVM guests, packet capture, inference and connection enforcement were exercised locally. These are initial controlled-lab measurements, not a claim of production security or a full reproduction of every paper in the literature review.

## Corrected CICIDS2017 benchmark

The source archive contained 2,099,976 rows. Seeded sampling capped each original label at 4,000 rows, then removed duplicate feature vectors. The prepared dataset contains 39,671 rows and 80 input features. Group separation uses host pairs and two-minute time blocks before preprocessing.

| Model | Test macro F1 | Test accuracy | Benign false positive rate |
| --- | ---: | ---: | ---: |
| Extra Trees | 0.7916 | 0.9191 | 0.0026 |
| Logistic Regression | 0.7209 | 0.9017 | 0.0578 |
| MLP | 0.7609 | 0.8970 | 0.0218 |
| Random Forest | 0.8000 | 0.9184 | 0.0051 |
| TabM | 0.7439 | 0.9108 | 0.1104 |
| XGBoost | 0.7279 | 0.9153 | 0.0090 |

Macro F1 uses only classes with ground-truth support in the evaluated partition, identically across models. Per-class reports and the confusion matrix retain all corpus labels, including zero-support classes. Attempted-attack labels are retained as supplied. Some rare classes have no training examples; inspect the dashboard before interpreting aggregate scores. Hyperparameters are fixed baselines, not an equal-budget optimization study. Probabilities are not calibrated.

The corrected CIC exporter has a separate schema. These models classify compatible CSVs; the application refuses to feed its different packet features into them. Transfer from the CIC benchmark directly to live VM traffic has not been established.

## Real VM packet corpus

Collected six independent three-second sessions for each of four controlled scenarios: benign web plus occasional UDP traffic, bounded UDP DoS, port probes, and repeated requests to a failing toy authentication endpoint. Four sessions train, one validates and one tests each scenario. Source peers vary across sessions; target Delta remains fixed. All 24 labelled destination captures and their hashes are retained.

Both completed-flow and ten-packet-prefix models were trained from initialization on the same versioned extraction code used for inference. These tests are deliberately small and regular; high scores demonstrate this lab configuration, not broad attack recognition.

| Dataset | Model | Test macro F1 | Test rows |
| --- | --- | ---: | ---: |
| lab_completed | Extra Trees | 1.0000 | 384 |
| lab_completed | Logistic Regression | 1.0000 | 384 |
| lab_completed | MLP | 1.0000 | 384 |
| lab_completed | Random Forest | 1.0000 | 384 |
| lab_completed | TabM | 1.0000 | 384 |
| lab_completed | XGBoost | 0.9972 | 384 |
| lab_prefix10 | Extra Trees | 1.0000 | 384 |
| lab_prefix10 | Logistic Regression | 1.0000 | 384 |
| lab_prefix10 | MLP | 1.0000 | 384 |
| lab_prefix10 | Random Forest | 1.0000 | 384 |
| lab_prefix10 | TabM | 1.0000 | 384 |
| lab_prefix10 | XGBoost | 0.9972 | 384 |

## Packet loss comparisons

Ran 576 held-out capture-loss conditions: four labelled test captures × six models × two loss patterns × four requested rates × three corruption seeds. This changes the sensor view of fixed traffic. Actual live link loss is evaluated separately using NetEm.

| Scenario | Model | Random 10 percent class recall | Burst 10 percent class recall |
| --- | --- | ---: | ---: |
| BENIGN | logistic | 0.8533 | 0.9467 |
| BENIGN | rf | 0.8400 | 0.9333 |
| BENIGN | xgboost | 0.8400 | 0.9333 |
| BENIGN | extra | 0.8400 | 0.9333 |
| BENIGN | mlp | 0.8533 | 0.9733 |
| BENIGN | tabm | 0.8933 | 0.9467 |
| DoS | logistic | 1.0000 | 1.0000 |
| DoS | rf | 1.0000 | 1.0000 |
| DoS | xgboost | 1.0000 | 1.0000 |
| DoS | extra | 1.0000 | 1.0000 |
| DoS | mlp | 1.0000 | 1.0000 |
| DoS | tabm | 1.0000 | 1.0000 |
| PortScan | logistic | 0.8227 | 0.9056 |
| PortScan | rf | 0.8227 | 0.9056 |
| PortScan | xgboost | 0.8112 | 0.8940 |
| PortScan | extra | 0.8227 | 0.9056 |
| PortScan | mlp | 0.8227 | 0.9056 |
| PortScan | tabm | 0.8227 | 0.9056 |
| BruteForce | logistic | 0.9304 | 0.9267 |
| BruteForce | rf | 0.9744 | 0.9799 |
| BruteForce | xgboost | 0.9744 | 0.9780 |
| BruteForce | extra | 0.9744 | 0.9670 |
| BruteForce | mlp | 0.8901 | 0.8846 |
| BruteForce | tabm | 0.8938 | 0.8938 |

Class recall counts completely invisible original flows as missed. Conditional classifier scores are separate. Repeated seeds of one trace quantify corruption variability; they are not independent attack campaigns or confidence intervals across networks. Explanation overlap compares top-five features for at most two matched same-prediction flows per condition and is only a small-sample stability diagnostic.

## Live enforcement acceptance

| Scenario | Source link loss | Captured at destination | Flow decisions | Blocked connections | UDP delivered | Firewall packet drops |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| BENIGN | 0% burst | 304 | 26 | 0 | 8 | 0 |
| DoS | 10% burst | 266 | 6 | 6 | 179 | 87 |

These runs used lab_prefix10 Random Forest, trained on real controlled captures. Capture occurs before the destination firewall; raw observed counts therefore include packets later dropped by nftables. Application delivery counters and firewall counters are independently read from the guest. Blocking is connection-specific and confirmed by the agent. Rules and loss are reset after each run.

## Verification and limits

- Four QEMU/KVM guests are running and all four authenticated packet sensors responded.
- Python tests cover extraction, closure, loss, split isolation, fingerprints, inference, imports, API origin protection, repeat-run persistence, and agent authorization/command boundaries.
- Desktop and narrow-screen browser checks exercised the dashboard, source selection, decisions, model inspection and experiment results.
- The original mitlab and chess-builder definitions were removed at the user’s request; their dedicated chess disks were deleted and the mitlab files were already absent.

The current live generators do not reproduce every CICIDS2017 attack family. Single-source UDP load is DoS, not distributed DDoS. The authentication scenario is a toy service, not an SSH/FTP exploit. Production throughput, unseen attack detection, probability calibration, broad cross-network transfer, and literature-wide benchmark claims remain outside the validated results.

## Reproduce

```bash
./start.sh
.venv/bin/python -m pytest -q
.venv/bin/python scripts/validate_project.py
.venv/bin/python scripts/report_results.py
```

Validation sends bounded traffic only among the four isolated lab addresses. Keep guest setup and token files local. Raw results, captures, manifests and model metadata are stored under data, models and results.

## Final dashboard check

The dashboard form started an eight-second real DoS scenario with the trained
lab prefix model and 10 percent requested burst loss. The result window displayed
709 captured packets, 16 confirmed blocked connections,
392 datagrams delivered and 317 packet drops from the destination
firewall. Source qdisc counters recorded the achieved link loss separately.
The older guest tc version does not support an RNG seed; this limitation is
reported in the run rather than claiming seeded live reproducibility. Offline
capture-loss experiments are seeded.

The final Python regression suite passed 17 tests. Shell syntax and JavaScript
syntax checks passed. The dark dashboard was inspected at desktop and narrow
mobile widths.

## Extended study completed

Forty new labelled VM sessions support completed and prefix models, three-source
DDoS, real HTTP credential checking and more varied traffic. Three candidates per
algorithm are selected on one validation-group subset; temperature calibration
uses another. Baseline and tuned artifacts are retained separately.

The corrected authors’ exporter at commit `55f60addd21ada7635a79ee3c596a389756552a6`
produces all 80 CICIDS features. CICIDS models now classify completed VM captures;
this mode refuses early enforcement. Ten held-out captures test transfer.
Random Forest recognized lab scans but missed UDP load and HTTP guessing.
This failure is retained rather than relabelled as successful generalization.

| Model | Expanded prefix test macro F1 | Live class recall at 0% loss | Live class recall at 10% loss | Benign FPR at 10% loss |
| --- | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.7890 | 0.8075 | 0.7821 | 0.0547 |
| Random Forest | 0.7923 | 0.7874 | 0.8013 | 0.0512 |
| XGBoost | 0.7722 | 0.8179 | 0.8130 | 0.0512 |
| Extra Trees | 0.8106 | 0.8003 | 0.7966 | 0.0356 |
| MLP | 0.7680 | 0.7912 | 0.7648 | 0.1128 |
| TabM | 0.7671 | 0.7903 | 0.7523 | 0.1128 |

Live recall averages emitted-flow scenario recall across sessions. Eighty fresh
NetEm sessions cover five scenarios, two patterns, four rates and two repeats;
all six classifiers share each trace, yielding 480 comparisons. Completely
invisible original flows are measured separately in the capture-loss study.
DoS versus DDoS confusion remains because inputs describe individual flows.

Twelve isolated-process benchmarks measure warm single-flow latency, CPU,
batch throughput and process peak RSS. They exclude packet-decoding, polling
and firewall-installation costs; batch scores are not IPS line-rate throughput.

Final acceptance with tuned Extra Trees installed 30 connection rules during
three-source DDoS. Destination capture observed 1,291 packets: 686 datagrams
were delivered and 605 were counted as input firewall drops. The benign
acceptance installed zero rules. A separate fresh CICIDS run emitted 45 completed
flow decisions, with no enforcement. All four authenticated sensors remained online.

The 21-test regression suite, selected Ruff checks, shell syntax and JavaScript
syntax passed. The final report and nine-slide presentation contain full method,
calibration, failed transfer results and limits. See [the report](FlowLab_Final_Report.docx),
[presentation](FlowLab_Project_Presentation.pptx) and [summary](STUDY_SUMMARY.json).
Raw evidence remains in local `results/cic-transfer.json`, `live-study.json`,
`model-performance.json`, `extended-acceptance.json` and the capture manifests.


## Context refinement completed

The refinement adds 80 labelled VM captures, 74 selected original
CICIDS windows, 112 live-loss sessions and
1344 paired live predictions sets. The sensor-loss matrix
contains 256 conditions and 3072
paired model evaluations, counting invisible original flows as misses.

| Model | Flow-only held-out F1 | Context flat F1 | Context hierarchical F1 | CIC-only F1 on lab | Combined F1 on lab |
| --- | ---: | ---: | ---: | ---: | ---: |
| logistic | 0.7848 | 0.9988 | 0.9988 | 0.2981 | 0.8886 |
| rf | 0.8098 | 0.9985 | 0.9986 | 0.3024 | 0.9985 |
| xgboost | 0.8225 | 0.9986 | 0.9937 | 0.2776 | 0.9986 |
| extra | 0.8222 | 0.9988 | 0.9985 | 0.3009 | 0.9986 |
| mlp | 0.8235 | 0.9987 | 0.9992 | 0.3010 | 0.9989 |
| tabm | 0.8058 | 0.9989 | 0.9990 | 0.2735 | 0.9989 |

Scores pool the same held-out lab records, average only truth-supported classes,
and count uncertainty as error. Accepted accuracy must be read with coverage.
The high contextual scores are specific to this controlled corpus and may reflect
regular traffic mixtures; they do not prove generalization to arbitrary mixtures.

The selected combined TabM model was chosen on validation binary metrics.
Final acceptance blocked no connections for ordinary, single-source burst or
three-source burst benign traffic. Three-source DDoS installed 24 connection
rules, with 545 delivered UDP datagrams and 587 input-firewall drops among
1,132 destination observations. A CICIDS-only prefix model was exercised live
without enforcement; the schema matches even when detection transfer fails.

CIC-only training still transfers poorly to these lab sessions. Public capture
NAT hides distinct DDoS source identities. The revised report and 12-slide deck
retain this failure, rare-family support, calibration policy and uncertainty.
Full raw evidence stays local; `REFINEMENT_SUMMARY.json` supplies compact scores,
dataset hashes, model hashes and acceptance counters.
