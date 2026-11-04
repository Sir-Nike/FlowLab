# FlowLab measured results

4 November 2026

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
