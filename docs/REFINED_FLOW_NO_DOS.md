# Refined flow four class ablation without DoS

All DoS-labelled records were removed from training, validation and test, including UDP DoS and HTTPDoS. Original artifacts and splits were preserved. Six models were fitted from untrained initialization with the existing three-candidate validation search and separate validation-group temperature calibration. No parameters were selected using test scores.

| Model | Test accuracy | Macro F1 | Benign classification FPR |
|---|---:|---:|---:|
| Logistic Regression | 99.99% | 0.9999 | 0.00% |
| Random Forest | 100.00% | 1.0000 | 0.00% |
| XGBoost | 100.00% | 1.0000 | 0.00% |
| Extra Trees | 100.00% | 1.0000 | 0.00% |
| MLP | 100.00% | 1.0000 | 0.00% |
| TabM | 100.00% | 1.0000 | 0.00% |

Retained 36058 records; removed 5366. Classes: BENIGN, BruteForce, DDoS, PortScan.

These are four-class held-out original-lab results. They do not establish robustness to the earlier independent-generator challenge or DoS detection. No DoS records were relabelled benign. DoS remains available in original datasets and archived results; these new models cannot output DoS. Duplicate feature rows and generator regularities were not repaired in this class-removal ablation.

Models appear under refined_flow_no_dos in the dashboard after refresh. Reproduce with `.venv/bin/python -m scripts.train_refined_without_dos`. Dataset CSVs and binary artifacts remain local; the compact metadata and script are version-controlled.
