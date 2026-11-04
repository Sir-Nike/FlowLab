# Frozen model set comparison on new challenge traffic

5 November 2026

Same 20 saved mixed-traffic captures; no new traffic or fitting. Refined-flow uses 21 features on ten-packet prefixes; CICIDS uses pinned corrected 80-feature completed flows. Different observation budgets and emitted record counts prevent strict prefix-to-completed equivalence.

Native argmax predictions mapped to family. DoS variants/attempts -> DoS; Web Attack - Brute Force/attempts -> BruteForce; Portscan -> PortScan; remaining unsupported attacks -> OTHER_ATTACK. No renormalizing away unsupported predictions.

All models and thresholds were frozen before this evaluation. Model binary and metadata hashes remained unchanged. No model was retrained or selected using these results. No packets were sent and the VMs remained shut down. Ground truth uses retained sender socket logs, with unknown/ambiguous flows excluded and counted. Scores are conditional on emitted labelled flows, not detection of invisible original events. Each class has support in the pooled test; unsupported predicted attack families remain errors. Blocking eligibility is counterfactual and is not actual enforcement.

## Results

| Dataset | Algorithm | Variant | Records | Family macro F1 | Attack recall | Benign binary FPR | Benign block eligibility |
|---|---|---|---:|---:|---:|---:|---:|
| refined_flow | logistic | baseline | 4177 | 0.3111 | 98.81% | 95.35% | 49.80% |
| refined_flow | logistic | tuned | 4177 | 0.3111 | 98.81% | 95.35% | 49.80% |
| refined_flow | rf | baseline | 4177 | 0.2337 | 86.45% | 46.75% | 1.61% |
| refined_flow | rf | tuned | 4177 | 0.2337 | 87.73% | 50.83% | 1.61% |
| refined_flow | xgboost | baseline | 4177 | 0.1770 | 88.10% | 51.58% | 38.60% |
| refined_flow | xgboost | tuned | 4177 | 0.1770 | 88.14% | 51.69% | 38.60% |
| refined_flow | extra | baseline | 4177 | 0.3392 | 30.17% | 53.30% | 1.61% |
| refined_flow | extra | tuned | 4177 | 0.3392 | 29.31% | 43.25% | 1.61% |
| refined_flow | mlp | baseline | 4177 | 0.3228 | 22.41% | 33.72% | 15.85% |
| refined_flow | mlp | tuned | 4177 | 0.3160 | 16.42% | 18.27% | 14.24% |
| refined_flow | tabm | baseline | 4177 | 0.4779 | 88.05% | 48.08% | 13.73% |
| refined_flow | tabm | tuned | 4177 | 0.3487 | 67.32% | 36.47% | 1.84% |
| cicids2017 | logistic | baseline | 4134 | 0.1895 | 40.59% | 63.91% | 52.31% |
| cicids2017 | logistic | tuned | 4134 | 0.1895 | 40.91% | 63.91% | 49.38% |
| cicids2017 | rf | baseline | 4134 | 0.3249 | 16.98% | 59.64% | 0.00% |
| cicids2017 | rf | tuned | 4134 | 0.3246 | 28.14% | 98.13% | 0.00% |
| cicids2017 | xgboost | baseline | 4134 | 0.3249 | 15.86% | 0.59% | 0.00% |
| cicids2017 | xgboost | tuned | 4134 | 0.3249 | 15.86% | 3.87% | 0.00% |
| cicids2017 | extra | baseline | 4134 | 0.3241 | 27.65% | 62.04% | 0.00% |
| cicids2017 | extra | tuned | 4134 | 0.3249 | 27.81% | 69.36% | 0.00% |
| cicids2017 | mlp | baseline | 4134 | 0.2994 | 21.88% | 37.38% | 5.86% |
| cicids2017 | mlp | tuned | 4134 | 0.2994 | 26.82% | 57.76% | 2.81% |
| cicids2017 | tabm | baseline | 4134 | 0.3233 | 19.49% | 17.87% | 0.00% |
| cicids2017 | tabm | tuned | 4134 | 0.3233 | 27.61% | 49.97% | 0.00% |

## Interpretation

Compare each model with its earlier score only with the changed test population clearly stated. Prefix versus completed-flow results have different information and records; these are shared-capture comparisons, not an assertion of identical observation budgets. Original CICIDS labels require a declared family mapping for these workloads. That mapping is evaluation-only and does not retrain or extend model classes.

The challenge uses independent generation code and services on the same four guests, two endpoint rotations, 0%/10% requested random link loss and concurrent benign workloads. It does not validate an unrelated physical network or prove actual resource exhaustion. Labels denote controlled workload intent. The separate context TabM challenge is reported in INDEPENDENT_CHALLENGE.md. Do not pick the highest scoring model here and claim validation on an untouched test; all 24 results are exploratory comparisons on a now-inspected challenge set.

## Reproduce

Run `.venv/bin/python -m scripts.evaluate_challenge_model_sets` with existing local model artifacts, saved captures and the pinned corrected CICFlowMeter installed. Raw mapped/native predictions remain in results/challenge-model-sets; the compact JSON summary preserves model/capture hashes, class reports, confusion matrices, loss strata and extraction counts.
