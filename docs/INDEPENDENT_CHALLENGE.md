# Frozen model challenge study

5 November 2026

## Result

The frozen recommended model failed to generalize reliably to the new controlled generators and mixed traffic. Across 20 runs and 4177 labelled observed flow records, argmax macro F1 was 0.1036, selective-policy macro F1 was 0.0913, coverage was 91.17%, and benign blocking eligibility was 11.83%. Enforcement was disabled; eligibility is not actual blocking.

## Protocol

New generator/service and mixed roles on existing VMs; NOT an independent physical network or held-out public campaign. Attack labels describe bounded attack-intent workloads, not demonstrated service impairment. No model selection or threshold tuning.

Two endpoint rotations, five cases and 0%/10% random link loss yielded twenty captures. Independent socket clients and a new HTTP/UDP service replaced the training generator. Benign UDP without replies, responding attack-load UDP, legitimate successful/failed logins, password guessing and random port probes ran with simultaneous background traffic. Configured request rates differed from collection settings. UDP sizes and packet counts varied. Ground truth was assigned using sender socket logs, not the capture scenario label. All observed packets contributed to context; unknown or ambiguous flows were excluded and counted.

The joblib and metadata SHA256 hashes were frozen before collection and checked unchanged afterward. No fitting, threshold adjustment or model choice used the challenge results. Existing prepared training datasets were not modified. Classifier performance was evaluated offline on actual destination captures using the same extractor and saved model. This does not test online decision or enforcement latency.

## Cases

| Case | Observed labelled flows | Accuracy | Binary attack recall | Benign block eligibility |
|---|---:|---:|---:|---:|
| distributed_with_background | 1355 | 16.24% | 0.00% | 0.00% |
| legitimate_no_reply | 652 | 67.33% | N/A | 5.37% |
| login_mixture | 543 | 43.65% | 0.98% | 0.00% |
| replying_single_load | 811 | 23.30% | 0.00% | 0.00% |
| scan_mixture | 816 | 3.68% | 98.44% | 39.68% |

## Interpretation and limits

These results contradict any claim that the earlier near-perfect score establishes robustness to changed traffic generation or mixtures. They support the audit concern about generator and context shortcuts. They do not identify a single causal feature: service, traffic mix and generation all changed. The model remains a demonstrator for its original scenarios; it is not validated as a robust detector. New failures should remain an untouched challenge set for this frozen model. If used to improve a later model, a further independent test is required.

The workload labels describe intended benign/attack roles. Low bounded load is not evidence of actual denial of service, and traffic statistics alone cannot infer intent. Similar legitimate and malicious login traffic may be intrinsically difficult to distinguish from a ten-packet prefix. Source workloads share the same four guests and private network. This is not an independent network, public dataset or realistic Internet-scale validation. Zero missed capture flags does not prove zero kernel capture loss. Scores are conditional on emitted labelled flows, not end-to-end recall of completely invisible flows. Related flows are correlated; two endpoint rotations do not yield broad confidence intervals. Requested 10% loss is not assumed to equal achieved loss; source qdisc counters are retained in raw study records.

## Evidence and reproduction

Captured packets: 39701; excluded unlabelled/ambiguous flows: 0; capture-limited flags: 0.

Run `.venv/bin/python -m scripts.independent_study`, then `.venv/bin/python -m scripts.summarize_independent`. The live driver needs all four provisioned VMs and must run without another experiment controlling them. It resets temporary NetEm settings and stops its temporary servers in cleanup. Raw source logs, captures, hashes, predictions and qdisc counters remain in `results/independent`; the compact public summary is `docs/INDEPENDENT_CHALLENGE_SUMMARY.json`.

Packet-level service verification found 10,959 UDP echo responses, 564 HTTP 200 responses and 599 HTTP 401 responses across the captures. The responding service was therefore exercised, rather than merely attempted.
