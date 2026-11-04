# Frozen model challenge protocol

This is a new socket/HTTP generator, not the training agent's scenario generator.
The driver uses existing authenticated capture agents only for observation and
NetEm. New service ports are 8082 (HTTP auth), 8083 (UDP echo), 8084 (UDP sink).
Addresses are restricted to the four isolated project guests. Clients are capped
at 12 seconds/1,500 connections; configured runs last four seconds. Temporary
servers stop after 900 seconds as a fallback and are terminated in driver cleanup.
No host sudo or public targets are involved.

Two endpoint rotations × five cases × two link-loss settings = 20 captures.
Cases: legitimate no-reply UDP with ordinary login traffic; replying single-source
load with benign login traffic; two replying load sources with benign HTTP;
password guessing with successful and failed legitimate login attempts; random
port probes with legitimate no-reply UDP. Inter-request delays are exponential,
UDP lengths and packets per socket vary, and HTTP service bodies have equal length
for success and rejection. The traffic rates and generator differ from training.
Attack labels are controlled attack-intent workload labels, not evidence of actual
resource exhaustion. HTTP guessing is newly generated but still plain HTTP; this
is not validation on real SSH/FTP exploits.

For each run reset capture, execute labelled roles concurrently, and retain the
sender's local socket ports. Label each bidirectional flow by its originating
sender IP/port rather than labelling the whole capture. Unknown/ambiguous flows
are excluded and counted. They still contribute to observed destination context.
Endpoint-generated source logs are ground truth metadata and never enter the model.
Scores condition on emitted labelled flows; they are not invisible-flow recall.
All counts are correlated within runs and should not imply per-flow independence.

Freeze joblib and metadata hashes before collection; verify both after cleanup.
No retraining, threshold search or model selection is allowed. Persist captures,
source configuration/logs, hashes, raw predictions and counters locally under
results/independent. Do not run alongside another job controlling these VMs.
Run from project root: `.venv/bin/python -m scripts.independent_study`.
