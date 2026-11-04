# FlowLab interface

The topology is the main workspace. A selected peer opens a scenario drawer;
the decision log stays visible below it. Model and dataset provenance are always
visible, and offline peers never look like connected VMs.

User requested a dark hacker-style theme. Palette: black #080d10,
surface #0e161b, raised #142027, mint #62efad, cyan #72cde1,
amber #edc26d, red #ff8495. Space Grotesk headings, IBM Plex Mono
for controls and evidence, system sans for explanatory copy. Fonts are local.
Green denotes selected or allowed states; red also carries text labels.
Use subtle grid geometry and a terminal decision log, no fake telemetry,
glitch effects, perpetual scanlines or illegible neon body text.

The skill search recommended a dashboard hierarchy but mixed in marketing
patterns. This app uses an instrument workspace, without a marketing hero,
decorative statistics or simulated health numbers. The network diagram is the
one expressive element. All states also carry text; keyboard focus is visible.


## Corrected CICIDS capture bridge

`flowlab/cic.py` invokes the authors’ corrected CICFlowMeter pinned at
`55f60addd21ada7635a79ee3c596a389756552a6`. The build uses a local Java 8 JDK
and a project-local native-library alias, without modifying host packages.
`setup_cicflowmeter.py` reconstructs it. All 80 required feature names must be
present; the bridge does not rename or invent measurements. The pinned source
retains `Total TCP Flow Time`, which later exporter versions changed.

The live controller can capture a new VM session and classify its completed
export using the original CICIDS model. This mode refuses enforcement before
starting traffic. Prefix prevention continues to use models trained on the
FlowLab prefix extractor. Technical schema compatibility and detection transfer
are evaluated separately; the transfer JSON retains failed detections.

## Extended scenarios and evaluation

For DDoS, all three non-target peers generate bounded UDP load toward the chosen
receiver. Each source gets its own NetEm configuration, capture and counters;
cleanup stops and resets every source. Destination capture includes all three.
This generates distributed traffic, while the individual-flow feature vector
still has no direct source-count context. Attack-type confusion is reported.

The HTTP authentication service validates credentials with a disposable PBKDF2
verifier and separately counts accepted and rejected logins. The guessing client
uses only a fixed fake account and bounded wrong-password list against a lab IP.
Benign traffic varies response sizes and pacing. No scenario permits arbitrary
targets, commands, packet spoofing or external addressing.

The extended corpus uses forty independent eight-to-ten-second sessions, with
explicit train/validation/test groups. Three candidates per algorithm are chosen
on one group-separated validation subset. Temperature scaling uses the other
subset. Unsupported calibration labels are excluded; test labels absent from
training remain in classification reports. Calibration is evaluated on the
held-out test set and is not asserted to transfer to the lab or other networks.

The 80-session live matrix performs two repetitions of five scenarios, four
loss rates and two patterns. Each fresh capture is shared by all six tuned
classifiers in shadow mode. This separates differences between classifiers from
differences between randomly generated traffic. Conditional emitted-flow recall
is named explicitly; capture-loss experiments separately retain end-to-end
coverage measurements. Independent-process benchmarks distinguish warm single
prediction latency from batch throughput and whole-process peak memory.


## Causal contextual prefix contract

`flowlab-context-v2` adds fourteen measurements to the original 21 inputs.
`flowlab/context.py` maintains one- and five-second destination windows, with
source and connection cardinalities, rates, source share, SYN fraction and the
target outbound/inbound packet ratio. Windows are (decision time - width,
decision time]. Expired flows are processed before the next packet is inserted.
Counters provide the same measurements in batch extraction and online inference;
future packets cannot mutate an emitted prefix. Capacity overruns fail explicitly.

Original CICIDS PCAPNG blocks are sliced without changing Ethernet packet bytes.
Prefixes are matched uniquely to corrected flow tuples and start times within
five milliseconds. Left/right truncations and cross-split original identities
are excluded. Family mapping includes attempted and successful DoS and HTTP
password guessing; malicious attempt does not imply successful compromise.
Raw label provenance is retained outside predictive inputs. The same prefix
contract is used for CICIDS-only, lab-only and domain-balanced combined models.

Hierarchical models fit a binary gate and an attack-only type classifier using
the flat classifier's selected settings. Each stage receives temperature scaling
on a separate validation subset. Uncertainty and block eligibility are separate:
weak binary scores do not block; strong binary attacks may block even when type
is unaccepted. Explanations separately measure gate and type sensitivity.

Live inference batches each poll's emitted prefixes for estimator efficiency;
each record retains the context that existed at its own emission time. Final
acceptance tests ordinary and burst benign traffic before distributed load.
No scenario labels, source-count selections or capture labels enter inference.
