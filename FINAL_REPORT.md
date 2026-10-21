# NoC Sentinel — Academic Demonstration & Engineering Handover Report

**Project**: NoC Sentinel — An Evidence-Based Cybersecurity Simulation & Mitigation Platform for Network-on-Chip  
**Simulation Engine**: Noxim (SystemC / C++)  
**Environment**: Ubuntu 22.04 LTS (WSL2)  
**Verification Date**: October 2026  
**Status**: MVP Complete — Freeze Reached — Evidence Verified  

---

## 1. Executive Summary

NoC Sentinel addresses hardware Trojan vulnerabilities and compromised routers in Network-on-Chip (NoC) architectures. Rather than relying on synthetic mocks or ungrounded machine learning metrics, this project implements and proves cycle-accurate hardware Trojan behavior, loop-free avoidance routing, configurable destination quarantine/remapping, and cycle-by-cycle packet telemetry in SystemC.

The demonstration is backed by **63 execution runs** (60 completed cycle-accurate simulations and 3 negative configuration aborts), full traffic-injection equivalence, zero routing loops, zero invalid hops, and an interactive Streamlit dashboard.

---

## 2. System Architecture

```
                          +------------------------------------------+
                          |   Noxim SystemC Discrete-Event Engine     |
                          +------------------------------------------+
                                               |
                     +-------------------------+-------------------------+
                     |                                                   |
        [Traffic Generation PE]                               [Routing Engine Router.cpp]
                     |                                                   |
        • Deterministic Injection RNG                        • Normal: XY Dimension-Order Routing
        • Decoupled Arbitration RNG                          • Sentinel: BFS Shortest Path on G \ {N}
        • Packet Timestamp & ID Tracing                      • Loop-Free & Non-Diagonal Traversal
                     |                                                   |
                     +-------------------------+-------------------------+
                                               |
                                   [Telemetry Logging Engine]
                                               |
                           • Cycle-by-cycle hop logging (_hops.csv)
                           • End-to-end packet audit (_packets.csv)
                           • Aggregate energy & throughput (_stats.csv)
                                               |
                                   [Sentinel Analytics Plane]
                                               |
                         +---------------------+---------------------+
                         |                                           |
             [Verification Audit Engine]                 [Streamlit Frontend Dashboard]
                (sentinel/analyze.py)                               (app.py)
           • Validates 0 Loops & Hops                  • Dynamic Mesh Topology (Nodes 0..15)
           • Validates 0 Compromised Hops              • Attack vs. Mitigated Delivery Curves
           • Validates 100% Traffic Matching           • Packet-Level Hop Inspector
           • Evaluates RF Domain Shift                 • Guarded Untested-Node Indicators
```

---

## 3. Threat Model & Evaluated Attack Scenarios

Five distinct hardware Trojan / router compromise prototypes were implemented in `src/Router.cpp` and evaluated across corner, interior, and edge topology positions:

1. **`BLACKHOLE`**: The compromised router silently drops all transit packets passing through its input buffers, causing catastrophic packet loss for routes intersecting the node.
2. **`SELECTIVE_FORWARDING`**: Packets are dropped based on an alternating/modulo pattern, mimicking stealthy trojans designed to evade simple burst-loss thresholds.
3. **`GRAYHOLE`**: Probabilistic packet discard (50% drop rate), introducing stochastic loss and severe tail-latency degradation.
4. **`ROUTING_MANIPULATION`**: Misroutes transit packets away from their optimal XY output direction, forcing path dilation, packet deflection, and artificial congestion.
5. **`DESTINATION_TAMPERING`**: Modifies the destination field of transit packets (redirecting to $N \oplus 1$), injecting misdelivered payloads into unintended cores.

---

## 4. Mitigation Engine: Configurable Single-Node Isolation

### Dynamic Node Configuration
Compromised node selection is fully decoupled via environment variables:
- `NOXIM_MAL_NODE` ($0..15$): Any router on the $4\times 4$ mesh can be isolated.
- `NOXIM_ATTACK_MODE`: Threat scenario selection (`NONE`, `BLACKHOLE`, etc.).
- `NOXIM_ENABLE_MITIGATION`: Activates Sentinel avoidance routing.

### Shortest-Path Avoidance Routing on $G \setminus \{N\}$
Instead of hardcoded neighbor offsets, Sentinel computes a cycle-free Breadth-First Search (BFS) shortest path over the punctured topology graph $G \setminus \{N\}$:
- **Loop-Freedom Guarantee**: Distances strictly decrease towards the destination on $G \setminus \{N\}$.
- **Physical Feasibility**: Restricts transitions strictly to cardinal mesh neighbors (North, South, East, West). No diagonal hops.
- **Zero Transit Compromise**: Guaranteed 0 intermediate visits to router $N$.

### Destination & Source Policies
When an endpoint itself is compromised, bypass routing alone is insufficient:
- **`QUARANTINE`** (Default): Packets addressed to the compromised node are safely discarded at source/adjacent routers to protect the system.
- **`REMAP`**: Packets addressed to the compromised router are dynamically redirected to an authenticated backup core (`NOXIM_BACKUP_NODE`).
- **`DROP` / `ALLOW`**: Selectable ingress/egress filtering for research evaluation.

---

## 5. Comprehensive Verification Results

### 5.1 Reconciliation of Run Counts

```
Total Log Runs in sentinel/runs/: 63
├── Negative Configuration Aborts :  3 (Input validation verified)
│     ├── neg_invalid_node        : Node 99 cleanly rejected
│     ├── neg_remap_nobackup      : REMAP without backup cleanly rejected
│     └── neg_backup_is_mal       : Backup == Malicious node cleanly rejected
└── Completed Simulation Runs     : 60 (Full packet, hop, and stat traces)
      ├── Baseline Clean Run      :  1 (Reference run, 0 attacks)
      ├── Attack Matrix           : 25 (5 nodes × 5 attack types)
      ├── Mitigated Matrix        : 25 (5 nodes × 5 attack types)
      ├── Uncompromised Bypass    :  5 (5 nodes, mitigation active, attack=NONE)
      └── Destination Policy Runs :  4 (deliver, quarantine, remap to Node 2, allow)
```

- **Traffic Matching**: 59 completed non-baseline runs were checked pairwise against the reference baseline; all **59 runs match the 591 injected packets identically**.
- **Path Validity**: **0** invalid hops, **0** routing loops across all 60 completed runs.
- **Mitigation Invariant**: **0** packets traversed compromised node $N$ as an intermediate router across all 25 mitigated runs.
- **Settled Delivery Recovery**: **100.0%** recovery of uncompromised traffic under Sentinel mitigation.
- **Remapping Delivery Proof**: **53 out of 53 packets** addressed to compromised Node 6 were successfully delivered to backup Node 2 under `NOXIM_DST_POLICY=REMAP`.

---

## 6. Machine Learning Analysis: 100% Score Context & Domain Shift

### 6.1 The 100% Held-Out Score in Context
The original binary Random Forest model (`network_attack_detector.pkl`) was trained on legacy $8\times 8$, 10,000-cycle simulation logs:
- **Aggregated Dataset**: 30 valid summary rows (19 normal, 11 attack).
- **80/20 Train/Test Split**: 24 training samples, **exactly 6 test samples** (4 normal, 2 attack).
- **Confusion Matrix**:
  $$\begin{pmatrix} 4 & 0 \\ 0 & 2 \end{pmatrix}$$
- **Interpretation**: 100% accuracy on a **six-sample** test set in an identical simulation parameter space demonstrates partitionability within that specific configuration, **not** universal generalization.

### 6.2 Domain Shift on the $4\times 4$ Mesh
When evaluated against the current $4\times 4$, 5,000-cycle runs:
- The classifier splits heavily on scale-dependent volume features such as `total_received_packets` (training threshold $> 1,487$).
- Because $4\times 4$ runs naturally produce fewer packets ($\sim 591$ packets), the model classifies **all 60 evaluated runs as ATTACK** (including the baseline and uncompromised bypass runs).
- **True Negative Rate**: **0.0%** on the $4\times 4$ dataset.
- **Demonstration Decision**: The Random Forest is maintained and explicitly presented in the documentation and dashboard as **EXPERIMENTAL (Domain Shift Detected)**.

---

## 7. Streamlit Dashboard Smoke Test & UI Verification

The Streamlit dashboard (`app.py`) is live on `http://localhost:8501`. A dedicated browser verification audit confirmed:
1. **Node 6 Selection**: Displays topology, neighbors, and delivery recovery (from 36.9% up to 100%).
2. **Node 10 Selection**: Dynamically updates the topology map and delivery metrics to Node 10 evidence.
3. **Untested Node Guardrail (e.g., Node 7)**: Clearly renders `[NOT TESTED IN SAVED MATRIX - Showing Baseline Reference Topology Only]` with 0 packets and no fabricated numbers.
4. **Packet Inspector (Tab 03)**: Traces individual packets (e.g., Packet ID 37 bypassing Node 10 via `11 > 15 > 14 > 13 > 9 > 8`).
5. **ML Classifier (Tab 05)**: Prominently displays the domain shift warning banner, empirical confusion matrix, and feature table.

---

## 8. Exact Reproduction Commands

```bash
# 1. Environment Activation
cd /home/soniya/noxim
source .venv/bin/activate

# 2. Build Simulator
./build.sh -B -j2

# 3. Execute Experiment Matrix (63 runs)
./sentinel/run_experiments.sh

# 4. Execute Verification Audit
python3 sentinel/analyze.py

# 5. Launch Intelligence Dashboard
streamlit run app.py --server.port 8501 --server.headless true
```

---

## 9. Handover File Inventory

### Preserved Backups & Safety
- **Full Pristine Backup**: Preserved intact at `/home/soniya/noxim_backup_handoff` (770 MB).
- **Git State**: Cleaned via `.gitignore` to prevent committing `.venv`, caches, or large tarballs.

### Key Handover Files
- `src/Router.cpp`, `src/ProcessingElement.cpp`, `src/DataStructs.h`, `src/Main.cpp`: Patched SystemC core.
- `src/SecurityTrace.h`, `src/SecurityTrace.cpp`: Sentinel logging and BFS avoidance engine.
- `sentinel/run_experiments.sh`: Matrix runner script.
- `sentinel/analyze.py`: Independent verification audit engine.
- `app.py`: Streamlit intelligence dashboard.
- `sentinel/results/`: Verified CSV comparison tables (`attack_comparison.csv`, `run_summary.csv`).
- `sentinel/runs/`: Raw logs, per-packet traces (`*_packets.csv`), and hop telemetry (`*_hops.csv`).
- `README.md`: Project guide, prerequisites, and build documentation.
- `FINAL_REPORT.md`: This document.

---

## 10. Scope & Verified Invariants

| Claim | Status | Verification Mechanism |
|:---|:---:|:---|
| **Loop-Free Avoidance Routing** | **VERIFIED** | Formal audit of all hops across all 60 completed runs |
| **Zero Transit Compromised Hops** | **VERIFIED** | 0 packets traversed node $N$ as intermediate router |
| **Deterministic Traffic Equivalence** | **VERIFIED** | Injected packets match baseline exactly (591/591) |
| **100% Settled Delivery Recovery** | **VERIFIED** | Settled delivery of uncompromised traffic restored to 100% |
| **Destination Remapping Proof** | **VERIFIED** | 53 remapped packets delivered to backup Node 2 |
| **Zero Fabricated Metrics** | **VERIFIED** | Dashboard reads raw CSVs directly; guards untested nodes |
| **Machine Learning Detector** | **EXPERIMENTAL** | Transparently disclosed domain shift ($8\times 8 \to 4\times 4$) |
EOF
