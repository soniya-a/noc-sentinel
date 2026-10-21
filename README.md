# NoC Sentinel: Evidence-Based Cybersecurity & Mitigation Platform for Network-on-Chip

**NoC Sentinel** extends the cycle-accurate **Noxim** SystemC simulator with dynamic, configurable hardware Trojan / compromised router isolation, packet-level security telemetry, configurable endpoint policies, and an interactive Streamlit intelligence dashboard.

---

## 1. Architecture Overview

NoC Sentinel integrates directly into the Noxim routing pipeline:
- **Simulator Core**: SystemC / C++ discrete-event simulator (`src/Router.cpp`, `src/ProcessingElement.cpp`, `src/SecurityTrace.cpp`, `src/SecurityTrace.h`).
- **Dynamic Compromised Node Selection**: Environment variables `NOXIM_MAL_NODE` ($0..15$ on a $4\times 4$ mesh) and `NOXIM_ATTACK_MODE` decouple malicious behavior from any hardcoded node ID.
- **Avoidance Routing**: Loop-free Breadth-First Search (BFS) shortest-path routing over the subgraph $G \setminus \{N\}$ dynamically bypasses the compromised router without traversing invalid diagonal hops.
- **RNG Decoupling**: Router arbitration pseudo-randomness is decoupled from traffic generation (`NOXIM_DECOUPLE_RNG=1`), guaranteeing strictly identical packet injection across baseline, attack, and mitigated runs.
- **Destination Policies**: Configurable policies handle packets destined for a compromised router (`QUARANTINE`, `REMAP`, `DROP`, `ALLOW`). Remapped packets are delivered to a designated backup node (`NOXIM_BACKUP_NODE`).
- **Telemetry Engine**: Cycle-by-cycle logging of packet generation, per-hop routing deviations, logical vs. actual destinations, and delivery timestamps.
- **Interactive Dashboard**: Modern Streamlit frontend (`app.py`) backed by real simulation evidence.
- **Machine Learning**: Binary Random Forest attack detector (`network_attack_detector.pkl`) evaluated with explicit domain-shift disclosure.

---

## 2. Prerequisites & Environment

- **Operating System**: Ubuntu 22.04 LTS (native or WSL2)
- **Compiler**: GCC / G++ (supporting C++14)
- **Build Tools**: CMake $\ge 3.16$, Make
- **Libraries**: SystemC 2.3.3 / 2.3.4, YAML-CPP
- **Python Runtime**: Python 3.10+ with `pandas`, `numpy`, `scikit-learn`, `joblib`, `plotly`, `streamlit`

To install Python dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install streamlit plotly pandas numpy scikit-learn joblib
```

---

## 3. Build Instructions

To compile the SystemC simulator binary (`bin/noxim`):

```bash
cd /home/soniya/noxim
./build.sh -B -j2
```

The resulting executable is located at `bin/noxim`.

---

## 4. Reproducing Experiments

The full experiment suite evaluates **63 runs** (60 completed simulations + 3 negative configuration aborts):
- **5 Nodes Evaluated**: Node 0 (corner), Node 5 (interior), Node 6 (interior), Node 10 (interior), Node 13 (edge).
- **5 Attack Vectors**: `BLACKHOLE`, `SELECTIVE_FORWARDING`, `GRAYHOLE`, `ROUTING_MANIPULATION`, `DESTINATION_TAMPERING`.
- **Mitigation Matrix**: Loop-free bypass on all 5 nodes and all 5 attack vectors.
- **Negative Tests**: Node out of bounds, remap without backup, backup equals compromised node.
- **Policy Suite**: Endpoint delivery, quarantine, and remapping to Node 2.

To run the complete matrix:
```bash
cd /home/soniya/noxim
./sentinel/run_experiments.sh
```

Simulation logs and CSV traces are written to `sentinel/runs/` and aggregated into `sentinel/results/`.

---

## 5. Independent Verification Audit

To verify the raw simulation traces independently:

```bash
cd /home/soniya/noxim
source .venv/bin/activate
python3 sentinel/analyze.py
```

The audit script verifies:
1. **Traffic Equivalence**: Injected packets match baseline exactly (591 packets, identical source/destination/timestamps).
2. **Path Validity**: 0 invalid hops (no diagonal or multi-hop leaps).
3. **Loop Freedom**: 0 routing loops across all runs.
4. **Zero Compromised Hops**: 0 visits to compromised node $N$ as an intermediate router in mitigated runs.
5. **Settled Delivery Recovery**: 100% settled delivery of uncompromised traffic under Sentinel bypass.
6. **Remapping Verification**: 53 remapped packets delivered to designated backup Node 2.

---

## 6. Launching the Streamlit Dashboard

To launch the interactive dashboard:

```bash
cd /home/soniya/noxim
source .venv/bin/activate
streamlit run app.py --server.port 8501 --server.headless true
```

Access the dashboard at `http://localhost:8501` to inspect:
- **Topology Map**: Visualizing compromised router, adjacent bypass hops, and traffic routes.
- **Performance Recovery**: Attack delivery degradation vs. 100% settled recovery.
- **Packet-Level Inspector**: Real-time inspection of individual packet paths and hop-by-hop bypass decisions.
- **Untested Node Guardrail**: Selecting nodes outside the evaluated set displays an explicit `[NOT TESTED IN SAVED MATRIX]` banner without fabricating data.
- **ML Classifier & Domain Shift**: Live inference and full analysis of the Random Forest model with domain-shift disclosures.

---

## 7. Known Limitations

1. **Static Avoidance Graph**: Avoidance paths are precomputed over $G \setminus \{N\}$ under the assumption of an identified compromised router. Runtime dynamic anomaly discovery is handled by the higher-level monitoring plane.
2. **Single-Node Isolation**: Avoidance routing assumes a single compromised router at a time ($N \in [0, 15]$); multi-point compromise requires disconnected component handling.
3. **Machine Learning Domain Shift**: The pre-trained Random Forest model was trained on $8\times 8$ mesh data over 10,000 cycles with volume-dependent features (`total_received_packets`). When evaluated on $4\times 4$, 5,000-cycle data, it exhibits a high false-positive rate. It is maintained and labeled as **EXPERIMENTAL** until retrained with scale-invariant rate features.

---

## 8. Upstream Attribution

Noxim is developed at the University of Catania (Italy):
- V. Catania, A. Mineo, S. Monteleone, M. Palesi and D. Patti, *"Improving the energy efficiency of wireless Network on Chip architectures through online selective buffers and receivers shutdown"*, IEEE CCNC 2016.
