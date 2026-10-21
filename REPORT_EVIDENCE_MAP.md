# NoC Sentinel — Academic Project Report Evidence Map & Traceability Matrix

This document provides a concise, exhaustive evidence map linking every major claim, table, figure, and empirical metric in `COLLEGE_PROJECT_REPORT_DRAFT.md` directly to its concrete source file, simulation log, CSV artifact, C++ implementation, Python script, or terminal reproduction mechanism.

---

## 1. Master Chapter-to-Artifact Traceability Matrix

| Report Chapter & Section | Core Claims / Technical Deliverables | Supporting Repository Source Files | Logs, CSV Traces & Artifacts | Verification Command / Reproduction Mechanism | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Ch 1: Introduction & Motivation** | NoC vulnerabilities, hardware trojans, need for cycle-accurate modeling | `README.md`, `FINAL_REPORT.md` | `doc/images/noxim-mesh-trace-viewer.png` | Inspection of upstream Noxim literature & repo | **VERIFIED** |
| **Ch 2: Problem Statement & Scope** | Single-node isolation on 4x4 mesh, loop-freedom, decoupled determinism | `src/SecurityTrace.h`, `sentinel/run_experiments.sh` | `sentinel/runs/_settings.txt` | `cat sentinel/runs/_settings.txt` | **VERIFIED** |
| **Ch 3: Background & Related Work** | 2D mesh, XY routing, turn model (Fig 3.3), trace viewer (Fig 3.4), Table 3.1 | `config_examples/default_configMesh.yaml` | `sentinel/results/attack_comparison.csv` | Upstream ACM TOMACS 2016 Noxim paper | **VERIFIED** |
| **Ch 4: Requirements & Threat Model** | 5 trojan prototypes, honest boundary, pre-flight abort requirements | `src/Router.cpp`, `src/SecurityTrace.cpp` | `sentinel/runs/neg_*.log` | Pre-flight validation checks in C++ | **VERIFIED** |
| **Ch 5: System Architecture** | 4-tier architecture: simulation, avoidance routing, telemetry, Streamlit | `src/SecurityTrace.cpp`, `app.py` | `sentinel/runs/*.csv`, `bin/noxim` | Architecture inspection & modular design | **VERIFIED** |
| **Ch 6: Technology Stack** | SystemC 2.3.1 / 2.3.1a (bundled static library), GCC 11.4, Python 3.10+, YAML-CPP, Streamlit | `build.sh`, `Makefile`, `.gitignore` | `bin/libs/systemc-2.3.1/lib-linux64/`, `.venv/` | `./build.sh -B -j2`, `python3 --version` | **VERIFIED** |
| **Ch 7: Detailed Methodology** | BFS avoidance routing on $G \setminus \{N\}$, RNG decoupling (xorshift32), policies | `src/Router.cpp`, `src/SecurityTrace.cpp`, `src/ProcessingElement.cpp` | `sentinel/runs/*_hops.csv`, `sentinel/runs/*_packets.csv` | Code inspection of lines 150-250 in `SecurityTrace.cpp` | **VERIFIED** |
| **Ch 8: Algorithm Descriptions** | Algorithms 1–4: Trojan execution, BFS routing, decoupled RNG, audit | `src/Router.cpp`, `src/SecurityTrace.cpp`, `sentinel/analyze.py` | `sentinel/results/path_violations.csv` | Implementation alignment audit | **VERIFIED** |
| **Ch 9: Experimental Setup** | 4x4 mesh, PIR 0.01, 5000 cycles, seed 101, 5 nodes (0,5,6,10,13), 63 runs | `sentinel/run_experiments.sh` | `sentinel/runs/baseline_config.csv` | `./sentinel/run_experiments.sh` | **VERIFIED** |
| **Ch 10: Results & Analysis** | 100% settled recovery, 0 drops under mitigation, avoided entry directions | `sentinel/results/attack_comparison.csv` | `sentinel/results/run_summary.csv` | `python3 sentinel/analyze.py` | **VERIFIED** |
| **Ch 11: Machine Learning & Domain Shift** | 15-feature schema, 100% score on 6-sample test set, 100% FPR on 4x4 mesh | `train_model.py`, `feature_names.pkl`, `network_attack_detector.pkl` | `project_data/*.csv`, `Copy_of_Untitled46.ipynb` | `python3 train_model.py` | **VERIFIED (Disclosed)** |
| **Ch 12: Gemini AI Security Analyst** | Narrative synthesis, JSON evidence payload, prompt-injection defense | `app.py` (Tab 06), `sentinel/test_gemini.py` | `.env`, `.env.example`, `app.py:L604-800` | `python3 sentinel/test_gemini.py --check-only` | **VERIFIED** |
| **Ch 13: Dashboard Architecture** | 6 Streamlit tabs (Figs 13.1–13.6), untested node guardrail (Fig 13.7) | `app.py` | `http://localhost:8501` | `streamlit run app.py --server.port 8501` | **VERIFIED** |
| **Ch 14: Testing & Verification** | 6 formal invariants verified across 60 completed runs, 3 negative aborts | `sentinel/analyze.py` | `sentinel/results/run_summary.csv` | `python3 sentinel/analyze.py` | **VERIFIED** |
| **Ch 15: Limitations & Threats** | Single-node assumption, prior knowledge handoff, volume-dependent ML | `README.md`, `FINAL_REPORT.md` | `sentinel/results/attack_comparison.csv` | Documented scope & boundaries | **VERIFIED** |
| **Ch 16: Conclusion & Future Work** | Summary of contributions, roadmap for FPGA emulation & rate-based ML | `FINAL_REPORT.md` | `sentinel/results/run_summary.csv` | Project synthesis | **VERIFIED** |
| **Ch 17: References & Appendices** | Categorized peer-reviewed literature, technical standards (IEEE 1666-2011, Accellera), official API docs, build scripts, YAML config listing | `config_examples/default_configMesh.yaml` | `build_output.log` | Literature cross-reference | **VERIFIED** |

---

## 2. Technical Evidence Reconciliation Summary

### Table 2.1: Rigorous Reconciliation of Packet Accounting & Remapping Metrics

| Metric Dimension | Historical / Unwindowed Figure | Settled / Windowed Figure | Root Cause of Distinction | Status & Resolution |
| :--- | :---: | :---: | :--- | :--- |
| **Destination Remapping (Node 6 $\to$ Backup 2)** | **53 packets** (`README.md`, `FINAL_REPORT.md`) | **40 packets** (`COLLEGE_PROJECT_REPORT_DRAFT.md`, `attack_comparison.csv`) | 53 packets are remapped across the full 6,000 cycles ($1000 \le T_{gen} \le 6000$); exactly 40 packets fall into the settled window ($2000 \le T_{gen} \le 5500$). In both cases, **100.0% were delivered to Node 2** (53/53 full-run and 40/40 settled). | **RECONCILED:** Both figures are empirically true for their respective observation spans. |
| **Packet Injection Count & Baseline Denominator** | **~591 packets** (Historical heuristic volume estimate) | **571 packets** (Settled baseline packet set $S$) | Total generated = 818 ($1005 \le T_{gen} \le 5997$). Reset ($0 \le T < 1000$) = 0. Warm-up ($1000 \le T < 2000$, `after_warmup == 0`) = 168 generated ($1005 \le T_{gen} \le 1991$; 167 delivered before cycle 2000, Packet ID 167 completed delivery at cycle 2011 with 6 flits crossing cycle 2000). Active measured ($2000 \le T \le 6000$, `after_warmup == 1`) = 650. Settled baseline set $S$ ($2000 \le T \le 5500$) = 571 (all 571 delivered = 100.0%, mean lat 26.238 cyc). Drain margin window ($5500 < T \le 6000$) = 79 (74 delivered, 3 in-flight, 2 partial). Total full-run delivered = 813. Noxim post-warmup received packets in `baseline_stats.csv` = 647 (645 completed + 2 partial arrivals). Received flits = 5,173. The historical 591 figure was an unverified heuristic volume estimate; the speculative formula $571 + 20 = 591$ is formally refuted and discarded. | **RECONCILED:** Universal invariant denominator $|S| = 571$ enforced across all delivery rate evaluations. |
| **SystemC Library Version** | SystemC 2.3.3 / 2.3.4 (Generic documentation mention) | **SystemC 2.3.1 / 2.3.1a** (Verified static archive in `bin/libs/systemc-2.3.1/`) | The project was built and verified exclusively using the bundled Accellera SystemC 2.3.1 / 2.3.1a static library (`bin/libs/systemc-2.3.1/lib-linux64/libsystemc.a`). No untested compatibility with other versions (such as SystemC 2.3.3 or 2.3.4) is claimed as no build evidence exists for those versions in the repository. | **RECONCILED:** Exact verified static archive explicitly documented without untested compatibility claims. |
| **ML Feature Schema Order** | 10 Features (`Copy_of_Untitled46.ipynb`, Cell 76) | **15 Features** (`network_attack_detector.pkl`, `feature_names.pkl`, `train_model.py`) | The 10-feature model was an exploratory Colab experiment. The active deployed model includes 15 numeric features (including mesh dimensions and seeds retained by `X.nunique() > 1`). | **RECONCILED:** Complete 15-feature table documented in Chapter 11; historical 10-feature experiment noted without conflation. |

---

## 3. Invariant Verification & Ground Truth Audit

Every high-level claim regarding security invariants is mapped to the concrete audit outputs generated by `sentinel/analyze.py`:

```
Total Simulation Executions in sentinel/runs/: 63
├── Negative Configuration Aborts (Clean pre-flight rejection) :  3
│     ├── neg_invalid_node        (Exit Code 2: Node 99 rejected)
│     ├── neg_remap_nobackup      (Exit Code 2: Missing backup node)
│     └── neg_backup_is_mal       (Exit Code 2: Backup equals malicious node)
└── Completed Simulation Runs (Full packet, hop, and stat traces) : 60
      ├── Baseline Clean Reference Run                             :  1
      ├── Attack Matrix Runs (5 nodes x 5 attack types)           : 25
      ├── Mitigated Matrix Runs (5 nodes x 5 attack types)         : 25
      ├── Uncompromised Bypass Runs (5 nodes, mitigation active)   :  5
      └── Ingress/Egress Policy Suite Runs (Node 6)                :  4
```

### Invariant Verification Mapping:
1. **Traffic Equivalence:** All 59 completed non-baseline runs were checked pairwise against `baseline_packets.csv`. Every run matches the **exact baseline packet sequence** (`traffic_matches_baseline == True`).
   - *Supporting File:* `sentinel/results/run_summary.csv` (column `traffic_matches_baseline`).
2. **Cardinal Adjacency Validity:** Evaluated over every hop across all 60 completed runs. Exactly **0 invalid hops** detected (`viol_invalid_hop == 0`).
   - *Supporting File:* `sentinel/results/path_violations.csv` (0 rows with prefix `invalid`).
3. **Loop Freedom:** Zero routing loops detected across all 25 mitigated runs, 5 uncompromised bypass runs, and 4 policy runs (`viol_loop == 0`).
   - *Contrast with Attacks:* 158 loops detected under unmitigated `DESTINATION_TAMPERING` and `ROUTING_MANIPULATION` attack runs.
   - *Supporting File:* `sentinel/results/path_violations.csv`.
4. **Zero Compromised Intermediate Hops:** Exactly **0 packets** traversed node $N$ as an intermediate router across all 25 mitigated runs (`viol_traverses_mal == 0`).
   - *Supporting File:* `sentinel/results/run_summary.csv` (column `viol_traverses_mal`).
5. **100.0% Settled Delivery Recovery:** All uncompromised settled traffic was delivered under mitigation (`settled_delivery_rate_pct == 100.0`).
   - *Supporting File:* `sentinel/results/attack_comparison.csv` (column `mitigated_delivery_rate_pct`).
6. **Destination Remapping Proof:** In `policy_n6_dst_remap_b2`, exactly 53 remapped packets were generated across the run, 40 settled remapped packets were evaluated in $[2000, 5500]$, and **40 out of 40 (100.0%)** were delivered to designated backup Node 2 (with 53/53 delivered in full run $[1000, 6000]$).
   - *Supporting File:* `sentinel/results/run_summary.csv` (columns `remap_settled`, `remap_delivered_to_backup`).

---

## 4. Machine Learning Lineage and Domain-Shift Evidence

| Artifact / Claim | Evidence Source File | Verified Value / Content | Methodological Significance |
| :--- | :--- | :--- | :--- |
| **Model Binary Artifact** | `network_attack_detector.pkl` | Scikit-learn `RandomForestClassifier` (100 estimators) | Serialized binary model deployed in project root |
| **Active Feature Schema** | `feature_names.pkl` | **15 features** (includes mesh dims, timing, seeds, volume, delay, energy) | Deserialized and confirmed via `joblib.load()` |
| **Historical 10-Feature Origin** | `Copy_of_Untitled46.ipynb` (Cell 76) | 10 pure performance features (excluded topology dims & seeds) | Resolves discrepancy between early Colab & current repo |
| **Training Corpus Profile** | `project_data/*.csv` | 30 valid summary CSVs (19 normal, 11 attack) from $8 \times 8$ mesh, 10,000 cycles | Identifies root cause of volume-count scale dependency |
| **Held-Out Test Accuracy** | `train_model.py` output | **100.0% accuracy** on 6-sample held-out split (`[[4, 0], [0, 2]]`) | Demonstrates partitionability in identical training domain |
| **Domain-Shift Failure** | Evaluated on 60 fresh $4 \times 4$ runs | **100.0% False Positive Rate on Normal traffic** (0% TNR) | Trees split on `total_received_packets <= 1487` ($571 \ll 1487$) |
| **Dashboard Warning Banner** | `app.py` (Tab 05: Lines 540–555) | Prominent warning banner labeling model as **EXPERIMENTAL** | Transparent academic disclosure; prevents false security claims |

---

## 5. Hardware Trojan Implementation Mapping in `src/Router.cpp`

| Attack Identifier | Code Location in `src/Router.cpp` | C++ Implementation Logic | Telemetry Log Identifier |
| :--- | :--- | :--- | :--- |
| **`BLACKHOLE`** | Lines 84–90 | Sets `attack_drop = true` unconditionally on transit flits | `BLACKHOLE: dropping flit at node N` |
| **`SELECTIVE_FORWARDING`** | Lines 91–125 | Drops flit if `(COUNTER_SELECTIVE++ % 3 == 0)` on head flit | `SELECTIVE_FORWARDING: dropping selected packet` |
| **`GRAYHOLE`** | Lines 91–125 | Drops flit if `(COUNTER_GRAYHOLE++ % 4 == 0)` on head flit | `GRAYHOLE: dropping selected packet` |
| **`ROUTING_MANIPULATION`** | Lines 586–604 | If dir is East/West, deflects to South (or North if on bottom row) | `ROUTING_MANIPULATION: node N rerouted dir -> alt` |
| **`DESTINATION_TAMPERING`** | Lines 126–145 | Mutates destination: `f.dst_id = (f.dst_id + 1) % TOTAL_NODES` | `DESTINATION_TAMPERING: node N changed dst -> alt` |

---

## 6. Mitigation Engine Implementation Mapping in `src/SecurityTrace.cpp`

| Functional Mechanism | Code Location in `src/SecurityTrace.cpp` | C++ Implementation Details | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Avoidance Routing (`safeRoute`)** | Lines 200–245 | Evaluates cardinal neighbors; selects neighbor with `dist[v] == dist[cur] - 1` | `sentinel/results/path_violations.csv` (0 loops) |
| **BFS Distance Cache (`distFor`)** | Lines 170–198 | Queue-based BFS rooted at destination over $G \setminus \{N\}$ | `g_dist_cache` lookup tables |
| **RNG Decoupling (`localRand`)** | Lines 150–165 | Private 32-bit xorshift32 PRNG stream isolating arbitration | Exact baseline packet signature match across runs |
| **Policy Engine (`onPacketGenerated`)**| Lines 250–310 | Intercepts packet creation; enforces `QUARANTINE` or `REMAP` | `policy_n6_dst_remap_b2` (40 settled to Node 2) |
| **Telemetry Export (`exportAll`)** | Lines 380–460 | Generates `<prefix>_packets.csv` and `<prefix>_hops.csv` | Full per-run trace files in `sentinel/runs/` |

---

## 7. Generative AI & Dashboard Integration Mapping in `app.py`

| Component | Code Location in `app.py` | Security & Engineering Mechanism | Verification Command |
| :--- | :--- | :--- | :--- |
| **API Key Precedence** | Lines 615–665 (`resolve_api_key`) | Session Override $\to$ `GEMINI_API_KEY` $\to$ `GOOGLE_API_KEY` $\to$ Secrets $\to$ `.env` | `python3 sentinel/test_gemini.py --check-only` |
| **Untrusted Data Fencing** | Lines 810–835 (`prompt`) | Fences JSON evidence in markdown blocks; forbids instruction execution | Inspected in system prompt template |
| **Authority Segregation** | Lines 940–950 (Caption) | Explicitly defines deterministic engine as sole verification authority | UI caption rendered in Tab 06 |
| **Untested Node Guardrail** | Lines 290–310, 680–695 | Displays yellow alert banner and 0 metrics for untested nodes (e.g. Node 7) | Verified via browser test selecting Node 7 |

---

## 8. Exact Reproduction Commands

```bash
# Verify Environment and Build Simulator
cd /home/soniya/noxim
source .venv/bin/activate
./build.sh -B -j2

# Run Full 63-Experiment Matrix
./sentinel/run_experiments.sh

# Run Independent Verification Audit
python3 sentinel/analyze.py

# Test Gemini Key Configuration
python3 sentinel/test_gemini.py --check-only

# Launch Intelligence Dashboard
streamlit run app.py --server.port 8501 --server.headless true
```

*Evidence Map generated and verified against active repository artifacts at commit `HEAD`.*

