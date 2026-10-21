#!/usr/bin/env python3
"""
NoC Sentinel — Dynamic Execution Engine and Experiment Validator
Accepts a single experiment configuration (dict/JSON/YAML) specifying target node (0-15)
on a 4x4 mesh. Reuses verified evidence if settings match; otherwise executes fresh
Noxim discrete-event simulations for 11 core runs (1 baseline + 5 attacks + 5 mitigations)
in an isolated bundle directory, executes the deterministic audit, and generates a manifest.
"""

import os
import sys
import json
import time
import shutil
import datetime
import subprocess
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
import pandas as pd
import yaml

BASE_DIR = Path("/home/soniya/noxim").resolve()
RUNS_DIR = BASE_DIR / "sentinel" / "runs"
RESULTS_DIR = BASE_DIR / "sentinel" / "results"
NOXIM_BIN = BASE_DIR / "bin" / "noxim"
ANALYZE_PY = BASE_DIR / "sentinel" / "analyze.py"

VALID_ATTACKS = [
    "BLACKHOLE",
    "SELECTIVE_FORWARDING",
    "GRAYHOLE",
    "ROUTING_MANIPULATION",
    "DESTINATION_TAMPERING"
]

DEFAULT_CONFIG = {
    "mesh_width": 4,
    "mesh_height": 4,
    "target_node": 6,
    "attack_modes": VALID_ATTACKS,
    "simulation_cycles": 5000,
    "warmup_cycles": 1000,
    "pir": 0.01,
    "seed": 101,
    "backup_node": 2
}

PRESET_CONFIGS = {
    "Node 6 (Verified Benchmark — Blackhole)": {
        "mesh_width": 4,
        "mesh_height": 4,
        "target_node": 6,
        "attack_modes": VALID_ATTACKS,
        "simulation_cycles": 5000,
        "warmup_cycles": 1000,
        "pir": 0.01,
        "seed": 101,
        "backup_node": 2
    },
    "Node 10 (Verified Benchmark — Grayhole)": {
        "mesh_width": 4,
        "mesh_height": 4,
        "target_node": 10,
        "attack_modes": VALID_ATTACKS,
        "simulation_cycles": 5000,
        "warmup_cycles": 1000,
        "pir": 0.01,
        "seed": 101,
        "backup_node": 2
    },
    "Node 7 (Dynamic Live Simulation)": {
        "mesh_width": 4,
        "mesh_height": 4,
        "target_node": 7,
        "attack_modes": VALID_ATTACKS,
        "simulation_cycles": 5000,
        "warmup_cycles": 1000,
        "pir": 0.01,
        "seed": 101,
        "backup_node": 2
    },
    "Node 0 (Corner Node Benchmark)": {
        "mesh_width": 4,
        "mesh_height": 4,
        "target_node": 0,
        "attack_modes": VALID_ATTACKS,
        "simulation_cycles": 5000,
        "warmup_cycles": 1000,
        "pir": 0.01,
        "seed": 101,
        "backup_node": 1
    },
    "Node 13 (Edge Node Benchmark)": {
        "mesh_width": 4,
        "mesh_height": 4,
        "target_node": 13,
        "attack_modes": VALID_ATTACKS,
        "simulation_cycles": 5000,
        "warmup_cycles": 1000,
        "pir": 0.01,
        "seed": 101,
        "backup_node": 2
    }
}

def parse_config_str(content_str: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Parse YAML or JSON string into a validated configuration dictionary."""
    content_str = content_str.strip()
    if not content_str:
        return False, "Configuration content is empty.", {}
    
    # Try YAML (which also parses JSON)
    try:
        data = yaml.safe_load(content_str)
        if not isinstance(data, dict):
            return False, "Configuration must be a valid key-value mapping / dictionary.", {}
        return validate_config(data)
    except Exception as e_yaml:
        # Fallback to direct JSON
        try:
            data = json.loads(content_str)
            if not isinstance(data, dict):
                return False, "Configuration must be a valid JSON object.", {}
            return validate_config(data)
        except Exception as e_json:
            return False, f"Failed to parse config as YAML or JSON: {e_yaml}", {}


def validate_config(cfg: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate user configuration against strict 4x4 mesh specifications."""
    out = dict(DEFAULT_CONFIG)
    out.update(cfg)
    
    # 1. Mesh Dimensions
    try:
        w = int(out.get("mesh_width", 4))
        h = int(out.get("mesh_height", 4))
        if w != 4 or h != 4:
            return False, f"Invalid mesh dimensions {w}x{h}. Scope is strictly a 4x4 2D mesh (16 nodes).", {}
        out["mesh_width"] = w
        out["mesh_height"] = h
    except (ValueError, TypeError):
        return False, "Mesh width and height must be integers equal to 4.", {}

    # 2. Target Node ID
    try:
        t = int(out.get("target_node", -1))
        if t < 0 or t > 15:
            return False, f"Invalid target_node {t}. Valid 4x4 node IDs are 0 to 15.", {}
        out["target_node"] = t
    except (ValueError, TypeError):
        return False, "target_node must be an integer between 0 and 15.", {}

    # 3. Attack Modes
    raw_attacks = out.get("attack_modes", VALID_ATTACKS)
    if isinstance(raw_attacks, str):
        raw_attacks = [a.strip() for a in raw_attacks.split(",")]
    if not isinstance(raw_attacks, list) or len(raw_attacks) == 0:
        return False, "attack_modes must be a non-empty list of valid attack types.", {}
    
    norm_attacks = []
    for a in raw_attacks:
        a_upper = str(a).strip().upper()
        if a_upper not in VALID_ATTACKS:
            return False, f"Unknown attack mode '{a}'. Allowed: {', '.join(VALID_ATTACKS)}", {}
        if a_upper not in norm_attacks:
            norm_attacks.append(a_upper)
    out["attack_modes"] = norm_attacks

    # 4. Simulation Cycles & Warmup
    try:
        sim = int(out.get("simulation_cycles", 5000))
        warm = int(out.get("warmup_cycles", 1000))
        if sim < 1000:
            return False, f"simulation_cycles must be >= 1000 (got {sim}).", {}
        if warm < 0 or warm >= sim:
            return False, f"warmup_cycles must be >= 0 and < simulation_cycles (got {warm}).", {}
        out["simulation_cycles"] = sim
        out["warmup_cycles"] = warm
    except (ValueError, TypeError):
        return False, "simulation_cycles and warmup_cycles must be positive integers.", {}

    # 5. PIR and Seed
    try:
        pir = float(out.get("pir", 0.01))
        seed = int(out.get("seed", 101))
        if pir <= 0.0 or pir > 1.0:
            return False, f"PIR must be between 0.0 and 1.0 (got {pir}).", {}
        if seed <= 0:
            return False, f"Seed must be positive integer (got {seed}).", {}
        out["pir"] = pir
        out["seed"] = seed
    except (ValueError, TypeError):
        return False, "PIR must be float and seed must be integer.", {}

    # 6. Backup Node (Optional for destination remapping)
    if "backup_node" in out and out["backup_node"] is not None:
        try:
            b = int(out["backup_node"])
            if b < 0 or b > 15:
                return False, f"backup_node must be in range 0..15 (got {b}).", {}
            if b == t:
                return False, f"backup_node ({b}) cannot be identical to compromised target_node ({t}).", {}
            out["backup_node"] = b
        except (ValueError, TypeError):
            return False, "backup_node must be integer between 0 and 15.", {}

    return True, "Configuration validated successfully for 4x4 mesh.", out


def check_existing_evidence(cfg: Dict[str, Any], runs_dir: Path = RUNS_DIR) -> Tuple[bool, str]:
    """Check if complete matching evidence exists in runs_dir for target_node and config."""
    target = cfg["target_node"]
    attacks = cfg["attack_modes"]
    sim = cfg["simulation_cycles"]
    warm = cfg["warmup_cycles"]
    seed = cfg["seed"]

    # Check baseline
    for suffix in ["_packets.csv", "_hops.csv", "_config.csv", "_stats.csv", ".log"]:
        if not (runs_dir / f"baseline{suffix}").exists():
            return False, f"Missing baseline run files: baseline{suffix}"

    # Check baseline configuration match
    cfg_file = runs_dir / "baseline_config.csv"
    if cfg_file.exists():
        try:
            cdf = pd.read_csv(cfg_file)
            cfg_dict = dict(zip(cdf["key"], cdf["value"]))
            if int(cfg_dict.get("sim_cycles", 0)) != sim or int(cfg_dict.get("seed", 0)) != seed:
                return False, "Saved baseline simulation cycles or seed mismatch."
        except Exception:
            return False, "Could not verify baseline_config.csv parameters."

    # Check all required attack and mitigated runs
    for a in attacks:
        tag = a.lower()
        for mode in ["attack", "mitigated"]:
            prefix = f"{tag}_n{target}_{mode}"
            for suffix in ["_packets.csv", "_hops.csv", "_config.csv", "_stats.csv", ".log"]:
                p = runs_dir / f"{prefix}{suffix}"
                if not p.exists():
                    return False, f"Missing run file: {prefix}{suffix}"

    return True, f"Matching saved evidence found for Node {target} across all {len(attacks)} attacks."


def run_noxim_step(name: str, out_dir: Path, sim: int, warm: int, seed: int, pir: float,
                   attack: Optional[str] = None, mal_node: Optional[int] = None,
                   mitigate: bool = False, dst_policy: Optional[str] = None,
                   backup_node: Optional[int] = None) -> Tuple[int, float, str]:
    """Execute a single Noxim discrete-event simulation run via safe subprocess."""
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{BASE_DIR}/bin/libs/systemc-2.3.1/lib-linux64:{BASE_DIR}/bin/libs/yaml-cpp/lib:" + env.get("LD_LIBRARY_PATH", "")
    env["NOXIM_DECOUPLE_RNG"] = "1"
    env["NOXIM_TRACE_PREFIX"] = str(out_dir / name)
    
    # Clean previous security vars
    for k in ["NOXIM_ATTACK", "NOXIM_MAL_NODE", "NOXIM_MITIGATE", "NOXIM_SRC_POLICY", "NOXIM_DST_POLICY", "NOXIM_BACKUP_NODE"]:
        env.pop(k, None)

    if attack:
        env["NOXIM_ATTACK"] = attack
    if mal_node is not None and mal_node >= 0:
        env["NOXIM_MAL_NODE"] = str(mal_node)
    if mitigate:
        env["NOXIM_MITIGATE"] = "1"
    if dst_policy:
        env["NOXIM_DST_POLICY"] = dst_policy
    if backup_node is not None:
        env["NOXIM_BACKUP_NODE"] = str(backup_node)

    cmd = [
        str(NOXIM_BIN),
        "-config", str(BASE_DIR / "config_examples" / "default_configMesh.yaml"),
        "-power", str(BASE_DIR / "bin" / "power.yaml"),
        "-sim", str(sim),
        "-warmup", str(warm),
        "-seed", str(seed),
        "-pir", str(pir), "poisson",
        "-routing", "XY",
        "-stats_format", "csv",
        "-stats_file", str(out_dir / f"{name}_stats.csv")
    ]

    log_path = out_dir / f"{name}.log"
    t0 = time.time()
    try:
        with open(log_path, "w", encoding="utf-8") as lf:
            res = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env, timeout=120, cwd=str(BASE_DIR))
            rc = res.returncode
    except subprocess.TimeoutExpired:
        rc = -9
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write("\nSENTINEL_ERROR: Simulation process timed out after 120s.\n")
    except Exception as e:
        rc = -1
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"\nSENTINEL_ERROR: Execution failed: {e}\n")
    
    elapsed = time.time() - t0
    return rc, elapsed, str(log_path)


def run_experiment_suite(cfg: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """
    Execute the core 11-run experiment matrix (1 baseline + 5 attacks + 5 mitigations)
    in an isolated unique directory, execute the deterministic audit, and write a manifest.
    """
    valid, msg, c = validate_config(cfg)
    if not valid:
        return {"success": False, "error": msg, "target_node": cfg.get("target_node")}

    target = c["target_node"]
    attacks = c["attack_modes"]
    sim = c["simulation_cycles"]
    warm = c["warmup_cycles"]
    seed = c["seed"]
    pir = c["pir"]
    backup = c.get("backup_node", 2)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_id = f"exp_n{target}_{timestamp}"
    
    bundle_dir = RUNS_DIR / exp_id
    bundle_dir.mkdir(parents=True, exist_ok=True)
    results_dir = RESULTS_DIR / exp_id
    results_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "experiment_id": exp_id,
        "timestamp": timestamp,
        "target_node": target,
        "mesh_dimensions": [c["mesh_width"], c["mesh_height"]],
        "configuration": c,
        "core_matrix_runs_count": 1 + len(attacks) * 2,
        "runs": {},
        "status": "RUNNING"
    }

    def notify(step, total, text):
        if progress_callback:
            progress_callback(step, total, text)

    total_steps = 1 + len(attacks) * 2
    cur_step = 0

    # 1. Baseline Run
    cur_step += 1
    notify(cur_step, total_steps, f"Executing Baseline simulation (Clean XY, Seed {seed})...")
    rc_base, el_base, log_base = run_noxim_step("baseline", bundle_dir, sim, warm, seed, pir)
    manifest["runs"]["baseline"] = {"exit_code": rc_base, "duration_s": round(el_base, 3), "log": log_base}
    if rc_base != 0:
        manifest["status"] = "FAILED_BASELINE"
        return {"success": False, "error": f"Baseline simulation failed with exit code {rc_base}. Check {log_base}", "manifest": manifest}

    # 2. Attack and Mitigation Runs (5 pairs = 10 runs)
    for a in attacks:
        tag = a.lower()
        
        # Attack Run
        cur_step += 1
        atk_name = f"{tag}_n{target}_attack"
        notify(cur_step, total_steps, f"Executing Attack: {a} at Node {target}...")
        rc_atk, el_atk, log_atk = run_noxim_step(atk_name, bundle_dir, sim, warm, seed, pir, attack=a, mal_node=target, mitigate=False)
        manifest["runs"][atk_name] = {"exit_code": rc_atk, "duration_s": round(el_atk, 3), "log": log_atk}

        # Mitigated Run
        cur_step += 1
        mit_name = f"{tag}_n{target}_mitigated"
        notify(cur_step, total_steps, f"Executing Mitigation: {a} at Node {target} (BFS Avoidance)...")
        rc_mit, el_mit, log_mit = run_noxim_step(mit_name, bundle_dir, sim, warm, seed, pir, attack=a, mal_node=target, mitigate=True)
        manifest["runs"][mit_name] = {"exit_code": rc_mit, "duration_s": round(el_mit, 3), "log": log_mit}

    # 3. Optional Destination Remap Run (if target is destination)
    dst_remap_name = f"policy_n{target}_dst_remap_b{backup}"
    rc_dst, el_dst, log_dst = run_noxim_step(dst_remap_name, bundle_dir, sim, warm, seed, pir,
                                            attack="BLACKHOLE", mal_node=target, mitigate=True,
                                            dst_policy="REMAP", backup_node=backup)
    manifest["runs"][dst_remap_name] = {"exit_code": rc_dst, "duration_s": round(el_dst, 3), "log": log_dst, "optional": True}

    # 4. Deterministic Verification Audit
    notify(total_steps, total_steps, "Running Deterministic Security Audit (sentinel/analyze.py)...")
    audit_cmd = [sys.executable, str(ANALYZE_PY), str(bundle_dir), str(results_dir)]
    t_aud0 = time.time()
    aud_res = subprocess.run(audit_cmd, capture_output=True, text=True, cwd=str(BASE_DIR))
    audit_duration = time.time() - t_aud0
    
    manifest["audit"] = {
        "exit_code": aud_res.returncode,
        "duration_s": round(audit_duration, 3),
        "stdout": aud_res.stdout,
        "stderr": aud_res.stderr
    }
    
    manifest["status"] = "COMPLETED" if aud_res.returncode == 0 else "AUDIT_WARNING"
    with open(bundle_dir / "manifest.json", "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)

    # Load Audit Results
    comp_csv = results_dir / "attack_comparison.csv"
    comp_df = pd.read_csv(comp_csv) if comp_csv.exists() else pd.DataFrame()
    viols_csv = results_dir / "path_violations.csv"
    viols_df = pd.read_csv(viols_csv) if viols_csv.exists() else pd.DataFrame()

    return {
        "success": True,
        "experiment_id": exp_id,
        "bundle_dir": str(bundle_dir),
        "results_dir": str(results_dir),
        "manifest": manifest,
        "comparison_df": comp_df,
        "violations_df": viols_df,
        "audit_stdout": aud_res.stdout
    }


def load_or_run_experiment(cfg: Dict[str, Any], force_rerun: bool = False, progress_callback=None) -> Dict[str, Any]:
    """
    Intelligent dispatcher: if matching saved evidence exists and force_rerun is False,
    loads and verifies the matching historical runs; otherwise dynamically runs Noxim.
    """
    valid, msg, c = validate_config(cfg)
    if not valid:
        return {"success": False, "error": msg, "target_node": cfg.get("target_node")}

    target = c["target_node"]
    
    # Check if saved evidence can be reused
    if not force_rerun:
        has_evidence, reason = check_existing_evidence(c, RUNS_DIR)
        if has_evidence:
            comp_csv = RESULTS_DIR / "attack_comparison.csv"
            comp_df = pd.DataFrame()
            if comp_csv.exists():
                all_df = pd.read_csv(comp_csv)
                comp_df = all_df[all_df["mal_node"] == target].copy()
            
            viols_csv = RESULTS_DIR / "path_violations.csv"
            viols_df = pd.DataFrame()
            if viols_csv.exists():
                all_v = pd.read_csv(viols_csv)
                viols_df = all_v[all_v["run"].str.contains(f"_n{target}_")].copy()

            return {
                "success": True,
                "is_reused": True,
                "reason": reason,
                "experiment_id": f"saved_n{target}",
                "bundle_dir": str(RUNS_DIR),
                "results_dir": str(RESULTS_DIR),
                "target_node": target,
                "configuration": c,
                "comparison_df": comp_df,
                "violations_df": viols_df
            }

        # Also check for existing completed experiment bundles in RUNS_DIR
        bundle_candidates = sorted(RUNS_DIR.glob(f"exp_n{target}_*"), key=os.path.getmtime, reverse=True)
        for b_cand in bundle_candidates:
            if b_cand.is_dir():
                has_b_evidence, b_reason = check_existing_evidence(c, b_cand)
                if has_b_evidence:
                    b_res_dir = RESULTS_DIR / b_cand.name
                    comp_csv = b_res_dir / "attack_comparison.csv"
                    comp_df = pd.read_csv(comp_csv) if comp_csv.exists() else pd.DataFrame()
                    viols_csv = b_res_dir / "path_violations.csv"
                    viols_df = pd.read_csv(viols_csv) if viols_csv.exists() else pd.DataFrame()
                    manifest_file = b_cand / "manifest.json"
                    manifest = {}
                    if manifest_file.exists():
                        try:
                            with open(manifest_file) as mf:
                                manifest = json.load(mf)
                        except Exception:
                            pass
                    return {
                        "success": True,
                        "is_reused": True,
                        "reason": f"Found existing matching experiment bundle {b_cand.name}",
                        "experiment_id": b_cand.name,
                        "bundle_dir": str(b_cand),
                        "results_dir": str(b_res_dir),
                        "target_node": target,
                        "configuration": c,
                        "manifest": manifest,
                        "comparison_df": comp_df,
                        "violations_df": viols_df
                    }

    # Must execute dynamic simulation
    res = run_experiment_suite(c, progress_callback=progress_callback)
    if res.get("success"):
        res["is_reused"] = False
        res["target_node"] = target
        res["configuration"] = c
    return res
