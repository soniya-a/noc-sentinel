#!/usr/bin/env python3
"""NoC Sentinel evidence analyzer (stdlib only).

Reads the per-run files written by sentinel/run_experiments.sh:
  <run>_packets.csv, <run>_hops.csv, <run>_config.csv, <run>_stats.csv, <run>.log
and independently verifies paths and deliveries. It does NOT reuse the router's
routing code: path validity is re-checked from the raw forwarded-hop sequence.

Definitions (all explicit):
  measured packet      generated at or after reset+warm-up (same window as Noxim stats)
  settled packet       measured packet generated >= DRAIN_MARGIN cycles before the end,
                       so it had time to arrive; unsettled packets may legitimately be IN_FLIGHT
  delivery rate (%)    DELIVERED / injected, over settled packets (packet-level, max 100%)
  at-risk packet       injected packet whose plain-XY route src->dst has the compromised
                       node as an INTERMEDIATE router
  Noxim ratio (%)      Noxim "Received/Ideal flits Ratio" x 100. Ideal flits are estimated
                       from PIR, so this can exceed 100%; it is NOT a delivery probability.

Statuses (mitigated runs):
  mitigation_hook_observed      >=1 forwarded hop labelled MITIGATION (route actually changed)
  path_verified                 every recorded path is adjacency-valid, loop-free, never uses
                                the compromised node as an intermediate, delivered paths end at
                                the delivery node, AND >=1 at-risk packet exercised the detour
  destination_delivery_verified every settled at-risk packet was DELIVERED at its actual_dst,
                                and no packet in the run was DROPPED or MISDELIVERED
"""
import csv
import glob
import os
import sys
from collections import Counter, defaultdict

RUNS = sys.argv[1] if len(sys.argv) > 1 else "sentinel/runs"
OUT = sys.argv[2] if len(sys.argv) > 2 else "sentinel/results"
DRAIN_MARGIN = 500

def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def coord(n, X):
    return n % X, n // X

def xy_path(src, dst, X):
    x, y = coord(src, X)
    dx, dy = coord(dst, X)
    p = [src]
    while x != dx:
        x += 1 if dx > x else -1
        p.append(y * X + x)
    while y != dy:
        y += 1 if dy > y else -1
        p.append(y * X + x)
    return p

def adjacent(a, b, X, Y):
    if a < 0 or b < 0 or a >= X * Y or b >= X * Y:
        return False
    ax, ay = coord(a, X)
    bx, by = coord(b, X)
    return abs(ax - bx) + abs(ay - by) == 1

def check_path(pk, mal, X, Y):
    """Return list of violation strings for one packet path."""
    v = []
    path = [int(t) for t in pk["path"].split(">") if t != ""]
    src = int(pk["src"])
    if not path or path[0] != src:
        v.append("path_not_starting_at_src")
    for a, b in zip(path, path[1:]):
        if not adjacent(a, b, X, Y):
            v.append(f"invalid_hop_{a}->{b}")
    if len(set(path)) != len(path):
        v.append("loop")
    if mal >= 0:
        allowed = {src}
        if pk["outcome"] in ("DELIVERED", "MISDELIVERED"):
            allowed.add(int(pk["delivered_node"]))
        if any(n == mal and n not in allowed for n in path):
            v.append("traverses_compromised_node")
    if pk["outcome"] in ("DELIVERED", "MISDELIVERED") and path[-1] != int(pk["delivered_node"]):
        v.append("path_end_mismatch")
    return v

def parse_log(path):
    info = {"exit_ok": False, "hook_lines": 0, "attack_lines": 0, "error": ""}
    if not os.path.exists(path):
        return info
    for line in open(path, errors="replace"):
        if "Noxim simulation completed" in line:
            info["exit_ok"] = True
        if line.startswith("SENTINEL_HOOK"):
            info["hook_lines"] += 1
        if line.startswith(("BLACKHOLE", "SELECTIVE_FORWARDING", "GRAYHOLE",
                            "ROUTING_MANIPULATION", "DESTINATION_TAMPERING")):
            info["attack_lines"] += 1
        if line.startswith("SENTINEL_ERROR"):
            info["error"] = line.strip()
    return info

def traffic_signature(pkts):
    return {(p["packet_id"], p["src"], p["logical_dst"], p["gen_cycle"], p["size_flits"]) for p in pkts}

def analyze(run, base_sig):
    cfg = {r["key"]: r["value"] for r in read_csv(f"{RUNS}/{run}_config.csv")}
    pkts = read_csv(f"{RUNS}/{run}_packets.csv")
    hops = read_csv(f"{RUNS}/{run}_hops.csv")
    stats = read_csv(f"{RUNS}/{run}_stats.csv")
    log = parse_log(f"{RUNS}/{run}.log")
    row = {"run": run, "sim_completed": log["exit_ok"], "config_error": log["error"]}
    if not cfg or not pkts:
        row["note"] = "no trace (run rejected or failed)"
        return row, []

    X, Y = int(cfg["mesh_dim_x"]), int(cfg["mesh_dim_y"])
    mal = int(cfg["mal_node"])
    mit = cfg["mitigation"] == "1"
    end = int(cfg["reset_cycles"]) + int(cfg["sim_cycles"])
    row.update(attack=cfg["attack"], mal_node=mal, mitigation=int(mit),
               src_policy=cfg["src_policy"], dst_policy=cfg["dst_policy"],
               backup_node=int(cfg["backup_node"]), seed=cfg["seed"],
               sim_cycles=cfg["sim_cycles"], warmup_cycles=cfg["warmup_cycles"])

    row["generated"] = len(pkts)
    oc = Counter(p["outcome"] for p in pkts)
    for k in ("DELIVERED", "MISDELIVERED", "DROPPED", "PARTIAL", "IN_FLIGHT",
              "QUEUED_AT_SOURCE", "QUARANTINED_SRC", "QUARANTINED_DST"):
        row["n_" + k.lower()] = oc.get(k, 0)
    row["n_remapped"] = sum(p["remapped"] == "1" for p in pkts)

    injected = [p for p in pkts if not p["outcome"].startswith("QUARANTINED")]
    settled = [p for p in injected if p["after_warmup"] == "1"
               and float(p["gen_cycle"]) <= end - DRAIN_MARGIN]
    s_del = sum(p["outcome"] == "DELIVERED" for p in settled)
    row["settled_injected"] = len(settled)
    row["settled_delivered"] = s_del
    row["settled_delivery_rate_pct"] = round(100.0 * s_del / len(settled), 3) if settled else ""
    row["settled_not_delivered"] = len(settled) - s_del
    lat = [float(p["latency_cycles"]) for p in settled if p["outcome"] == "DELIVERED"]
    row["settled_avg_latency_cycles"] = round(sum(lat) / len(lat), 3) if lat else ""

    s_oc = Counter(p["outcome"] for p in settled)
    row["settled_dropped"] = s_oc.get("DROPPED", 0)
    row["settled_misdelivered"] = s_oc.get("MISDELIVERED", 0)
    row["settled_flits_dropped"] = sum(int(p["flits_dropped"]) for p in settled)
    row["full_flits_dropped"] = sum(int(p["flits_dropped"]) for p in pkts)

    att_hops = [h for h in hops if h.get("deviation") == "ATTACK"]
    row["attack_hops_full"] = len(att_hops)
    s_pkt_ids = {p["packet_id"] for p in settled}
    row["attack_hops_settled"] = len([h for h in att_hops if h.get("packet_id") in s_pkt_ids])

    # at-risk packets: XY route would use mal as an intermediate router
    at_risk = []
    if mal >= 0:
        for p in injected:
            s, d = int(p["src"]), int(p["logical_dst"])
            if mal in xy_path(s, d, X)[1:-1]:
                at_risk.append(p)
    ar_settled = [p for p in at_risk if p["after_warmup"] == "1"
                  and float(p["gen_cycle"]) <= end - DRAIN_MARGIN]
    ar_ok = [p for p in ar_settled if p["outcome"] == "DELIVERED"
             and int(p["delivered_node"]) == int(p["actual_dst"])]
    row["at_risk_injected"] = len(at_risk)
    row["at_risk_settled"] = len(ar_settled)
    row["at_risk_settled_delivered"] = len(ar_ok)
    row["at_risk_traversed_mal"] = sum(
        mal in [int(t) for t in p["path"].split(">")][1:] and
        not (p["outcome"] == "DELIVERED" and int(p["delivered_node"]) == mal)
        for p in at_risk)

    # independent path verification
    violations = []
    for p in pkts:
        if p["outcome"].startswith("QUARANTINED"):
            continue
        for v in check_path(p, mal, X, Y):
            violations.append({"run": run, "packet_id": p["packet_id"], "src": p["src"],
                               "actual_dst": p["actual_dst"], "path": p["path"],
                               "outcome": p["outcome"], "violation": v})
    vc = Counter(v["violation"].split("_")[0] if v["violation"].startswith("invalid") else v["violation"]
                 for v in violations)
    row["viol_invalid_hop"] = vc.get("invalid", 0)
    row["viol_loop"] = vc.get("loop", 0)
    row["viol_traverses_mal"] = vc.get("traverses_compromised_node", 0)
    row["viol_path_end"] = vc.get("path_end_mismatch", 0) + vc.get("path_not_starting_at_src", 0)

    mh = [h for h in hops if h["deviation"] == "MITIGATION"]
    row["mitigation_hops"] = len(mh)
    row["hook_log_lines"] = log["hook_lines"]
    # Avoided entry directions: show both the upstream neighbor bearing relative to mal and heading direction into mal
    # For instance, if upstream router is East of mal and was heading West into mal, report "from_E(heading_W):<count>"
    entry_counts = Counter()
    for h in mh:
        if int(h["xy_next"]) == mal:
            router = int(h["router"])
            rx, ry = coord(router, X)
            mx, my = coord(mal, X)
            from_bearing = "?"
            if ry < my: from_bearing = "N"
            elif ry > my: from_bearing = "S"
            elif rx > mx: from_bearing = "E"
            elif rx < mx: from_bearing = "W"
            entry_counts[f"from_{from_bearing}(heading_{h['xy_dir']})"] += 1
    row["avoided_entry_dirs"] = " ".join(f"{k}:{v}" for k, v in sorted(entry_counts.items()))

    row["attack_log_lines"] = log["attack_lines"]
    row["drops_recorded"] = sum(int(p["flits_dropped"]) > 0 for p in pkts)
    row["tampered_recorded"] = sum(p["tampered"] == "1" for p in pkts)

    if stats:
        s = stats[0]
        row["noxim_received_packets"] = s.get("total_received_packets", "")
        row["noxim_ratio_pct"] = round(100 * float(s["received_ideal_flits_ratio"]), 4)
        row["noxim_avg_delay_cycles"] = round(float(s["global_average_delay_cycles"]), 4)
        row["noxim_throughput_flits_per_cycle"] = round(float(s["network_throughput_flits_per_cycle"]), 6)

    row["traffic_matches_baseline"] = (traffic_signature(pkts) == base_sig) if base_sig else ""

    # destination remap evidence
    rem = [p for p in pkts if p["remapped"] == "1"]
    if rem:
        rs = [p for p in rem if p["after_warmup"] == "1" and float(p["gen_cycle"]) <= end - DRAIN_MARGIN]
        row["remap_settled"] = len(rs)
        row["remap_delivered_to_backup"] = sum(p["outcome"] == "DELIVERED" and
                                               int(p["delivered_node"]) == int(cfg["backup_node"]) for p in rs)

    if mit:
        hook = len(mh) > 0
        clean = not violations
        row["status_mitigation_hook_observed"] = "YES" if hook else "NO"
        if not clean:
            row["status_path_verified"] = "FAILED"
        elif not ar_settled:
            row["status_path_verified"] = "NOT_EXERCISED"
        else:
            row["status_path_verified"] = "VERIFIED"
        bad = oc.get("DROPPED", 0) + oc.get("MISDELIVERED", 0)
        if not ar_settled:
            row["status_destination_delivery_verified"] = "NOT_EXERCISED"
        elif len(ar_ok) == len(ar_settled) and bad == 0:
            row["status_destination_delivery_verified"] = "VERIFIED"
        else:
            row["status_destination_delivery_verified"] = "FAILED"
    return row, violations

def main():
    os.makedirs(OUT, exist_ok=True)
    runs = sorted({os.path.basename(p)[:-4] for p in glob.glob(f"{RUNS}/*.log")})
    base = read_csv(f"{RUNS}/baseline_packets.csv")
    base_sig = traffic_signature(base) if base else None
    rows, viols = [], []
    for r in runs:
        row, v = analyze(r, base_sig)
        rows.append(row)
        viols.extend(v)

    keys = []
    for r in rows:
        for k in r:
            if k not in keys:
                keys.append(k)
    with open(f"{OUT}/run_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    with open(f"{OUT}/path_violations.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["run", "packet_id", "src", "actual_dst", "path", "outcome", "violation"])
        w.writeheader()
        w.writerows(viols)

    # attack comparison: baseline vs attack vs mitigated for each (attack, node)
    by = {r["run"]: r for r in rows}
    b = by.get("baseline", {})
    comp = []
    for r in rows:
        name = r["run"]
        if not name.endswith("_attack"):
            continue
        stem = name[:-len("_attack")]
        m = by.get(stem + "_mitigated", {})
        comp.append({
            "attack": r.get("attack"), "mal_node": r.get("mal_node"),
            "baseline_delivery_rate_pct": b.get("settled_delivery_rate_pct"),
            "attack_delivery_rate_pct": r.get("settled_delivery_rate_pct"),
            "mitigated_delivery_rate_pct": m.get("settled_delivery_rate_pct"),
            "attack_dropped": r.get("settled_dropped", r.get("n_dropped")),
            "attack_flits_dropped": r.get("settled_flits_dropped", 0),
            "attack_misdelivered": r.get("settled_misdelivered", r.get("n_misdelivered")),
            "attack_route_deviations_settled": r.get("attack_hops_settled", 0),
            "attack_full_dropped": r.get("n_dropped"),
            "attack_full_flits_dropped": r.get("full_flits_dropped", 0),
            "attack_full_misdelivered": r.get("n_misdelivered"),
            "attack_route_deviations_full": r.get("attack_hops_full", 0),
            "mitigated_dropped": m.get("settled_dropped", m.get("n_dropped")),
            "mitigated_flits_dropped": m.get("settled_flits_dropped", 0),
            "mitigated_misdelivered": m.get("settled_misdelivered", m.get("n_misdelivered")),
            "mitigated_full_dropped": m.get("n_dropped"),
            "mitigated_full_flits_dropped": m.get("full_flits_dropped", 0),
            "mitigated_full_misdelivered": m.get("n_misdelivered"),
            "mitigated_quarantined_src": m.get("n_quarantined_src"),
            "mitigated_quarantined_dst": m.get("n_quarantined_dst"),
            "at_risk_settled_attack": r.get("at_risk_settled"),
            "at_risk_delivered_attack": r.get("at_risk_settled_delivered"),
            "at_risk_settled_mitigated": m.get("at_risk_settled"),
            "at_risk_delivered_mitigated": m.get("at_risk_settled_delivered"),
            "baseline_avg_latency_cycles": b.get("settled_avg_latency_cycles"),
            "attack_avg_latency_cycles": r.get("settled_avg_latency_cycles"),
            "mitigated_avg_latency_cycles": m.get("settled_avg_latency_cycles"),
            "baseline_noxim_ratio_pct": b.get("noxim_ratio_pct"),
            "attack_noxim_ratio_pct": r.get("noxim_ratio_pct"),
            "mitigated_noxim_ratio_pct": m.get("noxim_ratio_pct"),
            "avoided_entry_dirs": m.get("avoided_entry_dirs"),
            "traffic_matched": f"{r.get('traffic_matches_baseline')}/{m.get('traffic_matches_baseline')}",
            "status_mitigation_hook_observed": m.get("status_mitigation_hook_observed"),
            "status_path_verified": m.get("status_path_verified"),
            "status_destination_delivery_verified": m.get("status_destination_delivery_verified"),
        })
    if comp:
        with open(f"{OUT}/attack_comparison.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(comp[0].keys()))
            w.writeheader()
            w.writerows(comp)

    print(f"runs analysed: {len(rows)}  path violations: {len(viols)}")
    for r in rows:
        print(f"{r['run']:<42} deliv%={str(r.get('settled_delivery_rate_pct','')):>8} "
              f"drop={r.get('n_dropped','-'):>4} mis={r.get('n_misdelivered','-'):>4} "
              f"risk={r.get('at_risk_settled_delivered','-')}/{r.get('at_risk_settled','-')} "
              f"viol={r.get('viol_invalid_hop',0)+r.get('viol_loop',0)+r.get('viol_traverses_mal',0)+r.get('viol_path_end',0) if 'viol_loop' in r else '-'} "
              f"match={r.get('traffic_matches_baseline','')} "
              f"hook={r.get('status_mitigation_hook_observed','')} path={r.get('status_path_verified','')} "
              f"dest={r.get('status_destination_delivery_verified','')} {r.get('config_error','')}")

if __name__ == "__main__":
    main()
