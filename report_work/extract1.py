import csv, collections
rows = list(csv.DictReader(open("sentinel/results/run_summary.csv")))
print("RUNS_IN_SUMMARY", len(rows))
cols = ["run","sim_completed","attack","mal_node","mitigation","src_policy","dst_policy","backup_node","generated","settled_injected","settled_delivered","settled_delivery_rate_pct","n_dropped","n_misdelivered","n_in_flight","n_quarantined_src","n_quarantined_dst","n_remapped","remap_settled","remap_delivered_to_backup","at_risk_settled","at_risk_settled_delivered","viol_invalid_hop","viol_loop","viol_traverses_mal","viol_path_end","mitigation_hops","traffic_matches_baseline","status_mitigation_hook_observed","status_path_verified","status_destination_delivery_verified","settled_avg_latency_cycles","noxim_received_packets","noxim_ratio_pct","config_error"]
print("|".join(cols))
for r in rows:
    print("|".join(str(r.get(c,"")) for c in cols))
v = list(csv.DictReader(open("sentinel/results/path_violations.csv")))
print("TOTAL_VIOLATION_ROWS", len(v))
c = collections.Counter((x["run"].endswith("_mitigated") or x["run"].startswith(("policy","none","baseline")), x["violation"].split("_")[0] if x["violation"].startswith("invalid") else x["violation"]) for x in v)
for k,n in sorted(c.items()): print("VIOL", k, n)
runs_with_v = collections.Counter(x["run"] for x in v)
print("RUNS_WITH_VIOLATIONS", sorted(runs_with_v.items()))
