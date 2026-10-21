#!/usr/bin/env bash
# NoC Sentinel - reproducible matched experiment matrix.
# All runs share: config, seed, sim/warm-up cycles, PIR, XY routing, NOXIM_DECOUPLE_RNG=1.
# Usage: sentinel/run_experiments.sh            (full matrix)
#        NODES="6" ATTACKS="BLACKHOLE" sentinel/run_experiments.sh   (subset)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export LD_LIBRARY_PATH="$ROOT/bin/libs/systemc-2.3.1/lib-linux64:$ROOT/bin/libs/yaml-cpp/lib:${LD_LIBRARY_PATH:-}"

OUT=${OUT:-sentinel/runs}
SIM=${SIM:-5000}
WARM=${WARM:-1000}
SEED=${SEED:-101}
PIR=${PIR:-0.01}
NODES=${NODES:-"5 6 10 13 0"}
ATTACKS=${ATTACKS:-"BLACKHOLE SELECTIVE_FORWARDING GRAYHOLE ROUTING_MANIPULATION DESTINATION_TAMPERING"}
POLICY_NODE=${POLICY_NODE:-6}
BACKUP=${BACKUP:-2}

mkdir -p "$OUT"
echo "SIM=$SIM WARM=$WARM SEED=$SEED PIR=$PIR NODES=$NODES" > "$OUT/_settings.txt"
echo "ATTACKS=$ATTACKS POLICY_NODE=$POLICY_NODE BACKUP=$BACKUP" >> "$OUT/_settings.txt"
git rev-parse HEAD >> "$OUT/_settings.txt" 2>/dev/null

run() {   # run <name> [VAR=value ...]
    local name=$1; shift
    env -u NOXIM_ATTACK -u NOXIM_MAL_NODE -u NOXIM_MITIGATE -u NOXIM_SRC_POLICY \
        -u NOXIM_DST_POLICY -u NOXIM_BACKUP_NODE \
        NOXIM_DECOUPLE_RNG=1 NOXIM_TRACE_PREFIX="$OUT/$name" "$@" \
        ./bin/noxim -config config_examples/default_configMesh.yaml -power bin/power.yaml \
        -sim "$SIM" -warmup "$WARM" -seed "$SEED" -pir "$PIR" poisson -routing XY \
        -stats_format csv -stats_file "$OUT/${name}_stats.csv" > "$OUT/${name}.log" 2>&1
    local rc=$?
    echo "$name exit=$rc $(grep -h SENTINEL_SUMMARY "$OUT/$name.log")"
}

run baseline

for n in $NODES; do
    run "none_n${n}_mitigated" NOXIM_MAL_NODE="$n" NOXIM_MITIGATE=1
    for a in $ATTACKS; do
        tag=$(echo "$a" | tr 'A-Z' 'a-z')
        run "${tag}_n${n}_attack"    NOXIM_ATTACK="$a" NOXIM_MAL_NODE="$n"
        run "${tag}_n${n}_mitigated" NOXIM_ATTACK="$a" NOXIM_MAL_NODE="$n" NOXIM_MITIGATE=1
    done
done

# Destination / source policy tests (separate from the attack matrix)
p=$POLICY_NODE
run "policy_n${p}_dst_deliver"    NOXIM_ATTACK=BLACKHOLE NOXIM_MAL_NODE="$p" NOXIM_MITIGATE=1 NOXIM_DST_POLICY=DELIVER
run "policy_n${p}_dst_quarantine" NOXIM_ATTACK=BLACKHOLE NOXIM_MAL_NODE="$p" NOXIM_MITIGATE=1 NOXIM_DST_POLICY=QUARANTINE
run "policy_n${p}_dst_remap_b${BACKUP}" NOXIM_ATTACK=BLACKHOLE NOXIM_MAL_NODE="$p" NOXIM_MITIGATE=1 NOXIM_DST_POLICY=REMAP NOXIM_BACKUP_NODE="$BACKUP"
run "policy_n${p}_src_allow"      NOXIM_ATTACK=BLACKHOLE NOXIM_MAL_NODE="$p" NOXIM_MITIGATE=1 NOXIM_SRC_POLICY=ALLOW

# Negative tests: invalid configuration must be rejected (non-zero exit expected)
run "neg_invalid_node"   NOXIM_MAL_NODE=99 NOXIM_MITIGATE=1
run "neg_remap_nobackup" NOXIM_MAL_NODE="$p" NOXIM_MITIGATE=1 NOXIM_DST_POLICY=REMAP
run "neg_backup_is_mal"  NOXIM_MAL_NODE="$p" NOXIM_MITIGATE=1 NOXIM_DST_POLICY=REMAP NOXIM_BACKUP_NODE="$p"
echo DONE
