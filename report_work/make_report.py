import csv, os, sys
from pathlib import Path

# Paths
REPORT_PATH = Path("COLLEGE_PROJECT_REPORT_DRAFT.md")
MAP_PATH = Path("REPORT_EVIDENCE_MAP.md")

print("Building College Project Report Draft...")

# 1. Load data
summary_rows = list(csv.DictReader(open("sentinel/results/run_summary.csv")))
violations = list(csv.DictReader(open("sentinel/results/path_violations.csv")))

# Helper functions for tables
def get_run(name):
    for r in summary_rows:
        if r["run"] == name:
            return r
    return {}

print("Loaded datasets successfully.")
