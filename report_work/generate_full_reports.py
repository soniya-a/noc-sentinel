import csv, os, sys
from pathlib import Path

# Paths
REPORT_PATH = Path("COLLEGE_PROJECT_REPORT_DRAFT.md")
MAP_PATH = Path("REPORT_EVIDENCE_MAP.md")

print("Loading dataset summaries...")
summary_rows = list(csv.DictReader(open("sentinel/results/run_summary.csv")))
violations = list(csv.DictReader(open("sentinel/results/path_violations.csv")))

def get_row(name):
    for r in summary_rows:
        if r["run"] == name:
            return r
    return {}

print(f"Loaded {len(summary_rows)} summary rows and {len(violations)} violation rows.")
