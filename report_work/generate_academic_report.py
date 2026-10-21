import os, sys, csv
from pathlib import Path

print("Reading ev1.txt and results...")
# Load summary rows
summary_rows = list(csv.DictReader(open("sentinel/results/run_summary.csv")))
print(f"Loaded {len(summary_rows)} summary rows.")

violations = list(csv.DictReader(open("sentinel/results/path_violations.csv")))
print(f"Loaded {len(violations)} violation rows.")
