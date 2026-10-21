import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

DATA_DIR = Path(project_data)
files = sorted(DATA_DIR.glob(*.csv))
print(Files
