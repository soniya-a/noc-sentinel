import pandas as pd
import joblib
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# --------------------------------------------------
# 1. Load the 25 Noxim CSV files
# --------------------------------------------------

DATA_DIR = Path("project_data")

files = sorted(DATA_DIR.glob("*.csv"))

print("CSV files found:", len(files))

if len(files) == 0:
    raise FileNotFoundError("No CSV files found in project_data/")

dfs = []

for file in files:
    df = pd.read_csv(file)

    # Label based on filename
    if file.name.lower().startswith("attack_"):
        df["label"] = 1
    elif file.name.lower().startswith("normal_"):
        df["label"] = 0
    else:
        continue

    dfs.append(df)

data = pd.concat(dfs, ignore_index=True)

print("\nDataset shape:", data.shape)
print("\nClass distribution:")
print(data["label"].value_counts())

# --------------------------------------------------
# 2. Prepare features
# --------------------------------------------------

X = data.drop(columns=["label"])

# The original notebook used numeric features.
X = X.select_dtypes(include=["number"])

# Remove columns that have exactly the same value
# for every sample.
X = X.loc[:, X.nunique() > 1]

y = data["label"]

feature_names = X.columns.tolist()

print("\nFeatures used:")
for feature in feature_names:
    print(" -", feature)

print("\nNumber of features:", len(feature_names))

# --------------------------------------------------
# 3. Train/test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

# --------------------------------------------------
# 4. Random Forest
# --------------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

print("\nTraining model...")

model.fit(X_train, y_train)

# --------------------------------------------------
# 5. Evaluate
# --------------------------------------------------

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n==============================")
print("MODEL RESULTS")
print("==============================")

print("Accuracy:", accuracy)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# --------------------------------------------------
# 6. Save permanently in the project folder
# --------------------------------------------------

joblib.dump(
    model,
    "network_attack_detector.pkl"
)

joblib.dump(
    feature_names,
    "feature_names.pkl"
)

print("\n==============================")
print("FILES CREATED")
print("==============================")

print("network_attack_detector.pkl")
print("feature_names.pkl")

print("\nTraining complete.")
