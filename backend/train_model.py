"""Train the phishing URL model used by the API.

Reproduces the Assignment 2 setup (baseline.py): 200,000-row random sample of
features_combined.csv, stratified 80/20 split, random forest on the 16 lexical
features. Writes model/phishing_rf.joblib and prints its SHA-256, which must be
copied into MODEL_SHA256 (see .env.example) so the server refuses a swapped file.

Usage:  python train_model.py path/to/features_combined.csv[.gz]
"""
import hashlib
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from app.features import FEATURES

OUT = Path(__file__).parent / "model" / "phishing_rf.joblib"


def main(csv_path):
    df = pd.read_csv(csv_path).dropna(subset=FEATURES)
    df = df.sample(200_000, random_state=42)
    X, y = df[FEATURES], df["label"]
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    # max_depth/min_samples_leaf keep the file small enough to ship in the ZIP
    model = RandomForestClassifier(n_estimators=100, max_depth=20, min_samples_leaf=2,
                                   n_jobs=-1, random_state=42)
    model.fit(X_tr, y_tr)
    print(classification_report(y_te, model.predict(X_te), digits=3))

    # One request = one row: spawning worker processes per call is slower, not faster
    model.n_jobs = 1
    OUT.parent.mkdir(exist_ok=True)
    joblib.dump(model, OUT, compress=3)
    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    print(f"Saved {OUT} ({OUT.stat().st_size / 1e6:.1f} MB)")
    print(f"MODEL_SHA256={digest}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "features_combined.csv")
