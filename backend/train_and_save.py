import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import hashlib

print("Loading data...")
df = pd.read_csv("features_combined.csv")

FEATURES = ['url_length', 'host_length', 'path_length', 'n_hyphens', 'n_dots',
            'n_digits', 'n_slashes', 'n_subdomains', 'has_ip', 'has_at',
            'has_port', 'suspicious_words', 'digit_ratio', 'suspicious_tlds',
            'companies_in_sub', 'tld_length']

data = df.dropna(subset=FEATURES)
print("Sampling 200,000 rows...")
data = data.sample(200000, random_state=42)

X = data[FEATURES]
y = data["label"]

print("Training Random Forest model...")
model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
model.fit(X, y)

print("Saving model to model.pkl...")
joblib.dump(model, "model.pkl")

print("Calculating SHA-256 hash...")
with open("model.pkl", "rb") as f:
    model_hash = hashlib.sha256(f.read()).hexdigest()

print("\n==================================================")
print("MODEL_HASH =", model_hash)
print("==================================================")
print("Copy that hash into your .env file as:")
print("MODEL_HASH=<the hash above>")
