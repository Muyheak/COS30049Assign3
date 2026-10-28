import joblib
from feature_extractor import extract_features

# 1. Load the model (make sure your model file is named exactly model.pkl in this folder)
model = joblib.load("model.pkl")

# 2. Test URLs
urls = [
    "https://www.google.com", 
    "http://paypal-secure-login.example.com/verify"
]

for url in urls:
    feats = extract_features(url)
    prediction = model.predict([feats])[0]
    proba = model.predict_proba([feats])[0]
    
    print(f"URL: {url}")
    print(f"  Features: {feats}")
    print(f"  Prediction: {prediction} (0=Benign, 1=Phishing)")
    print(f"  Confidence: {max(proba):.4f}\n")