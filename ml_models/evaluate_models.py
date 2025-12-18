# ml_models/evaluate_models.py
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

# -------- LOAD DATA --------
df = pd.read_csv("ml_models/phishing_site_urls.csv")

X = df["url"]
y = df["label"]  # 0 = benign, 1 = phishing

# -------- LOAD MODEL --------
model = joblib.load("ml_models/url_model.pkl")
vectorizer = joblib.load("ml_models/url_vectorizer.pkl")

X_vec = vectorizer.transform(X)
y_pred = model.predict(X_vec)

# -------- METRICS --------
print("=== Classification Report ===")
print(classification_report(y, y_pred))

print("\n=== Confusion Matrix ===")
print(confusion_matrix(y, y_pred))
