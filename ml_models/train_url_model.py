import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

# Load dataset
df = pd.read_csv("ml_models/phishing_site_urls.csv")

# Normalize column names
df.columns = ["url", "label"]

# Convert labels to binary
df["label"] = df["label"].map({"benign": 0, "phishing": 1, "malicious": 1})

X = df["url"]
y = df["label"]

# Character-level vectorization (best for URLs)
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
X_vec = vectorizer.fit_transform(X)

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42
)

# Train model
model = LogisticRegression(max_iter=3000)
model.fit(X_train, y_train)

# Evaluation
pred = model.predict(X_test)
print("URL MODEL RESULTS")
print(classification_report(y_test, pred))

# Save model
joblib.dump(model, "ml_models/url_model.pkl")
joblib.dump(vectorizer, "ml_models/url_vectorizer.pkl")

print("✅ URL model trained & saved")
